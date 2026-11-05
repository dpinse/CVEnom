"""Static checks on the production packaging (no Docker needed)."""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "docker-compose.prod.yml"
DOCKERFILE = ROOT / "backend" / "Dockerfile"
LOCK = ROOT / "backend" / "requirements.lock"
ENTRYPOINT = ROOT / "backend" / "docker-entrypoint.sh"
ENV_EXAMPLE = ROOT / ".env.example"
INIT = ROOT / "deploy" / "postgres-init" / "01-app-role.sh"
APP_SERVICES = ("api", "worker", "beat", "migrate")
SECRET_KEY_RE = re.compile(r"(?i)(password|secret|token|key)")
# Boolean flags whose names merely contain "secret"/"key".
NOT_SECRETS = {"REQUIRE_SECRETS_KEY"}
REF_RE = re.compile(r"\$\{[A-Z_]+:\?[^}]*\}")


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
            yield str(k), v, f"{path}.{k}"
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def test_services_present(compose):
    for name in (*APP_SERVICES, "postgres", "redis"):
        assert name in compose["services"]
    assert compose["services"]["migrate"]["restart"] == "no"
    assert compose["services"]["api"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )


def test_postgres_redis_publish_no_ports(compose):
    assert "ports" not in compose["services"]["postgres"]
    assert "ports" not in compose["services"]["redis"]


def test_only_api_publishes_loopback(compose):
    assert compose["services"]["api"]["ports"] == ["127.0.0.1:8000:8000"]
    for name, svc in compose["services"].items():
        if name != "api":
            assert "ports" not in svc


def test_no_literal_secrets_in_compose(compose):
    for key, value, path in _walk(compose):
        if SECRET_KEY_RE.search(key) and isinstance(value, str) and key not in NOT_SECRETS:
            # "" blanks a value env_file would otherwise inject (see M-e).
            assert value == "" or REF_RE.fullmatch(value), (path, value)
    text = COMPOSE.read_text()
    for var in ("POSTGRES_PASSWORD", "APP_DB_PASSWORD", "REDIS_PASSWORD"):
        for m in re.finditer(r"\$\{" + var + r"(.*?)\}", text):
            assert m.group(1).startswith(":?"), m.group(0)
    redis = compose["services"]["redis"]
    assert "${REDIS_PASSWORD:?" in redis["environment"]["REDISCLI_AUTH"]
    assert "-a" not in redis["healthcheck"]["test"]


@pytest.mark.parametrize("svc", APP_SERVICES)
def test_app_service_hardening(compose, svc):
    s = compose["services"][svc]
    assert s["read_only"] is True
    assert s["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in s["security_opt"]
    assert s["user"] == "10001:10001"
    assert "/tmp" in s["tmpfs"]
    assert "cvenom_app:${APP_DB_PASSWORD:?" in s["environment"]["DATABASE_URL"]
    assert "${REDIS_PASSWORD:?" in s["environment"]["REDIS_URL"]


def test_long_running_restart_and_redis_policy(compose):
    for name in ("api", "worker", "beat", "postgres", "redis"):
        assert compose["services"][name]["restart"] == "unless-stopped"
    cmd = compose["services"]["redis"]["command"]
    assert "volatile-ttl" in cmd and "--requirepass" in cmd


def test_postgres_init_env_and_mounts(compose):
    pg = compose["services"]["postgres"]
    assert "${APP_DB_PASSWORD:?" in pg["environment"]["APP_DB_PASSWORD"]
    assert "./postgres-init:/docker-entrypoint-initdb.d:ro" in pg["volumes"]


def test_dockerfile_nonroot_and_hashes():
    text = DOCKERFILE.read_text()
    assert "--require-hashes" in text
    users = re.findall(r"(?m)^USER\s+(\S+)", text)
    assert users and users[-1] == "10001:10001"
    assert "PYTHONDONTWRITEBYTECODE=1" in text


def _lock_requirements():
    """Return a list of [requirement, *continuation parts] over the lock file."""
    logical, cur = [], None
    for raw in LOCK.read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if cur is not None and raw.startswith((" ", "\t")):
            cur.append(raw.strip().rstrip("\\").strip())
            continue
        cur = [raw.strip().rstrip("\\").strip()]
        logical.append(cur)
    return logical


def test_lock_every_requirement_hashed():
    reqs = _lock_requirements()
    assert len(reqs) > 20
    for parts in reqs:
        assert "==" in parts[0], parts
        hashes = [p for p in parts[1:] if p.startswith("--hash=sha256:")]
        assert hashes, parts[0]
        assert all(re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", h) for h in hashes)
    names = {p[0].split("==")[0].lower() for p in reqs}
    assert {"fastapi", "celery", "uvicorn", "sqlalchemy"} <= names
    assert "pytest" not in names
    assert LOCK.read_text().lstrip().startswith("#")


def test_env_example_secrets_blank():
    seen = set()
    for line in ENV_EXAMPLE.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        seen.add(k)
        if SECRET_KEY_RE.search(k) and k not in NOT_SECRETS:
            assert v.strip() == "", k
    for k in ("SECRETS_KEY", "POSTGRES_PASSWORD", "APP_DB_PASSWORD", "REDIS_PASSWORD",
              "SMTP_PASSWORD", "TRUST_CF_CONNECTING_IP"):
        assert k in seen, k
    assert "openssl rand -base64 32" in ENV_EXAMPLE.read_text()


def test_env_example_covers_settings():
    from cvenom.config import Settings

    text = ENV_EXAMPLE.read_text()
    for field in Settings.model_fields:
        assert re.search(rf"(?m)^#?\s*{field.upper()}=", text), field


def test_entrypoint_api_line():
    text = ENTRYPOINT.read_text()
    assert "set -eu" in text
    api = next(line for line in text.splitlines() if "uvicorn" in line)
    assert "--ws-max-size 8192" in api and "--proxy-headers" in api
    assert "cvenom.api.app:create_app --factory" in api
    for cmd in ("worker", "beat", "migrate", "create-admin"):
        assert re.search(rf"(?m)^\s*{cmd}\)", text), cmd


def test_init_script_uses_psql_variables():
    text = INIT.read_text()
    assert "set -eu" in text
    assert "-v pw=" in text and ":'pw'" in text
    sql = text.split("<<'SQL'", 1)[1]  # quoted heredoc: shell expands nothing
    assert "APP_DB_PASSWORD" not in sql
    assert ":'pw'" in sql
    assert "NOSUPERUSER" in text


GATEWAY = "172.28.0.1"


def test_network_pinned_and_attached(compose):
    cfg = compose["networks"]["cvenom"]["ipam"]["config"][0]
    assert cfg["subnet"] == "172.28.0.0/24" and cfg["gateway"] == GATEWAY
    for name, svc in compose["services"].items():
        assert "cvenom" in svc["networks"], name


def test_forwarded_allow_ips_defaults_to_gateway(compose):
    env = compose["services"]["api"]["environment"]
    assert env["FORWARDED_ALLOW_IPS"] == "${FORWARDED_ALLOW_IPS:-" + GATEWAY + "}"


def test_env_example_trusted_proxy_cidrs_has_gateway():
    m = re.search(r"(?m)^TRUSTED_PROXY_CIDRS=(.*)$", ENV_EXAMPLE.read_text())
    assert m and GATEWAY in m.group(1)


def test_postgres_healthcheck_uses_tcp(compose):
    assert "-h 127.0.0.1" in " ".join(compose["services"]["postgres"]["healthcheck"]["test"])


def test_build_is_fully_hashed():
    text = DOCKERFILE.read_text()
    assert "--no-build-isolation" in text
    assert "build-constraints.lock" in text
    bc = (ROOT / "backend" / "build-constraints.lock").read_text()
    assert "setuptools==" in bc and "--hash=sha256:" in bc


@pytest.mark.parametrize("svc", APP_SERVICES)
def test_prod_requires_secrets_key(compose, svc):
    assert compose["services"][svc]["environment"]["REQUIRE_SECRETS_KEY"] == "true"


def test_env_example_requires_secrets_key():
    assert re.search(r"(?m)^REQUIRE_SECRETS_KEY=true$", ENV_EXAMPLE.read_text())


DEPLOY_MD = ROOT / "docs" / "deploy.md"
BLANKED = ("POSTGRES_PASSWORD", "APP_DB_PASSWORD", "REDIS_PASSWORD")


@pytest.mark.parametrize("svc", APP_SERVICES)
def test_app_services_do_not_receive_infra_passwords(compose, svc):
    # M-e: env_file passes the whole .env; the internet-facing app containers must not
    # hold the Postgres superuser or Redis password (REDIS_URL already embeds the latter).
    env = compose["services"][svc]["environment"]
    for key in BLANKED:
        assert env[key] == "", (svc, key)


def test_env_example_has_no_admin_password():
    assert not re.search(r"(?m)^\s*#?\s*ADMIN_PASSWORD=", ENV_EXAMPLE.read_text())


def _compose_commands(text):
    return [line for line in text.splitlines() if "docker compose" in line]


@pytest.mark.parametrize("path", [DEPLOY_MD, COMPOSE])
def test_every_compose_command_passes_root_env_file(path):
    # The project directory is deploy/, so without --env-file the root .env is not
    # used for ${VAR:?} interpolation and the first-run command fails.
    cmds = _compose_commands(path.read_text())
    assert cmds, path
    for line in cmds:
        assert "docker compose --env-file ./.env -f deploy/docker-compose.prod.yml" in line, line
