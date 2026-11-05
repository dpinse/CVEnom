# Development

## One-command dev stack (Docker, live reload)

```bash
cp .env.dev.example .env.dev      # untracked; throwaway local values
docker compose -f docker-compose.dev.yml up --build
```

Then open <http://127.0.0.1:5173>. What runs:

| Service | What | Reload |
| --- | --- | --- |
| `postgres`, `redis` | same images as the root `docker-compose.yml` | n/a |
| `migrate` | `alembic upgrade head`, once per `up`, before the api starts | n/a |
| `api` (127.0.0.1:8000) | `uvicorn --reload` | restarts on edits under `backend/src` |
| `worker`, `beat` | Celery under `watchfiles` | restart on edits to `*.py` under `backend/src` |
| `frontend` (127.0.0.1:5173) | Vite dev server, HMR | proxies `/api` and the WebSocket to `api:8000` |

Every published port is bound to `127.0.0.1`. `backend/src`, `backend/migrations` and
`frontend/` are bind-mounted, so edits need no rebuild. Rebuild only when dependencies change:
`docker compose -f docker-compose.dev.yml build` after editing `backend/pyproject.toml`; the
frontend reinstalls by itself when `frontend/package-lock.json` changes (its `node_modules` lives
in a named volume).

Bind mounts on Windows/OneDrive deliver no file events, so the stack polls:
`WATCHFILES_FORCE_POLLING=true` for uvicorn/watchfiles, `CVENOM_VITE_POLLING=1` for Vite
(`server.watch.usePolling`). `CVENOM_API_PROXY` (set to `http://api:8000` in the stack) is the Vite
proxy target; it defaults to `http://127.0.0.1:8000`.

To change host ports (e.g. another Postgres already holds 5432), set `DEV_PG_PORT`,
`DEV_REDIS_PORT`, `DEV_API_PORT` or `DEV_FRONTEND_PORT` in `.env.dev` and start with
`docker compose --env-file .env.dev -f docker-compose.dev.yml up`.

Reset the database: `docker compose -f docker-compose.dev.yml down -v`.

### Instant first scrape

Whenever a worker starts it queues one run of every registered collector, so a fresh stack fills in
immediately instead of waiting for each cron slot. The per-collector Redis lock prevents double runs
and collectors without a key skip. To trigger the same thing by hand:

```bash
docker compose -f docker-compose.dev.yml exec worker python -c "from cvenom.tasks import REGISTRY, run_collector_task as t; [t.delay(n) for n in REGISTRY]"
# production:
docker compose --env-file ./.env -f deploy/docker-compose.prod.yml exec worker python -c "from cvenom.tasks import REGISTRY, run_collector_task as t; [t.delay(n) for n in REGISTRY]"
```

## Host-only alternative

Run just Postgres and Redis in Docker and the apps on the host:

```bash
docker compose up -d                      # root docker-compose.yml: postgres + redis on localhost
cd backend
python -m venv .venv && . .venv/Scripts/activate      # Windows Git Bash; use .venv/bin/activate elsewhere
pip install -e ".[dev]"
export DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/cvenom REDIS_URL=redis://127.0.0.1:6379/0
alembic upgrade head
uvicorn cvenom.api.app:create_app --factory --reload            # api on :8000
watchfiles "celery -A cvenom.tasks:celery_app worker --loglevel=INFO" src   # worker (second shell)
cd ../frontend && npm ci && npm run dev                          # Vite on :5173, proxies /api to 127.0.0.1:8000
```

Tests: `cd backend && python -m pytest -q` (uses the root compose Postgres; set
`CVENOM_TEST_PG_PORT` to point at a different one) and, in `frontend/`, `npm test`, `npm run lint`,
`npm run typecheck`.
