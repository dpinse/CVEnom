import argparse
import getpass
import os
import sys

from sqlalchemy.exc import IntegrityError

from cvenom.auth.passwords import WeakPassword
from cvenom.auth.users import AdminExists, create_admin


def _read_password() -> str:
    env = os.environ.get("ADMIN_PASSWORD")
    if env:
        return env
    if sys.stdin.isatty():
        return getpass.getpass()
    return sys.stdin.readline().rstrip("\r\n")


def main(argv=None, *, session_factory=None) -> int:
    parser = argparse.ArgumentParser(prog="cvenom.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create-admin", help="create the first admin user")
    p.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    if session_factory is None:
        from cvenom.db import session_scope as session_factory

    password = _read_password()
    try:
        with session_factory() as session:
            user = create_admin(session, args.email, password)
            email = user.email
    except WeakPassword as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except IntegrityError:
        print("error: a user with that email already exists", file=sys.stderr)
        return 1
    except AdminExists:
        print("error: an admin already exists", file=sys.stderr)
        return 1
    print(f"created admin {email}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
