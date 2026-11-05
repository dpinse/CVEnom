import argparse
import getpass
import os
import sys
from datetime import UTC, datetime

from sqlalchemy import select
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


def _create_admin(args, session_factory) -> int:
    password = _read_password()
    try:
        with session_factory() as session:
            user = create_admin(session, args.email, password)
            email = user.email
    except WeakPassword as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except IntegrityError:
        print("error: user with that email already exists or constraint violated", file=sys.stderr)
        return 1
    except AdminExists:
        print("error: an admin already exists", file=sys.stderr)
        return 1
    print(f"created admin {email}")
    return 0


def _reset_mfa(args, session_factory) -> int:
    """Break-glass: forget a user's MFA (e.g. the last admin lost their device).

    Revokes every session; the user enrolls again at the next sign-in."""
    from cvenom.auth.mfa import reset_mfa
    from cvenom.models import User

    email = args.email.strip().lower()
    with session_factory() as session:
        user_id = session.scalars(select(User.id).where(User.email == email)).first()
        if user_id is None:
            print("error: no such user", file=sys.stderr)
            return 1
        reset_mfa(session, user_id, datetime.now(UTC))
    print(f"mfa reset for {email}; all sessions revoked; enrollment required at next sign-in")
    return 0


def main(argv=None, *, session_factory=None) -> int:
    parser = argparse.ArgumentParser(prog="cvenom.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create-admin", help="create the first admin user")
    p.add_argument("--email", required=True)
    r = sub.add_parser("reset-mfa", help="forget a user's MFA so they enroll again (break-glass)")
    r.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    if session_factory is None:
        from cvenom.db import session_scope as session_factory

    if args.command == "reset-mfa":
        return _reset_mfa(args, session_factory)
    return _create_admin(args, session_factory)


if __name__ == "__main__":
    sys.exit(main())
