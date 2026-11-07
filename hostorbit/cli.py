"""Local administrative entry points. Passwords and bootstrap tokens use hidden input."""

import argparse
import getpass
from pathlib import Path
import sys

from .auth import AuthService
from .config import Settings
from .database import Store
from .errors import Denied


def main(argv=None):
    parser = argparse.ArgumentParser(prog="hostorbit")
    parser.add_argument("--database", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a new private application database")
    commands.add_parser("bootstrap-token", help="Issue or rotate the local one-time 10-minute Owner token")
    owner = commands.add_parser("create-owner", help="Consume the bootstrap token locally")
    owner.add_argument("--username", required=True)
    serve = commands.add_parser("serve", help="Serve the foundation API on loopback behind a configured HTTPS proxy")
    serve.add_argument("--origin", required=True)
    serve.add_argument("--trusted-proxy", action="append", default=[])
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            Store.initialize(args.database)
            print("Database initialized")
            return 0
        store = Store(args.database)
        with store.connect():
            pass
        service = AuthService(store)
        if args.command == "bootstrap-token":
            print(service.issue_bootstrap())
        elif args.command == "create-owner":
            token = getpass.getpass("Bootstrap token: ")
            secret = getpass.getpass("Owner password: ")
            if secret != getpass.getpass("Confirm password: "):
                raise Denied("PASSWORD_CONFIRMATION_MISMATCH", 422)
            owner_id = service.create_owner(token, args.username, secret)
            print(f"Owner created {owner_id}")
        elif args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise ValueError("Port is outside range")
            import uvicorn
            from .api import create_app
            settings = Settings(args.database, args.origin, tuple(args.trusted_proxy))
            uvicorn.run(create_app(settings, auth=service), host="127.0.0.1", port=args.port,
                        proxy_headers=False, access_log=False)
    except (Denied, OSError, RuntimeError, ValueError) as error:
        code = error.code if isinstance(error, Denied) else type(error).__name__
        print(f"HostOrbit command failed {code}", file=sys.stderr)
        return 1
    return 0
