"""Local Owner bootstrap and server-side authentication with scoped authorization."""

from dataclasses import dataclass, field
import base64
from enum import StrEnum
import hashlib
import hmac
from importlib.resources import files
import json
import re
import secrets
import time

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

from .database import Store, canonical, identifier
from .errors import Denied


IDLE_SECONDS = 1800
ABSOLUTE_SECONDS = 43200
BOOTSTRAP_SECONDS = 600
REAUTH_SECONDS = 300
COOKIE = "__Host-hostorbit_session"
_PROFILE = json.loads(files("hostorbit").joinpath("release-manifest.json").read_text())["password_profile"]


class Role(StrEnum):
    OWNER = "Owner"
    ADMIN = "Admin"
    OPERATOR = "Operator"
    AUDITOR = "Auditor"


PERMISSIONS = frozenset(("users:manage", "audit:read", "vps:read", "vps:restart",
                         "secrets:View Metadata", "secrets:Use", "secrets:Manage"))
_ROLE_PERMISSIONS = {
    Role.ADMIN: PERMISSIONS,
    Role.OPERATOR: frozenset(("vps:read", "vps:restart", "secrets:Use")),
    Role.AUDITOR: frozenset(("vps:read", "audit:read", "secrets:View Metadata")),
}


@dataclass(frozen=True)
class Tokens:
    session: str = field(repr=False)
    csrf: str = field(repr=False)


@dataclass(frozen=True)
class Principal:
    id: str
    username: str
    role: Role


def digest(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(token.encode("ascii")).digest()


def csrf_for(session):
    value = hmac.digest(session.encode("ascii"), b"hostorbit-csrf-v1", "sha256")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def username(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{2,63}", value):
        raise Denied("USERNAME_INVALID", 422)
    return value.lower()


def password(value):
    if not isinstance(value, str) or not 12 <= len(value) <= 128 or len(value.encode("utf-8")) > 512:
        raise Denied("PASSWORD_POLICY", 422)
    return value


def etag(value, revision):
    return f'"r:{revision}:{hashlib.sha256(canonical(value).encode()).hexdigest()}"'


def check_etag(submitted, current):
    if submitted is None:
        raise Denied("IF_MATCH_REQUIRED", 428)
    if submitted != current:
        raise Denied("STALE_REVISION", 412)


class AuthService:
    def __init__(self, store: Store, *, clock=time.time):
        self.store = store
        self.clock = clock
        self.hasher = PasswordHasher(
            time_cost=_PROFILE["time_cost"], memory_cost=_PROFILE["memory_cost_kib"],
            parallelism=_PROFILE["parallelism"], hash_len=_PROFILE["hash_len"],
            salt_len=_PROFILE["salt_len"], type=Type.ID,
        )
        self._dummy = self.hasher.hash(secrets.token_urlsafe(32))

    def _event(self, db, kind, actor="anonymous", target="controller", outcome="SUCCEEDED", correlation="local-cli", details=None):
        return self.store.event(db, at=int(self.clock()), actor=actor, kind=kind, target=target,
                                outcome=outcome, correlation=correlation, details=details)

    def issue_bootstrap(self):
        token = secrets.token_urlsafe(32)
        with self.store.write() as db:
            if db.execute("SELECT 1 FROM users WHERE role='Owner'").fetchone():
                raise Denied("OWNER_ALREADY_EXISTS", 409)
            now = int(self.clock())
            db.execute("INSERT OR REPLACE INTO bootstrap VALUES(1,?,?,?)", (digest(token), now, now + BOOTSTRAP_SECONDS))
            self._event(db, "owner.bootstrap_issued")
        return token

    def create_owner(self, token, account, secret):
        account = username(account)
        hashed = self.hasher.hash(password(secret))
        user_id = identifier()
        with self.store.write() as db:
            now = int(self.clock())
            row = db.execute("SELECT * FROM bootstrap WHERE singleton=1").fetchone()
            supplied = digest(token)
            if (row is None or supplied is None or not secrets.compare_digest(row["digest"], supplied)
                    or not row["issued_at"] <= now < row["expires_at"]):
                raise Denied("BOOTSTRAP_INVALID", 401)
            if db.execute("SELECT 1 FROM users WHERE role='Owner'").fetchone():
                raise Denied("OWNER_ALREADY_EXISTS", 409)
            db.execute("INSERT INTO users(id,username,password_hash,password_profile,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                       (user_id, account, hashed, _PROFILE["version"], Role.OWNER, now, now))
            db.execute("DELETE FROM bootstrap")
            self._event(db, "owner.created", actor=user_id, target=user_id)
        return user_id

    def _session(self, db, token, *, csrf=None, mutating=False):
        row = db.execute("""SELECT u.*,s.csrf_digest,s.issued_at,s.last_seen FROM sessions s
                            JOIN users u ON u.id=s.user_id WHERE s.digest=?""", (digest(token),)).fetchone()
        now = int(self.clock())
        if (row is None or row["disabled"] or row["last_seen"] > now or now - row["last_seen"] >= IDLE_SECONDS
                or row["issued_at"] > now or now - row["issued_at"] >= ABSOLUTE_SECONDS):
            raise Denied("SESSION_REQUIRED", 401)
        if mutating:
            submitted = digest(csrf)
            if submitted is None or not secrets.compare_digest(row["csrf_digest"], submitted):
                raise Denied("CSRF_REQUIRED")
        return row

    @staticmethod
    def _principal(row):
        return Principal(row["id"], row["username"], Role(row["role"]))

    def _budget(self, db, user_id, ip):
        now = int(self.clock())
        db.execute("DELETE FROM api_calls WHERE at<=?", (now - 60,))
        counts = db.execute("SELECT sum(user_id=?),sum(ip=?) FROM api_calls", (user_id, ip)).fetchone()
        if (user_id != "anonymous" and (counts[0] or 0) >= 120) or (counts[1] or 0) >= 600:
            raise Denied("API_RATE_LIMIT", 429, retry_after=60)
        db.execute("INSERT INTO api_calls VALUES(?,?,?)", (user_id, ip, now))

    def authenticate(self, token, *, ip, csrf=None, mutating=False):
        failure = None
        principal = None
        with self.store.write() as db:
            try:
                row = self._session(db, token, csrf=csrf, mutating=mutating)
                principal = self._principal(row)
            except Denied as error:
                failure = error
                if error.code == "SESSION_REQUIRED":
                    db.execute("DELETE FROM sessions WHERE digest=?", (digest(token),))
            try:
                self._budget(db, principal.id if principal else "anonymous", ip)
            except Denied as error:
                failure = error
            if failure is None:
                db.execute("UPDATE sessions SET last_seen=? WHERE digest=?", (int(self.clock()), digest(token)))
        if failure:
            raise failure
        return principal

    def reserve_login_request(self, ip, *, correlation):
        failure = None
        with self.store.write() as db:
            now = int(self.clock())
            db.execute("DELETE FROM login_requests WHERE at<=?", (now - 900,))
            if db.execute("SELECT count(*) FROM login_requests WHERE ip=?", (ip,)).fetchone()[0] >= 20:
                self._event(db, "auth.login_limited", outcome="DENIED", correlation=correlation)
                failure = Denied("LOGIN_RATE_LIMIT", 429, retry_after=900)
            else:
                db.execute("INSERT INTO login_requests VALUES(?,?)", (ip, now))
        if failure:
            raise failure

    def login(self, account, secret, *, ip, previous=None, correlation, count_request=True):
        if count_request:
            self.reserve_login_request(ip, correlation=correlation)
        account = username(account)
        attempt_id = identifier()
        failure = None
        with self.store.write() as db:
            now = int(self.clock())
            db.execute("DELETE FROM login_attempts WHERE at<=?", (now - 900,))
            pair_count = db.execute("SELECT count(*) FROM login_attempts WHERE ip=? AND account=? AND failed=1", (ip, account)).fetchone()[0]
            if pair_count >= 5:
                self._event(db, "auth.login_limited", outcome="DENIED", correlation=correlation)
                failure = Denied("LOGIN_RATE_LIMIT", 429, retry_after=900)
            else:
                # Pending verifications count as failures until committed, bounding concurrent guesses.
                db.execute("INSERT INTO login_attempts VALUES(?,?,?,?,1)", (attempt_id, account, ip, now))
                row = db.execute("SELECT * FROM users WHERE username=?", (account,)).fetchone()
        if failure:
            raise failure
        valid = False
        try:
            valid = self.hasher.verify(row["password_hash"] if row else self._dummy, secret)
        except (VerificationError, InvalidHashError):
            pass
        replacement_hash = None
        if valid and row is not None and (self.hasher.check_needs_rehash(row["password_hash"]) or row["password_profile"] != _PROFILE["version"]):
            replacement_hash = self.hasher.hash(secret)
        session = secrets.token_urlsafe(32)
        tokens = Tokens(session, csrf_for(session))
        with self.store.write() as db:
            current = db.execute("SELECT * FROM users WHERE username=?", (account,)).fetchone()
            if not valid or row is None or current is None or current["disabled"] or current["password_hash"] != row["password_hash"]:
                self._event(db, "auth.login_failed", outcome="DENIED", correlation=correlation)
                failure = Denied("LOGIN_FAILED", 401)
            else:
                if replacement_hash is not None:
                    db.execute("UPDATE users SET password_hash=?,password_profile=? WHERE id=?",
                               (replacement_hash, _PROFILE["version"], current["id"]))
                now = int(self.clock())
                db.execute("DELETE FROM sessions WHERE digest=?", (digest(previous),))
                db.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (digest(tokens.session), current["id"], digest(tokens.csrf), now, now))
                db.execute("UPDATE login_attempts SET failed=0 WHERE id=?", (attempt_id,))
                self._event(db, "auth.login", actor=current["id"], target=current["id"], correlation=correlation)
        if failure:
            raise failure
        return tokens, self._principal(current)

    def session_info(self, token):
        with self.store.read() as db:
            row = self._session(db, token)
            csrf = csrf_for(token)
            if not secrets.compare_digest(digest(csrf), row["csrf_digest"]):
                raise Denied("SESSION_REQUIRED", 401)
        return self._principal(row), csrf

    def logout(self, token, csrf, *, correlation):
        with self.store.write() as db:
            row = self._session(db, token, csrf=csrf, mutating=True)
            db.execute("DELETE FROM sessions WHERE digest=?", (digest(token),))
            self._event(db, "auth.logout", actor=row["id"], target=row["id"], correlation=correlation)

    @staticmethod
    def require(db, row, permission, resource):
        if permission not in PERMISSIONS:
            raise Denied("PERMISSION_UNKNOWN")
        if row["role"] == Role.OWNER:
            return
        allowed = _ROLE_PERMISSIONS.get(Role(row["role"]), frozenset())
        if permission not in allowed or not db.execute(
            "SELECT 1 FROM grants WHERE user_id=? AND permission=? AND resource_id IN (?, '*')",
            (row["id"], permission, resource),
        ).fetchone():
            raise Denied("FORBIDDEN")

    def require_permission(self, token, permission, resource):
        with self.store.read() as db:
            self.require(db, self._session(db, token), permission, resource)

    def audit_events(self, token, after):
        with self.store.read() as db:
            self.require(db, self._session(db, token), "audit:read", "*")
            return [dict(seq=row["seq"], event=json.loads(row["payload"])) for row in db.execute(
                "SELECT seq,payload FROM outbox WHERE seq>? ORDER BY seq LIMIT 100", (after,),
            )]

    @staticmethod
    def _public_user(db, row):
        return {**{k: row[k] for k in ("id", "username", "role", "revision", "created_at", "updated_at")},
                "observed_at": row["updated_at"],
                "disabled": bool(row["disabled"]),
                "grants": [dict(permission=g["permission"], resource_id=g["resource_id"]) for g in db.execute(
                    "SELECT permission,resource_id FROM grants WHERE user_id=? ORDER BY permission,resource_id", (row["id"],),
                )]}

    def _users(self, db, actor):
        self.require(db, actor, "users:manage", "*")
        query = "SELECT * FROM users" if actor["role"] == Role.OWNER else "SELECT * FROM users WHERE role NOT IN ('Owner','Admin')"
        values = [self._public_user(db, row) for row in db.execute(query + " ORDER BY id")]
        return values, etag(values, sum(row["revision"] for row in values))

    def list_users(self, token):
        with self.store.read() as db:
            return self._users(db, self._session(db, token))

    def get_user(self, token, target):
        with self.store.read() as db:
            actor = self._session(db, token)
            self.require(db, actor, "users:manage", "*")
            row = db.execute("SELECT * FROM users WHERE id=?", (target,)).fetchone()
            if row is None or (actor["role"] != Role.OWNER and row["role"] in (Role.OWNER, Role.ADMIN)):
                raise Denied("RESOURCE_NOT_FOUND", 404)
            public = self._public_user(db, row)
            return public, etag(public, row["revision"])

    def _delegate(self, db, actor, grants):
        if actor["role"] != Role.OWNER:
            for permission, resource in grants:
                self.require(db, actor, permission, resource)

    @staticmethod
    def _grants(role, grants):
        role = Role(role)
        if role == Role.OWNER:
            raise Denied("OWNER_LOCAL_ONLY")
        values = {(g["permission"], g["resource_id"]) for g in grants}
        if len(values) != len(grants):
            raise Denied("DUPLICATE_GRANT", 422)
        for permission, resource in values:
            if (permission not in _ROLE_PERMISSIONS[role]
                    or (resource != "*" and not re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", resource))
                    or (role == Role.OPERATOR and resource == "*")):
                raise Denied("GRANT_INVALID", 422)
        return sorted(values)

    def create_user(self, token, csrf, account, secret, role, grants, *, if_match, correlation):
        account, role = username(account), Role(role)
        grants = self._grants(role, grants)
        with self.store.read() as db:
            actor = self._session(db, token, csrf=csrf, mutating=True)
            self._users(db, actor)
            self._delegate(db, actor, grants)
            if actor["role"] != Role.OWNER and role == Role.ADMIN:
                raise Denied("FORBIDDEN")
        hashed = self.hasher.hash(password(secret))
        with self.store.write() as db:
            actor = self._session(db, token, csrf=csrf, mutating=True)
            _, current = self._users(db, actor)
            check_etag(if_match, current)
            if actor["role"] != Role.OWNER and role == Role.ADMIN:
                raise Denied("FORBIDDEN")
            self._delegate(db, actor, grants)
            if db.execute("SELECT 1 FROM users WHERE username=?", (account,)).fetchone():
                raise Denied("USERNAME_CONFLICT", 409)
            now, user_id = int(self.clock()), identifier()
            db.execute("INSERT INTO users(id,username,password_hash,password_profile,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                       (user_id, account, hashed, _PROFILE["version"], role, now, now))
            db.executemany("INSERT INTO grants VALUES(?,?,?)", [(user_id, p, r) for p, r in grants])
            self._event(db, "user.created", actor=actor["id"], target=user_id, correlation=correlation, details={"role": role})
            return self._public_user(db, db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def update_user(self, token, csrf, target, role, grants, disabled, *, if_match, correlation):
        role = Role(role)
        grants = self._grants(role, grants)
        with self.store.write() as db:
            actor = self._session(db, token, csrf=csrf, mutating=True)
            self.require(db, actor, "users:manage", "*")
            row = db.execute("SELECT * FROM users WHERE id=?", (target,)).fetchone()
            if row is None or row["role"] == Role.OWNER or (actor["role"] != Role.OWNER and (row["role"] == Role.ADMIN or role == Role.ADMIN)):
                raise Denied("RESOURCE_NOT_FOUND", 404)
            self._delegate(db, actor, grants)
            public = self._public_user(db, row)
            check_etag(if_match, etag(public, row["revision"]))
            now = int(self.clock())
            db.execute("UPDATE users SET role=?,disabled=?,revision=revision+1,updated_at=? WHERE id=?", (role, int(disabled), now, target))
            db.execute("DELETE FROM grants WHERE user_id=?", (target,))
            db.executemany("INSERT INTO grants VALUES(?,?,?)", [(target, p, r) for p, r in grants])
            db.execute("DELETE FROM sessions WHERE user_id=?", (target,))
            self._event(db, "user.permissions_changed", actor=actor["id"], target=target, correlation=correlation,
                        details={"role": role, "disabled": bool(disabled), "revision": row["revision"] + 1})
            return self._public_user(db, db.execute("SELECT * FROM users WHERE id=?", (target,)).fetchone())

    def reauthenticate(self, token, csrf, secret, plan_hash, *, correlation):
        if not re.fullmatch(r"[0-9a-f]{64}", plan_hash):
            raise Denied("PLAN_HASH_INVALID", 422)
        failure = None
        with self.store.write() as db:
            row = self._session(db, token, csrf=csrf, mutating=True)
            now = int(self.clock())
            db.execute("DELETE FROM critical_attempts WHERE at<=?", (now - 900,))
            if db.execute("SELECT count(*) FROM critical_attempts WHERE user_id=?", (row["id"],)).fetchone()[0] >= 3:
                self._event(db, "auth.reauth_limited", actor=row["id"], outcome="DENIED", correlation=correlation)
                failure = Denied("CRITICAL_RATE_LIMIT", 429, retry_after=900)
            else:
                db.execute("INSERT INTO critical_attempts VALUES(?,?)", (row["id"], now))
        if failure:
            raise failure
        try:
            valid = self.hasher.verify(row["password_hash"], secret)
        except (VerificationError, InvalidHashError):
            valid = False
        grant_id = identifier()
        with self.store.write() as db:
            current = self._session(db, token, csrf=csrf, mutating=True)
            if not valid or row["password_hash"] != current["password_hash"]:
                self._event(db, "auth.reauth_failed", actor=current["id"], outcome="DENIED", correlation=correlation)
                failure = Denied("LOGIN_FAILED", 401)
            else:
                expires = int(self.clock()) + REAUTH_SECONDS
                db.execute("INSERT INTO reauth(id,session_digest,plan_hash,expires_at) VALUES(?,?,?,?)", (grant_id, digest(token), plan_hash, expires))
                self._event(db, "auth.reauthenticated", actor=current["id"], target=grant_id, correlation=correlation)
        if failure:
            raise failure
        return {"id": grant_id, "plan_hash": plan_hash, "expires_at": expires}

    def consume_reauthentication(self, db, token, grant_id, plan_hash):
        self._session(db, token)
        changed = db.execute("""UPDATE reauth SET consumed=1 WHERE id=? AND session_digest=?
                                AND plan_hash=? AND consumed=0 AND expires_at>?""",
                             (grant_id, digest(token), plan_hash, int(self.clock())))
        if changed.rowcount != 1:
            raise Denied("REAUTH_REQUIRED")
