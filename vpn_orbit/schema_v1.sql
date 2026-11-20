
CREATE TABLE users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, password_profile INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Owner','Admin','Operator','Auditor')),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE grants (
    user_id TEXT NOT NULL REFERENCES users(id), permission TEXT NOT NULL,
    resource_id TEXT NOT NULL, PRIMARY KEY(user_id, permission, resource_id)
);
CREATE TABLE sessions (
    digest BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
    csrf_digest BLOB NOT NULL, issued_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE bootstrap (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest BLOB NOT NULL,
    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY, account TEXT NOT NULL, ip TEXT NOT NULL,
    at INTEGER NOT NULL, failed INTEGER NOT NULL CHECK(failed IN (0,1))
);
CREATE INDEX login_ip_time ON login_attempts(ip, at);
CREATE INDEX login_account_ip_time ON login_attempts(account, ip, at);
CREATE TABLE login_requests (ip TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX login_requests_ip_time ON login_requests(ip, at);
CREATE TABLE api_calls (user_id TEXT NOT NULL, ip TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX api_user_time ON api_calls(user_id, at);
CREATE INDEX api_ip_time ON api_calls(ip, at);
CREATE TABLE critical_attempts (user_id TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX critical_user_time ON critical_attempts(user_id, at);
CREATE TABLE reauth (
    id TEXT PRIMARY KEY, session_digest BLOB NOT NULL REFERENCES sessions(digest) ON DELETE CASCADE,
    plan_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
    at INTEGER NOT NULL, actor_id TEXT NOT NULL, event TEXT NOT NULL,
    target_id TEXT NOT NULL, outcome TEXT NOT NULL, correlation_id TEXT NOT NULL,
    details TEXT NOT NULL, previous_hash TEXT NOT NULL, digest TEXT NOT NULL
);
CREATE INDEX audit_target_time ON audit(target_id, at);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'AUDIT_APPEND_ONLY'); END;
CREATE TABLE outbox (
    seq INTEGER PRIMARY KEY REFERENCES audit(seq), event_id TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TRIGGER outbox_no_update BEFORE UPDATE ON outbox BEGIN SELECT RAISE(ABORT,'OUTBOX_APPEND_ONLY'); END;
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox BEGIN SELECT RAISE(ABORT,'OUTBOX_APPEND_ONLY'); END;
PRAGMA user_version = 1;
