"""Versioned foundation API. No infrastructure execution routes are registered."""

import ipaddress
import sqlite3
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.exceptions import HTTPException
from starlette.concurrency import run_in_threadpool

from . import __version__
from .auth import ABSOLUTE_SECONDS, COOKIE, AuthService, Role
from .config import Settings
from .database import DataAccess, Store, canonical, identifier
from .errors import Denied
from .queue import JobQueue


def failure(code, status, correlation, *, retry_after=None, details=None):
    headers = {"Cache-Control": "no-store", "X-Correlation-ID": correlation, "X-Content-Type-Options": "nosniff"}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse({"code": code, "message": code, "correlation_id": correlation, "details": details or {}},
                        status_code=status, headers=headers)


class SecurityBoundary:
    def __init__(self, app, settings, auth):
        self.app, self.settings, self.auth = app, settings, auth

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        correlation = identifier()
        state = scope.setdefault("state", {})
        state["correlation_id"] = correlation
        peer = (scope.get("client") or ("unknown", 0))[0]
        state["client_ip"] = peer
        if scope["path"].startswith("/api/"):
            pairs = scope["headers"]
            headers = {name.lower(): value.decode("latin-1") for name, value in pairs}
            critical = (b"host", b"origin", b"cookie", b"x-csrf-token", b"content-length", b"x-forwarded-for", b"x-forwarded-proto")
            code, status = None, 400
            if any(sum(name.lower() == key for name, _ in pairs) > 1 for key in critical):
                code = "AMBIGUOUS_HEADERS"
            scheme = scope.get("scheme")
            if self.settings.trusts(peer):
                forwarded = headers.get(b"x-forwarded-for")
                try:
                    if forwarded is not None:
                        state["client_ip"] = str(ipaddress.ip_address(forwarded))
                    if b"x-forwarded-proto" in headers:
                        scheme = headers[b"x-forwarded-proto"]
                except ValueError:
                    code = "PROXY_HEADERS_INVALID"
            if headers.get(b"host", "").lower() != self.settings.host:
                code = "HOST_INVALID"
            if scheme != "https":
                code = "HTTPS_REQUIRED"
            body = None
            if scope["method"] not in ("GET", "HEAD", "OPTIONS"):
                if headers.get(b"origin") != self.settings.public_origin:
                    code, status = "ORIGIN_REQUIRED", 403
                elif headers.get(b"content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    code, status = "JSON_REQUIRED", 415
                length = headers.get(b"content-length")
                if length is not None:
                    if not length.isascii() or not length.isdecimal():
                        code, status = "CONTENT_LENGTH_INVALID", 400
                    elif len(length) > 8 or int(length) > 16384:
                        code, status = "BODY_TOO_LARGE", 413
                if code is None and scope["path"] == "/api/v1/auth/login" and scope["method"] == "POST":
                    try:
                        await run_in_threadpool(self.auth.reserve_login_request, state["client_ip"], correlation=correlation)
                    except Denied as error:
                        return await failure(error.code, error.status, correlation, retry_after=error.retry_after)(scope, receive, send)
                    except (OSError, RuntimeError, sqlite3.Error):
                        return await failure("STORAGE_UNAVAILABLE", 503, correlation)(scope, receive, send)
                if code is None:
                    chunks, size = [], 0
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        chunk = message.get("body", b"")
                        size += len(chunk)
                        if size > 16384:
                            code, status = "BODY_TOO_LARGE", 413
                            break
                        chunks.append(chunk)
                        if not message.get("more_body", False):
                            break
                    body = b"".join(chunks)
            if code:
                return await failure(code, status, correlation)(scope, receive, send)
            if body is not None:
                original_receive = receive
                sent = False

                async def buffered_receive():
                    nonlocal sent
                    if not sent:
                        sent = True
                        return {"type": "http.request", "body": body, "more_body": False}
                    return await original_receive()

                receive = buffered_receive

        async def safe_send(message):
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                for name, value in ((b"cache-control", b"no-store"), (b"x-correlation-id", correlation.encode()), (b"x-content-type-options", b"nosniff")):
                    response_headers = [(n, v) for n, v in response_headers if n.lower() != name]
                    response_headers.append((name, value))
                message = {**message, "headers": response_headers}
            await send(message)

        await self.app(scope, receive, safe_send)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Login(Input):
    username: Annotated[str, Field(min_length=3, max_length=64)]
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]


class Grant(Input):
    permission: Literal["users:manage", "audit:read", "vps:read", "vps:probe", "vps:restart", "secrets:View Metadata", "secrets:Use", "secrets:Manage"]
    resource_id: Annotated[str, Field(min_length=1, max_length=26)]


class CreateUser(Login):
    role: Literal["Admin", "Operator", "Auditor"]
    grants: Annotated[list[Grant], Field(max_length=100)] = Field(default_factory=list)


class UpdateUser(Input):
    role: Literal["Admin", "Operator", "Auditor"]
    grants: Annotated[list[Grant], Field(max_length=100)] = Field(default_factory=list)
    disabled: bool = False


class Reauthentication(Input):
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]
    plan_hash: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]


def create_app(settings: Settings, *, auth: AuthService | None = None):
    import os
    access = DataAccess(settings.database_owner_uid if settings.database_owner_uid is not None else os.geteuid(), settings.database_gid)
    service = auth or AuthService(Store(settings.database, access=access))
    queue = JobQueue(service.store, clock=service.clock)
    app = FastAPI(title="HostOrbit API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = service
    app.add_middleware(SecurityBoundary, settings=settings, auth=service)

    @app.exception_handler(Denied)
    async def denied(request, error):
        return failure(error.code, error.status, request.state.correlation_id, retry_after=error.retry_after)

    @app.exception_handler(RequestValidationError)
    async def invalid(request, error):
        # FastAPI's default includes input values, which may contain passwords/tokens.
        known = {"username", "password", "role", "grants", "disabled", "plan_hash", "permission", "resource_id", "after"}
        fields = [{"field": ".".join(str(v) for v in e["loc"] if v in known or isinstance(v, int)) or "request",
                   "reason": e["type"]} for e in error.errors()]
        return failure("VALIDATION_FAILED", 422, request.state.correlation_id, details={"fields": fields})

    @app.exception_handler(HTTPException)
    async def http_failure(request, error):
        codes = {404: "RESOURCE_NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return failure(codes.get(error.status_code, "REQUEST_DENIED"), error.status_code, request.state.correlation_id)

    @app.exception_handler(OSError)
    async def filesystem_failure(request, error):
        return failure("STORAGE_UNAVAILABLE", 503, request.state.correlation_id)

    @app.exception_handler(sqlite3.Error)
    async def storage_failure(request, error):
        return failure("STORAGE_UNAVAILABLE", 503, request.state.correlation_id)

    @app.exception_handler(RuntimeError)
    async def contract_failure(request, error):
        return failure("CONTROLLER_NOT_READY", 503, request.state.correlation_id)

    def token(request):
        return request.cookies.get(COOKIE)

    def csrf(request):
        return request.headers.get("x-csrf-token")

    def principal(request: Request):
        return service.authenticate(token(request), ip=request.state.client_ip, csrf=csrf(request),
                                    mutating=request.method not in ("GET", "HEAD", "OPTIONS"))

    def audit_access(request: Request, actor=Depends(principal)):
        service.require_permission(token(request), "audit:read", "*")
        return actor

    @app.get("/healthz", include_in_schema=False)
    def health():
        # Liveness only; does not assert remote health or recovery readiness.
        return {"status": "alive", "version": __version__}

    @app.post("/api/v1/auth/login")
    def login(body: Login, request: Request, response: Response):
        tokens, actor = service.login(body.username, body.password.get_secret_value(), ip=request.state.client_ip,
                                      previous=token(request), correlation=request.state.correlation_id, count_request=False)
        response.set_cookie(COOKIE, tokens.session, secure=True, httponly=True, samesite="strict", path="/", max_age=ABSOLUTE_SECONDS)
        return {"user": {"id": actor.id, "username": actor.username, "role": actor.role}, "csrf_token": tokens.csrf}

    @app.get("/api/v1/auth/session")
    def session(request: Request, actor=Depends(principal)):
        actor, fresh_csrf = service.session_info(token(request))
        return {"user": {"id": actor.id, "username": actor.username, "role": actor.role}, "csrf_token": fresh_csrf}

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(request: Request, response: Response, actor=Depends(principal)):
        service.logout(token(request), csrf(request), correlation=request.state.correlation_id)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")

    @app.post("/api/v1/auth/reauth")
    def reauth(body: Reauthentication, request: Request, actor=Depends(principal)):
        return service.reauthenticate(token(request), csrf(request), body.password.get_secret_value(), body.plan_hash,
                                      correlation=request.state.correlation_id)

    @app.get("/api/v1/users")
    def list_users(request: Request, response: Response, actor=Depends(principal)):
        values, current = service.list_users(token(request))
        response.headers["ETag"] = current
        return {"items": values}

    @app.get("/api/v1/users/{user_id}")
    def get_user(user_id: str, request: Request, response: Response, actor=Depends(principal)):
        value, current = service.get_user(token(request), user_id)
        response.headers["ETag"] = current
        return value

    @app.post("/api/v1/users", status_code=201)
    def create_user(body: CreateUser, request: Request, actor=Depends(principal)):
        return service.create_user(token(request), csrf(request), body.username, body.password.get_secret_value(), body.role,
                                   [g.model_dump() for g in body.grants], if_match=request.headers.get("if-match"), correlation=request.state.correlation_id)

    @app.put("/api/v1/users/{user_id}")
    def update_user(user_id: str, body: UpdateUser, request: Request, response: Response, actor=Depends(principal)):
        result = service.update_user(token(request), csrf(request), user_id, body.role, [g.model_dump() for g in body.grants], body.disabled,
                                     if_match=request.headers.get("if-match"), correlation=request.state.correlation_id)
        from .auth import etag
        response.headers["ETag"] = etag(result, result["revision"])
        return result

    @app.get("/api/v1/audit")
    def audit(request: Request, after: Annotated[int, Field(ge=0, lt=2**63)] = 0, actor=Depends(audit_access)):
        return {"items": service.audit_events(token(request), after)}

    @app.post("/api/v1/resources/{resource_id}/observations", status_code=202)
    def observe_resource(resource_id: str, body: Input, request: Request, response: Response, actor=Depends(principal)):
        result = queue.enqueue_probe(service, token(request), csrf(request), resource_id, request.headers.get("idempotency-key"))
        response.headers["Location"] = f'/api/v1/jobs/{result["id"]}'
        return result

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str, request: Request, response: Response, actor=Depends(principal)):
        value, current = queue.get(service, token(request), job_id)
        response.headers["ETag"] = current
        return value

    @app.get("/api/v1/events")
    def events(request: Request, actor=Depends(audit_access)):
        try:
            after = int(request.headers.get("last-event-id", "0"))
            if not 0 <= after < 2**63:
                raise ValueError
        except ValueError:
            raise Denied("EVENT_CURSOR_INVALID", 400) from None
        # Bounded replay stream; EventSource reconnects after the persisted batch.
        values = service.audit_events(token(request), after)
        chunks = ["retry: 1000\n\n"] + [f'id: {v["seq"]}\nevent: audit\ndata: {canonical(v["event"])}\n\n' for v in values]
        return StreamingResponse(iter(chunks), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/v1/openapi.json", include_in_schema=False)
    def schema(request: Request, actor=Depends(principal)):
        if actor.role not in (Role.OWNER, Role.ADMIN):
            raise Denied("FORBIDDEN")
        return get_openapi(title=app.title, version=app.version, routes=app.routes)

    return app
