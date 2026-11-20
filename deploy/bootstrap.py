"""Install a fresh HostOrbit development Controller and loopback-only HTTPS WebUI."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile


TOOLS = Path("/opt/hostorbit-bootstrap")
APP = Path("/opt/hostorbit")
WEB_UNIT = Path("/etc/systemd/system/hostorbit-web.service")
DOCKER_SOCKET = "unix:///run/docker.sock"
PYTHON_VERSION = "3.15.2"
PYTHON_ARCHIVE = f"Python-{PYTHON_VERSION}.tar.xz"
PYTHON_SHA256 = "8b5536d280142ecf6cdfe15d12a21ba1c65e300bbf7b28a8d0cdb849575797de"
PYTHON = TOOLS / "python/bin/python3.15"
PYTHON_IMAGE = "docker.io/library/python@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928"
NODE_VERSION = "26.13.0"
NODE_ARCHIVE = f"node-v{NODE_VERSION}-linux-x64.tar.xz"
NODE_SHA256 = "d28a96af6c38596f6d9d97c0ee531c13d238d757742387d1928de822d959e997"
DOCKER_KEY = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
DOCKER_APT_SOURCE = Path("/etc/apt/sources.list.d/hostorbit-docker.sources")
DOCKER_APT_KEY = Path("/etc/apt/keyrings/hostorbit-docker.asc")
BUILD_USER = "ho-build"
SYSTEM_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
API_PORT = 18080
WEB_PORT = 18443
ORIGIN = f"https://127.0.0.1:{WEB_PORT}"


def run(*args, cwd=None, capture=False, output=None, env=None, identity=None, check=True):
    options = {}
    if identity:
        cwd = cwd or env["HOME"]
        options.update(user=identity.pw_uid, group=identity.pw_gid, extra_groups=[], umask=0o022)
    return subprocess.run(args, cwd=cwd, env={**SYSTEM_ENV, **(env or {})}, text=True,
                          stdout=subprocess.PIPE if capture else output, check=check, **options)


def capture(*args, **kwargs):
    return run(*args, capture=True, **kwargs).stdout.strip()


def stage(message):
    print(message, flush=True)


def memory_kib():
    return next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemTotal:"))


def python_build_jobs(cpus, memory):
    return max(1, min(cpus or 1, memory // 1024**2, 4))


def platform_and_ports():
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or platform.machine() != "x86_64":
        raise ValueError("Требуется Ubuntu Server amd64.")
    suites = {"24.04": "noble", "26.04": "resolute"}
    suite = suites.get(release.get("VERSION_ID"))
    if suite is None or release.get("VERSION_CODENAME") != suite:
        raise ValueError("Требуется Ubuntu Server 24.04 или 26.04.")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("Требуется запущенный host systemd.")
    for name in (TOOLS.parent, APP.parent, WEB_UNIT.parent, Path("/var/lib"), Path("/run")):
        for path in (name, *name.parents):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError(f"Небезопасные права каталога {path}.")
    memory = memory_kib()
    disk = shutil.disk_usage("/var/lib")
    if memory < 1792 * 1024 or disk.free < 6 * 1024**3:
        print("Рекомендация: 2 ГиБ RAM и 6 ГиБ свободного места в /var/lib.", file=sys.stderr)
    for port in (API_PORT, WEB_PORT):
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError as error:
                raise ValueError(f"Порт 127.0.0.1:{port} занят.") from error
    for path in (APP, TOOLS, WEB_UNIT, Path("/etc/hostorbit"), Path("/var/lib/hostorbit"),
                 Path("/run/hostorbit")):
        if path.exists() or path.is_symlink():
            raise ValueError(f"Найдена существующая установка или её часть: {path}.")
    return suite


def download(url, output, sha256=None):
    run("curl", "--disable", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
        "--proto-redir", "=https", "--connect-timeout", "15", "--max-time", "300",
        "--retry", "2", "--output", output, url)
    if sha256:
        with output.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != sha256:
                raise ValueError(f"SHA-256 не совпадает для {output.name}.")


def apt(*args, **kwargs):
    return run("apt-get", "-o", "Acquire::Retries=2", *args,
               env={"DEBIAN_FRONTEND": "noninteractive"}, **kwargs)


def install_docker(suite, temporary):
    docker = Path("/usr/bin/docker")
    if docker.exists():
        version = capture(docker, "--host", DOCKER_SOCKET, "version", "--format", "{{.Server.Version}}")
        if not version.startswith("29."):
            raise ValueError("Установленный Docker должен быть версии 29.x.")
        run(docker, "--host", DOCKER_SOCKET, "compose", "version")
        run(docker, "--host", DOCKER_SOCKET, "buildx", "version")
        return
    # apt will refuse to remove pre-existing conflicting host packages.
    candidate = temporary / "docker.asc"
    download("https://download.docker.com/linux/ubuntu/gpg", candidate)
    gpg_home = temporary / "gnupg"
    gpg_home.mkdir(mode=0o700)
    result = capture("gpg", "--batch", "--homedir", gpg_home, "--with-colons",
                     "--show-keys", candidate)
    lines = result.splitlines()
    primary_keys = [line.split(":")[9] for previous, line in zip(lines, lines[1:])
                    if previous.startswith("pub:") and line.startswith("fpr:")]
    if primary_keys != [DOCKER_KEY]:
        raise ValueError("Отпечаток ключа Docker APT не совпадает.")
    DOCKER_APT_KEY.parent.mkdir(mode=0o755, exist_ok=True)
    source = ("Types: deb\nURIs: https://download.docker.com/linux/ubuntu\n"
              f"Suites: {suite}\nComponents: stable\nArchitectures: amd64\nSigned-By: {DOCKER_APT_KEY}\n")
    for path, content in ((DOCKER_APT_KEY, candidate.read_bytes()), (DOCKER_APT_SOURCE, source.encode())):
        try:
            with path.open("xb") as stream:
                stream.write(content)
        except FileExistsError:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or path.read_bytes() != content):
                raise ValueError(f"Найдена другая конфигурация Docker: {path}.") from None
    apt("update")
    versions = []
    for name in ("docker-ce", "docker-ce-cli"):
        rows = [line.split("|") for line in capture("apt-cache", "madison", name).splitlines()]
        version = next((row[1].strip() for row in rows if len(row) == 3
                        and row[2].strip().startswith("https://download.docker.com/linux/ubuntu")
                        and re.match(r"(?:[0-9]+:)?29\.", row[1].strip())), None)
        if not version:
            raise ValueError(f"Пакет {name} версии 29.x недоступен.")
        versions.append(f"{name}={version}")
    apt("install", "-y", "--no-remove", "--no-install-recommends", *versions,
        "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")
    run("systemctl", "enable", "--now", "docker.service")


def materialize_checkout(bundle, source, revision, **options):
    run("git", "init", "-q", source, **options)
    run("git", "-C", source, "fetch", "-q", bundle, "HEAD", **options)
    run("git", "-C", source, "checkout", "-q", "--detach", "FETCH_HEAD", **options)
    if capture("git", "-C", source, "rev-parse", "HEAD", **options) != revision:
        raise ValueError("Ревизия checkout изменилась во время установки.")


def build_identity():
    try:
        user = pwd.getpwnam(BUILD_USER)
    except KeyError:
        run("useradd", "--system", "--no-create-home", "--user-group", "--home-dir", "/nonexistent",
            "--shell", "/usr/sbin/nologin", BUILD_USER)
        user = pwd.getpwnam(BUILD_USER)
    if not (0 < user.pw_uid < 1000 and 0 < user.pw_gid < 1000
            and user.pw_dir == "/nonexistent" and user.pw_shell == "/usr/sbin/nologin"):
        raise ValueError(f"Найдена несовместимая учётная запись {BUILD_USER}.")
    return user


def build_python(work, identity, env):
    archive = work.parent / PYTHON_ARCHIVE
    download(f"https://www.python.org/ftp/python/{PYTHON_VERSION}/{PYTHON_ARCHIVE}", archive, PYTHON_SHA256)
    settings = {"identity": identity, "env": env}
    run("tar", "-xJf", archive, cwd=work, **settings)
    source = work / f"Python-{PYTHON_VERSION}"
    run("./configure", f"--prefix={PYTHON.parent.parent}", cwd=source, **settings)
    run("make", "-j", str(python_build_jobs(os.cpu_count(), memory_kib())), cwd=source, **settings)
    destination = work / "python-install"
    run("make", "install", f"DESTDIR={destination}", cwd=source, **settings)
    shutil.copytree(destination / PYTHON.parent.parent.relative_to("/"), PYTHON.parent.parent, symlinks=True)
    run(PYTHON, "-I", "-c", "import compression.zstd, sqlite3, ssl, sys; assert sys.version_info[:3] == (3,15,2); "
        "assert sqlite3.sqlite_version_info >= (3,45)")


def build_release(source, revision, work, identity, env):
    settings = {"identity": identity, "env": env}
    age_archive = work / "age.tar.gz"
    run(PYTHON, source / "tools/fetch_age.py", "--output", age_archive, **settings)
    run("tar", "-xzf", age_archive, "age/age", cwd=work, **settings)
    venv = work / "builder"
    run(PYTHON, "-m", "venv", venv, **settings)
    builder = venv / "bin/python"
    run(builder, "-m", "pip", "install", "--only-binary=:all:", "--require-hashes",
        "-r", source / "deploy/requirements-wheels.lock", **settings)
    key = work / "signer.seed"
    raw_public = work / "signer.pub"
    run(builder, "-c", "import os, pathlib, sys; from nacl.signing import SigningKey; "
        "os.umask(0o077); key=SigningKey.generate(); pathlib.Path(sys.argv[1]).write_bytes(bytes(key)); "
        "pathlib.Path(sys.argv[2]).write_bytes(bytes(key.verify_key))", key, raw_public, **settings)
    bundle = work / "bundle"
    run(builder, source / "deploy/build_bundle.py", "--output", bundle, "--signing-key", key,
        "--python-image", PYTHON_IMAGE, "--age-tool", work / "age/age", **settings)
    key.unlink()
    if json.loads((bundle / "manifest.json").read_bytes())["source_commit"] != revision:
        raise ValueError("Ревизия сборки Controller отличается от исходного checkout.")
    trust = work.parent / "release.pub"
    trust.write_bytes(raw_public.read_bytes())
    return bundle, trust


def build_web(source, work, identity, env):
    archive = work.parent / NODE_ARCHIVE
    download(f"https://nodejs.org/dist/v{NODE_VERSION}/{NODE_ARCHIVE}", archive, NODE_SHA256)
    run("tar", "-xJf", archive, cwd=work, identity=identity, env=env)
    node_bin = work / NODE_ARCHIVE.removesuffix(".tar.xz") / "bin"
    options = {"cwd": source / "web", "identity": identity, "env": {**env, "PATH": f"{node_bin}:{SYSTEM_ENV['PATH']}"}}
    run("npm", "ci", "--engine-strict", "--ignore-scripts", "--no-audit", "--no-fund", **options)
    run("npm", "run", "build", **options)
    dist = source / "web/dist"
    if dist.is_symlink() or not (dist / "index.html").is_file() or any(
            not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1))
            for info in (path.lstat() for path in dist.rglob("*"))):
        raise ValueError("Сборка WebUI не содержит допустимое дерево статических файлов.")
    shutil.copytree(dist, TOOLS / "web")


def prepare_web(temporary):
    apt("download", "caddy", cwd=temporary)
    package, = temporary.glob("caddy_*.deb")
    extracted = temporary / "caddy-package"
    run("dpkg-deb", "--extract", package, extracted)
    shutil.copyfile(extracted / "usr/bin/caddy", TOOLS / "caddy")
    (TOOLS / "caddy").chmod(0o755)
    for filename in ("web-ca.pem", "web.pem"):
        (TOOLS / filename).touch(mode=0o644, exist_ok=False)
    key = TOOLS / "web.key"
    key.touch(mode=0o600, exist_ok=False)
    ca_key = temporary / "web-ca.key"
    ca = TOOLS / "web-ca.pem"
    csr = temporary / "web.csr"
    extension = temporary / "web.ext"
    extension.write_text("basicConstraints=critical,CA:FALSE\n"
                         "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                         "subjectAltName=IP:127.0.0.1\n")
    run("openssl", "req", "-x509", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-noenc", "-days", "397", "-subj", "/CN=HostOrbit local HTTPS",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "nameConstraints=critical,permitted;IP:127.0.0.1/255.255.255.255",
        "-keyout", ca_key, "-out", ca)
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-noenc", "-subj", "/CN=127.0.0.1", "-keyout", key, "-out", csr)
    run("openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
        "-days", "397", "-extfile", extension, "-out", TOOLS / "web.pem")
    ca_key.unlink()
    (TOOLS / "Caddyfile").write_text(f"""{{
    admin off
    auto_https disable_redirects
    servers {{
        protocols h1 h2
    }}
}}
{ORIGIN} {{
    bind 127.0.0.1
    tls {TOOLS}/web.pem {{$CREDENTIALS_DIRECTORY}}/web.key
    handle /api/* {{
        reverse_proxy 127.0.0.1:{API_PORT}
    }}
    handle /healthz {{
        reverse_proxy 127.0.0.1:{API_PORT}
    }}
    handle {{
        root * {TOOLS}/web
        header {{
            Content-Security-Policy "frame-ancestors 'none'"
            X-Content-Type-Options "nosniff"
            Referrer-Policy "no-referrer"
        }}
        file_server
    }}
}}
""")
    run(TOOLS / "caddy", "validate", "--config", TOOLS / "Caddyfile",
        env={"CREDENTIALS_DIRECTORY": str(TOOLS), "HOME": str(temporary)})


def start_web():
    with WEB_UNIT.open("x") as unit:
        unit.write(f"""[Unit]
Description=HostOrbit loopback WebUI and HTTPS proxy
Requires=hostorbit-compose.service
After=hostorbit-compose.service

[Service]
DynamicUser=yes
StateDirectory=hostorbit-web
StateDirectoryMode=0700
Environment=XDG_DATA_HOME=/var/lib/hostorbit-web
Environment=XDG_CONFIG_HOME=/var/lib/hostorbit-web
LoadCredential=web.key:{TOOLS}/web.key
ExecStart={TOOLS}/caddy run --config {TOOLS}/Caddyfile
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
""")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", WEB_UNIT.name)
    for path in ("/", "/healthz"):
        run("curl", "--disable", "--fail", "--silent", "--show-error", "--noproxy", "*",
            "--retry", "5", "--retry-connrefused", "--max-time", "5", "--cacert", TOOLS / "web-ca.pem",
            "--output", "/dev/null", ORIGIN + path)


def install(owner, targets, suite):
    root = Path(__file__).resolve().parents[1]
    checkout_owner = pwd.getpwuid(root.stat().st_uid)
    checkout = {"cwd": root, "identity": checkout_owner, "env": {"HOME": checkout_owner.pw_dir}}
    git = ("git", "-c", f"safe.directory={root}", "-C", root)
    revision = capture(*git, "rev-parse", "HEAD", **checkout)
    if capture(*git, "status", "--porcelain", "--untracked-files=no", **checkout):
        raise ValueError("Запустите установку из чистого зафиксированного checkout.")
    with tempfile.TemporaryDirectory(prefix="hostorbit-bootstrap-", dir="/var/tmp") as location:
        temporary = Path(location)
        temporary.chmod(0o711)
        private = temporary / "private"
        private.mkdir(mode=0o700)
        options = []
        if targets:
            approved = private / "targets.json"
            approved.write_bytes(targets.read_bytes())
            options = ["--targets", approved, "--web-enrollment"]
        stage(f"HostOrbit development · {revision}")
        apt("update")
        apt("install", "-y", "--no-remove", "--no-install-recommends", "curl", "ca-certificates", "gnupg",
            "openssl", "xz-utils", "build-essential", "pkg-config", "libssl-dev", "zlib1g-dev",
            "libsqlite3-dev", "libffi-dev", "libbz2-dev", "liblzma-dev", "libzstd-dev")
        install_docker(suite, private)
        identity = build_identity()
        work = temporary / "build"
        work.mkdir(mode=0o700)
        os.chown(work, identity.pw_uid, identity.pw_gid)
        env = {"HOME": str(work), "PIP_CONFIG_FILE": "/dev/null", "PIP_INDEX_URL": "https://pypi.org/simple",
               "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1"}
        checkout_bundle = temporary / "source.bundle"
        with checkout_bundle.open("wb") as stream:
            run(*git, "bundle", "create", "-", "HEAD", output=stream, **checkout)
        checkout_bundle.chmod(0o644)
        source = work / "source"
        materialize_checkout(checkout_bundle, source, revision, identity=identity, env=env)
        trusted_archive = private / "installer.tar"
        with trusted_archive.open("wb") as stream:
            run(*git, "archive", "--format=tar", revision, "deploy/artifact.py", "deploy/installer.py",
                output=stream, **checkout)
        with tarfile.open(trusted_archive) as archive:
            archive.extractall(private, filter="data")
        TOOLS.mkdir(mode=0o755)
        try:
            stage("Сборка Python 3.15 и подписанного комплекта Controller.")
            build_python(work, identity, env)
            bundle, trust = build_release(source, revision, work, identity, env)
            stage("Сборка WebUI и проверка локального HTTPS.")
            build_web(source, work, identity, env)
            prepare_web(private)
            run(PYTHON, private / "deploy/installer.py", "install", "--bundle", bundle, "--trust-key", trust,
                "--development", "--origin", ORIGIN, "--port", str(API_PORT), "--docker-host", DOCKER_SOCKET, *options)
            start_web()
        finally:
            if not APP.exists():
                shutil.rmtree(TOOLS)
    admin = APP / "admin"
    print(f"WebUI {ORIGIN}\n"
          f"SSH-туннель: ssh -N -L 127.0.0.1:{WEB_PORT}:127.0.0.1:{WEB_PORT} <пользователь>@<VPS>\n"
          f"Публичный CA для доверия в браузере: {TOOLS}/web-ca.pem", flush=True)
    print(f"Создание Owner на VPS: sudo {admin} create-owner --username {owner}", flush=True)
    if sys.stdin.isatty() and sys.stderr.isatty():
        stage("Пароль Owner: от 14 до 128 символов.")
        run(admin, "create-owner", "--username", owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="admin", help="Имя начального Owner (по умолчанию admin)")
    parser.add_argument("--targets", type=lambda value: Path(value).resolve(),
                        help="Подготовленная локальная политика VPS, видимая после подтверждения отпечатка в WebUI")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{2,63}", args.owner):
        parser.error("Имя Owner должно начинаться с латинской буквы и содержать 3–64 символа.")
    if args.targets and not args.targets.is_file():
        parser.error("Файл политики VPS не найден.")
    if os.geteuid() != 0:
        parser.exit(1, "Запустите sudo ./HostOrbit/install.\n")
    os.umask(0o022)
    try:
        with open("/run/hostorbit-bootstrap.lock", "w", opener=lambda p, f: os.open(
                p, f | os.O_NOFOLLOW, 0o600)) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            install(args.owner, args.targets, platform_and_ports())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Установка остановлена: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
