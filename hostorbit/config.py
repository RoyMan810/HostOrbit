from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    database: Path
    public_origin: str
    trusted_proxies: tuple[str, ...] = ()
    database_owner_uid: int | None = None
    database_gid: int | None = None
    writer_directory: Path | None = None

    def __post_init__(self):
        parsed = urlsplit(self.public_origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment or parsed.netloc != parsed.netloc.lower()):
            raise ValueError("public_origin must be a canonical HTTPS origin without a path")
        # Parsing port also rejects malformed authorities.
        if parsed.port == 443:
            raise ValueError("public_origin must omit the default HTTPS port")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if (len(parsed.hostname) > 253 or not parsed.hostname.isascii()
                    or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in parsed.hostname.split("."))):
                raise ValueError("public_origin must use a canonical hostname or IP address")
        for network in self.trusted_proxies:
            ipaddress.ip_network(network, strict=True)

    @property
    def host(self):
        return urlsplit(self.public_origin).netloc

    def trusts(self, peer):
        try:
            address = ipaddress.ip_address(peer)
            return any(address in ipaddress.ip_network(net) for net in self.trusted_proxies)
        except ValueError:
            return False
