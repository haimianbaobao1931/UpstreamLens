import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_AUTHORITY = re.compile(r"(\[[^\[\]]+\]|[^:\[\]]+)(?::([0-9]+))?")


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    authority: str
    request_target: str

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"


def parse_target(value: str) -> Target:
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise InvalidTarget("网址含有空格或控制字符，请使用百分号编码。")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise InvalidTarget("网址格式无效。") from None
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise InvalidTarget("请输入包含主机名的完整 HTTP 或 HTTPS 网址。")
    if "@" in parts.netloc:
        raise InvalidTarget("网址不得包含用户名或密码。")

    authority_match = _AUTHORITY.fullmatch(parts.netloc)
    if authority_match is None:
        raise InvalidTarget("主机或端口格式无效。")
    raw_host, raw_port = authority_match.groups()
    default_port = 443 if parts.scheme == "https" else 80
    try:
        port = int(raw_port) if raw_port is not None else default_port
    except ValueError:
        raise InvalidTarget("端口必须在 1 至 65535 之间。") from None
    if not 1 <= port <= 65535:
        raise InvalidTarget("端口必须在 1 至 65535 之间。")

    try:
        if raw_host.startswith("["):
            if "%" in raw_host:
                raise ValueError
            host = str(ipaddress.IPv6Address(raw_host[1:-1]))
            authority = f"[{host}]"
        else:
            host = raw_host.encode("idna").decode("ascii").lower()
            dns_name = host.removesuffix(".")
            if len(dns_name) > 253 or not all(
                _DNS_LABEL.fullmatch(label) for label in dns_name.split(".")
            ):
                raise ValueError
            authority = host
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if "?" in value.split("#", 1)[0]:
            path += "?" + quote(parts.query, safe="/?%:@!$&'()*+,;=-._~[]")
    except (ValueError, UnicodeError):
        raise InvalidTarget("主机名或请求路径无效。") from None

    if raw_port is not None:
        authority += f":{port}"
    return Target(parts.scheme, host, port, authority, path)
