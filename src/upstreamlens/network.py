import http.client
import io
import ipaddress
import math
import socket
import ssl
import time
from dataclasses import dataclass
from queue import Empty, Queue
from threading import Thread
from typing import Protocol

from .models import Evidence
from .target import Target

SECONDS_PER_DAY = 86_400


def certificate_days_remaining(not_after: str, *, now: float | None = None) -> int | None:
    """返回证书剩余有效天数，无法解析证书时间时返回 None。

    证书到期时间使用 UTC，剩余天数向下取整，已过期证书返回负数。
    """
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except (TypeError, ValueError):
        return None
    return math.floor((expires - (time.time() if now is None else now)) / SECONDS_PER_DAY)


@dataclass(frozen=True)
class Address:
    family: socket.AddressFamily
    endpoint: tuple[str, int] | tuple[str, int, int, int]

    @property
    def ip(self) -> str:
        return self.endpoint[0]


def literal_address(target: Target) -> Address | None:
    try:
        ip = ipaddress.ip_address(target.host)
    except ValueError:
        return None
    if ip.version == 6:
        return Address(socket.AF_INET6, (str(ip), target.port, 0, 0))
    return Address(socket.AF_INET, (str(ip), target.port))


class Probe(Protocol):
    def resolve(self, target: Target, timeout: float) -> list[Address]: ...
    def connect(self, addresses: list[Address], timeout: float) -> tuple[socket.socket, str]: ...
    def tls(
        self, connection: socket.socket, target: Target, timeout: float
    ) -> tuple[socket.socket, Evidence]: ...
    def http(self, connection: socket.socket, target: Target, timeout: float) -> int: ...


def _remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError
    return seconds


class _DeadlineReader(io.RawIOBase):
    """为标准库响应解析器提供受总时限约束的字节流。"""

    def __init__(self, connection: socket.socket, deadline: float):
        super().__init__()
        self.connection = connection
        self.deadline = deadline

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(self)

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self.connection.settimeout(_remaining(self.deadline))
        return self.connection.recv_into(buffer)


class SocketProbe:
    def resolve(self, target: Target, timeout: float) -> list[Address]:
        result: Queue[list[Address] | OSError] = Queue(maxsize=1)

        def lookup() -> None:
            try:
                records = socket.getaddrinfo(
                    target.host, target.port, type=socket.SOCK_STREAM
                )
                addresses = dict.fromkeys(
                    Address(family, endpoint)
                    for family, _, _, _, endpoint in records
                    if family in (socket.AF_INET, socket.AF_INET6)
                )
                result.put(list(addresses))
            except OSError as error:
                result.put(error)

        # 系统解析器没有调用级超时，守护线程允许主流程按时返回。
        deadline = time.monotonic() + timeout
        Thread(target=lookup, daemon=True).start()
        try:
            addresses = result.get(timeout=_remaining(deadline))
        except Empty:
            raise TimeoutError from None
        if isinstance(addresses, OSError):
            raise addresses
        if not addresses:
            raise socket.gaierror("没有可用的 IPv4 或 IPv6 地址")
        return addresses

    def connect(self, addresses: list[Address], timeout: float) -> tuple[socket.socket, str]:
        deadline = time.monotonic() + timeout
        last_error: OSError | None = None
        for index, address in enumerate(addresses):
            # 给同一主机的剩余地址留出连接时间。
            attempt_timeout = _remaining(deadline) / (len(addresses) - index)
            try:
                connection = socket.socket(address.family, socket.SOCK_STREAM)
            except OSError as error:
                last_error = error
                continue
            try:
                connection.settimeout(attempt_timeout)
                connection.connect(address.endpoint)
            except OSError as error:
                connection.close()
                last_error = error
            else:
                return connection, address.ip
        if last_error is not None:
            raise last_error
        raise OSError("没有可连接的地址")

    def tls(
        self, connection: socket.socket, target: Target, timeout: float
    ) -> tuple[socket.socket, Evidence]:
        deadline = time.monotonic() + timeout
        context = ssl.create_default_context()
        connection.settimeout(_remaining(deadline))
        secured = context.wrap_socket(
            connection, server_hostname=target.host.removesuffix("."),
            do_handshake_on_connect=False,
        )
        try:
            secured.do_handshake()
            certificate = secured.getpeercert()
            evidence: Evidence = {
                "version": secured.version() or "未知",
                "certificate": "证书链、有效期和主机名校验通过",
            }
            if certificate:
                evidence["valid_from"] = str(certificate.get("notBefore", "未知"))
                evidence["valid_until"] = str(certificate.get("notAfter", "未知"))
                remaining = certificate_days_remaining(
                    str(certificate.get("notAfter", "")), now=time.time()
                )
                if remaining is not None:
                    evidence["expires_in_days"] = remaining
        except BaseException:
            secured.close()
            raise
        return secured, evidence

    def http(self, connection: socket.socket, target: Target, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        request = (
            f"GET {target.request_target} HTTP/1.1\r\n"
            f"Host: {target.authority}\r\n"
            "User-Agent: UpstreamLens/0.1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        connection.settimeout(_remaining(deadline))
        connection.sendall(request)
        with http.client.HTTPResponse(_DeadlineReader(connection, deadline)) as response:
            response.begin()
            return response.status
