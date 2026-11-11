# UpstreamLens

UpstreamLens diagnoses deployment failures for a single HTTP or HTTPS URL by gathering DNS, TCP, TLS, and HTTP evidence. It separates observations, possible causes, and facts that require server-side evidence.

[简体中文](README.zh-CN.md)

## Install

Use Python 3.11 or newer. In Windows PowerShell, from the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\upstreamlens.exe --help
```

The examples below assume the virtual environment is active. You can also invoke its executable directly as shown above.

## Usage

```powershell
upstreamlens diagnose https://example.com
upstreamlens diagnose https://example.com --timeout 3 --format json --output report.json
upstreamlens demo
upstreamlens demo --format json
```

The default timeout is five seconds per network phase. The tool runs an HTTP GET against the supplied path and query and reads the response status and headers. Statuses 200–399 pass the HTTP check. Statuses 400–599 fail it. Other statuses are reported as unknown. Redirects are recorded and never followed. Reports show PASS, FAIL, or UNKNOWN for each check. An IP literal skips DNS, and plain HTTP skips TLS. Skipped checks are marked UNKNOWN.

`--output` writes a new UTF-8 JSON file and preserves the selected display format on standard output. Existing files are preserved. The report target contains the origin only. Reports omit the request path, query, fragment, headers, and raw errors. The diagnostic command exits with 1 if any check fails, 2 for invalid arguments or output errors, and 0 otherwise. The offline demo exits with 0 on successful display.

## Limits and safety

- Only use the tool against targets you are authorized to access. It connects directly to the specified host and port, using resolved addresses for that host. It does not scan, use HTTP proxy environment settings, follow redirects, or change system configuration.
- URLs with embedded credentials are rejected. No authentication headers or cookies are sent. A query you supply is transmitted to the target, so avoid including secrets.
- HTTPS uses standard-library certificate-chain and hostname verification. The diagnostic HTTP exchange uses HTTP/1.1.
- HTTP 502 is an observed response. The actual upstream address, port, and process status require server-side evidence.
- The demo is fully offline and uses simulated data. This release does not collect Nginx or systemd logs or integrate with Docker.

## Test and build

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build
```

Tests use mocks and local loopback sockets. Building produces a wheel and a source archive under `dist/`.
