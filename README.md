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
upstreamlens analyze-nginx examples/nginx-error.log
upstreamlens analyze-nginx examples/nginx-error.log --host gateway.example --request-path /api/health --format json --output nginx-report.json
```

The file `examples/nginx-error.log` contains simulated test data with fictional domains and documentation IP addresses. `analyze-nginx` reads the explicitly supplied local UTF-8 Nginx error log offline. It recognizes connection refusal, upstream timeouts, prematurely closed upstream connections, and no live upstreams. A successful analysis exits with 0. Invalid input or an output error exits with 2.

The optional host filter matches the logged request `host` field exactly, ignoring hostname case, a trailing dot, and a logged port. The path filter compares the logged request path exactly after removing its query. Events missing a field required by a filter are reported as unconfirmed. Explicit mismatches are counted separately. The server name alone does not establish the request host. Report fault counts cover matching events; valid event counts also include unmatched and unconfirmed events.

The report contains schema version `1.0`, counts, bounded representative evidence, confidence rationale, possible causes, unconfirmed facts, and suggestions. Request paths, server names, upstream hosts, credentials, query strings, IP addresses, and raw lines are hidden. An upstream HTTP scheme and port may be shown. Log timestamps retain their original text and an unknown timezone. Identical recognized lines are deduplicated, which can also combine distinct events that have identical log lines.

Input is limited to a regular file of 10 MiB, 100,000 lines, and 64 KiB per line. Empty files, invalid UTF-8, and exceeded limits are errors. The output path must be new, including when it refers to the input file.

The default timeout is five seconds per network phase. The tool runs an HTTP GET against the supplied path and query and reads the response status and headers. Statuses 200–399 pass the HTTP check. Statuses 400–599 fail it. Other statuses are reported as unknown. Redirects are recorded and never followed. Reports show PASS, FAIL, or UNKNOWN for each check. An IP literal skips DNS, and plain HTTP skips TLS. Skipped checks are marked UNKNOWN.

`--output` writes a new UTF-8 JSON file and preserves the selected display format on standard output. Existing files are preserved. The report target contains the origin only. Reports omit the request path, query, fragment, headers, and raw errors. The diagnostic command exits with 1 if any check fails, 2 for invalid arguments or output errors, and 0 otherwise. The offline demo exits with 0 on successful display.

## Limits and safety

- Only use the tool against targets you are authorized to access. It connects directly to the specified host and port, using resolved addresses for that host. It does not scan, use HTTP proxy environment settings, follow redirects, or change system configuration.
- URLs with embedded credentials are rejected. No authentication headers or cookies are sent. A query you supply is transmitted to the target, so avoid including secrets.
- HTTPS uses standard-library certificate-chain and hostname verification. The diagnostic HTTP exchange uses HTTP/1.1.
- HTTP 502 is an observed response. The actual upstream address, port, and process status require server-side evidence.
- The demo is fully offline and uses simulated data. Nginx analysis reads only the file supplied by the user. This release does not collect systemd logs or integrate with Docker.

## Test and build

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build
```

Tests use mocks and local loopback sockets. Building produces a wheel and a source archive under `dist/`.

## Continuous integration

The [GitHub Actions workflow](.github/workflows/ci.yml) runs on pushes and pull requests. Once the workflow is on the default branch, it can also be run manually from the Actions tab. The matrix covers Windows and Ubuntu with Python 3.11 and 3.12. Each job installs `.[dev]`, runs `pytest -q`, and checks the CLI help and offline demo. The Ubuntu job on Python 3.12 also builds both distribution files.

The tests use mocks and loopback sockets and require no external diagnostic target or private configuration. The workflow uses read-only repository contents permissions and keeps builds on the runner without uploading or publishing them.

Local validation was performed on Windows 11 with PowerShell 7.6 and Python 3.11.4. GitHub Actions has passed the Windows and Ubuntu matrix with Python 3.11 and 3.12, including the Ubuntu Python 3.12 distribution build.
