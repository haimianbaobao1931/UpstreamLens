# UpstreamLens

UpstreamLens 对单个 HTTP 或 HTTPS 网址采集 DNS、TCP、TLS 和 HTTP 证据，帮助定位服务部署故障。报告区分实际观测、可能原因和需要服务端证据才能确认的信息。

[英文说明](README.md)

## 安装

使用 Python 3.11 或更新版本。在项目目录下运行以下 PowerShell 命令：

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\upstreamlens.exe --help
```

下面的示例假定已激活虚拟环境，也可以像上面一样直接调用虚拟环境中的可执行文件。

## 使用

```powershell
upstreamlens diagnose https://example.com
upstreamlens diagnose https://example.com --timeout 3 --format json --output report.json
upstreamlens demo
upstreamlens demo --format json
```

每个网络阶段默认限时五秒。工具按指定路径和查询参数发出 HTTP GET 请求，读取响应状态和响应头。200 至 399 标为通过，400 至 599 标为失败，其余状态标为未知。重定向只记录状态，不跟随。每项检测使用 PASS、FAIL 或 UNKNOWN。目标为 IP 地址时跳过 DNS，纯 HTTP 跳过 TLS，跳过的检测标为 UNKNOWN。

`--output` 另存为新的 UTF-8 JSON 文件，标准输出仍使用所选格式。已有文件会被保留。报告目标只记录协议、主机和显式指定的端口，省略路径、查询、片段、请求及响应头、原始异常。诊断有失败项时退出码为 1，参数或文件写入错误为 2，其余为 0。离线演示成功显示时返回 0。

## 限制和安全

- 仅对获授权访问的目标使用。工具直接连接指定主机及端口，只尝试该主机的解析地址。工具不扫描、不使用环境变量中的 HTTP 代理、不跟随重定向、不修改系统配置。
- 拒绝含用户名或密码的网址，请求不会附带认证头或会话凭据。查询参数会按输入发送给目标，请避免在其中包含秘密。
- HTTPS 使用标准库校验证书链和主机名。HTTP 诊断使用 HTTP/1.1。
- HTTP 502 是响应观测。确认实际后端地址、端口和进程状态需要服务端证据。
- 演示完全离线，使用模拟数据。当前版本暂不采集 Nginx 或 systemd 日志，也未集成 Docker。

## 测试和打包

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build
```

测试使用替身和本机回环套接字。构建在 `dist/` 生成安装包和源码归档。
