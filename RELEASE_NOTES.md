# UpstreamLens 0.5.0 发布候选说明

本版本为首个 GitHub Release 候选版本。分发文件在发布前应与校验文件核对。

## 功能

- 对明确指定的单个 HTTP 或 HTTPS 目标检查 DNS、TCP、TLS 和 HTTP，记录状态与证据。
- 离线分析用户提供的 Nginx 文本错误日志，支持单文件和显式指定的多份轮转日志。
- 输出文本、JSON 和可离线查看的独立 HTML 报告。内置演示使用合成数据。
- Nginx 报告按物理日志记录计数，保留来源编号、未确认信息及筛选结果。

## 安装

需要 Python 3.11 或更新版本。取得 wheel 文件后，在虚拟环境中运行：

```text
python -m pip install upstreamlens-0.5.0-py3-none-any.whl
upstreamlens demo
```

GitHub 源码安装和 Windows、Linux 的详细命令见 README。wheel 和源码归档的 SHA256 值另见 `SHA256SUMS-0.5.0.txt`。

## 验证范围

本地使用 Windows 11、Python 3.11 验证。持续集成覆盖 Windows 与 Ubuntu 的 Python 3.11 和 3.12，并包含 Linux 独立安装检查。具体结果以本次提交对应的 GitHub Actions 运行记录为准。

## 限制与安全边界

- 仅对获授权访问的单个目标进行在线诊断，不扫描其他主机或端口。HTTP 502 无法单独证明上游地址、端口或进程状态。
- 日志分析仅支持显式指定的普通 UTF-8 文本文件，暂不支持压缩日志或自动发现。多文件内容重叠可能重复计数，日志时间缺少时区时不能确定绝对时间。
- 报告省略或隐藏查询参数、认证信息及日志中的敏感字段。HTML 为静态单文件，不加载外部资源。
- 不采集 systemd 日志，未集成 Docker，也不自动修改服务端配置。
- Nginx 单文件 JSON 模式为 2.0，多文件为 3.0。旧 1.0 日志报告可能少计相同行。
