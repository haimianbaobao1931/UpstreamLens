# 变更记录

## 未发布

- 建立 0.1.0 本地 Git 基线，并忽略本地环境变量文件，保留示例配置。
- 新增 GitHub Actions 持续集成，配置 Windows 和 Ubuntu 上的 Python 3.11、3.12 测试，以及 Ubuntu 上的安装包和源码归档构建。
- 已在 Windows 11、PowerShell 7.6 和 Python 3.11.4 上完成本地验证，并通过 GitHub Actions 的 Windows、Ubuntu 与 Python 3.11、3.12 四组测试及分发包构建。
- 修复终端样式控制序列导致帮助选项测试失败的问题，增加带样式输出和选项调用的回归验证。

## 0.1.0

- 新增单网址诊断，采集 DNS、TCP、TLS 和 HTTP 证据。
- 新增区分观测、推断和待确认信息的终端报告与 JSON 报告。
- 新增包含模拟网关日志的离线故障演示。
