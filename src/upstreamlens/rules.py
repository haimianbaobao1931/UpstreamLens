from .models import Report


def analyze(report: Report) -> None:
    failure = next((check for check in report.checks if check.status == "FAIL"), None)
    if failure is None:
        if report.checks[-1].status == "PASS":
            report.summary = "已收到目标的 HTTP 响应。"
            report.suggestions = ["如业务仍异常，请核对实际业务请求和应用日志。"]
        else:
            report.summary = "已连接目标，但未能确认最终 HTTP 状态。"
            report.suggestions = ["查看服务端日志，确认是否发出了最终响应。"]
        return

    if failure.name == "DNS":
        report.summary = "系统解析器未返回目标的可用地址。"
        report.possible_causes = ["目标记录缺失，或当前网络的解析器不可用。"]
        report.suggestions = ["检查目标域名记录和本机 DNS 解析器。"]
    elif failure.name == "TCP":
        report.summary = "未能与目标端口建立 TCP 连接。"
        report.possible_causes = ["目标端口未监听，连接被过滤，或网络路径不可达。"]
        report.suggestions = ["核对目标端口，并在服务端检查监听和防火墙记录。"]
    elif failure.name == "TLS":
        report.summary = "目标的 TLS 握手或证书校验失败。"
        report.possible_causes = ["证书链、有效期、主机名或 TLS 配置异常。"]
        report.suggestions = ["检查服务器证书链、域名和 TLS 配置。"]
    elif failure.evidence.get("status_code") == 502:
        report.summary = "目标返回 HTTP 502，可能与网关或代理访问上游有关。"
        report.possible_causes = ["上游不可达、协议不匹配，或上游响应无效。"]
        report.unconfirmed = ["网关类型、实际后端地址、端口和进程状态。"]
        report.suggestions = ["查看网关错误日志，核对上游地址，再检查上游监听和应用日志。"]
    elif "status_code" in failure.evidence:
        report.summary = f"目标返回 HTTP {failure.evidence['status_code']}。"
        report.suggestions = ["按状态码核对请求路径、访问权限和服务端日志。"]
    else:
        report.summary = "未收到可解析的 HTTP 响应。"
        report.possible_causes = ["服务未及时响应、连接提前关闭，或目标端口使用其他协议。"]
        report.suggestions = ["核对目标端口的协议，并检查服务端请求和错误日志。"]
