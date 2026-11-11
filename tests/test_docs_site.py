import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

from upstreamlens.demo import load_demo
from upstreamlens.html_report import render_html


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.images = []
        self.tags = []
        self.policy = ""
        self.style = ""
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "a":
            self.links.append(attrs.get("href", ""))
        if tag == "img":
            self.images.append(attrs.get("src", ""))
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.policy = attrs["content"]
        if tag == "style":
            self.in_style = True

    def handle_data(self, data):
        if self.in_style:
            self.style += data

    def handle_endtag(self, tag):
        if tag == "style":
            self.in_style = False


def parse(path):
    parser = Page()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def test_homepage_links_work_under_pages_subpath():
    page = parse(DOCS / "index.html")
    assert "demo.html" in page.links
    assert "https://github.com/haimianbaobao1931/UpstreamLens" in page.links
    assert page.images == ["report-preview.png"]
    base = "https://example.invalid/UpstreamLens/"
    assert urljoin(base, "demo.html") == base + "demo.html"
    assert urljoin(base, page.images[0]) == base + "report-preview.png"
    for target in [*page.images, *(link for link in page.links if not link.startswith(("#", "https://")))]:
        assert (DOCS / target).is_file()


def test_homepage_csp_blocks_scripts_and_external_assets():
    page = parse(DOCS / "index.html")
    assert "default-src 'none'" in page.policy
    assert "img-src 'self' data:" in page.policy
    digest = base64.b64encode(hashlib.sha256(page.style.encode("utf-8")).digest()).decode("ascii")
    assert f"'sha256-{digest}'" in page.policy
    assert "@import" not in page.style.lower() and "url(" not in page.style.lower()
    assert all(tag not in {"script", "iframe", "object", "embed"} for tag, _ in page.tags)
    assert [attrs for tag, attrs in page.tags if tag == "link"] == [{"rel": "icon", "href": "data:,"}]
    assert all(not any(name.startswith("on") for name in attrs) for _, attrs in page.tags)


def test_published_demo_matches_synthetic_report_generator():
    expected = render_html(load_demo()) + "\n"
    demo = (DOCS / "demo.html").read_text(encoding="utf-8")
    assert expected == (ROOT / "examples" / "demo-report.html").read_text(encoding="utf-8")
    # 站点仅添加内嵌空图标及对应的最小权限，不改变报告内容。
    expected = expected.replace("img-src &#x27;none&#x27;", "img-src data:", 1)
    expected = expected.replace("<title>", '<link rel="icon" href="data:,"><title>', 1)
    assert demo == expected
    assert "SIMULATED / 模拟数据" in demo
    assert "模拟网关" in demo and "502" in demo
    page = parse(DOCS / "demo.html")
    assert "img-src data:" in page.policy
    assert all(tag not in {"script", "iframe", "object", "embed"} for tag, _ in page.tags)
    assert [attrs for tag, attrs in page.tags if tag == "link"] == [{"rel": "icon", "href": "data:,"}]


def test_preview_is_png_and_homepage_explains_simulation():
    assert (DOCS / "report-preview.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    content = (DOCS / "index.html").read_text(encoding="utf-8")
    assert "查看模拟诊断报告" in content
    assert "演示使用合成数据" in content
    assert "真实服务器诊断" in content
