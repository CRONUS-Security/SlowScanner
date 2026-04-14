"""
TrueNAS 指纹识别模块
在以下版本中测试通过：
- 25.10.2.1 - Goldeye
"""

import re
import bs4
from core.fingerprint import FingerprintData, FingerprintMatch


def match(data: FingerprintData) -> FingerprintMatch:
    content = data.get("content", "") or ""
    headers = data.get("headers", {}) or {}
    title = data.get("title", "") or ""

    html = bs4.BeautifulSoup(content, "html.parser")

    hits = []

    score = 0

    # 检查 /ui/ 路径
    # <base href="/ui/">
    base_tag = html.find("base", href=True)
    if base_tag and base_tag["href"].strip() == "/ui/":
        score += 1

    # 检查 body 元素
    # <body class="ix-dark">
    body_tag = html.find("body", class_=True)
    if body_tag and "ix-dark" in body_tag["class"]:
        score += 1

    if score == 2:
        return {"type": "Device", "fingerprint": "TrueNAS"}
    else:
        return {"type": "Unknown", "fingerprint": "Unknown"}
