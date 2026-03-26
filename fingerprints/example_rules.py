"""
示例指纹规则文件
函数规范：
- 必须实现 match(data)
- 命中返回 [type, fingerprint] 或 [[type, fingerprint], ...]
- 未命中返回 []

data 可用字段：
- data['status'] -> HTTP 状态码
- data['headers'] -> 响应头字典
- data['content'] -> 页面内容
- data['title'] -> 页面标题
- data['url'] -> 请求 URL
"""

import re


def match(data):
    content = data.get("content", "") or ""
    headers = data.get("headers", {}) or {}
    title = data.get("title", "") or ""

    hits = []

    # 关键词匹配
    if "nginx" in content.lower() or "nginx" in str(headers).lower():
        hits.append(["web-server", "nginx"])

    # 正则匹配
    if re.search(r"wordpress", content, re.IGNORECASE):
        hits.append(["cms", "wordpress"])

    # 标题关键词
    if "登录" in title or "后台" in title:
        hits.append(["portal", "login-panel"])

    return hits if hits else []
