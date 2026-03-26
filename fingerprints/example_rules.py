"""
示例指纹规则文件
函数规范：
- 必须实现 match(data)
- 命中返回 {"type": "...", "fingerprint": "..."}
- 未命中返回 {"type": "Unknown", "fingerprint": "Unknown"}

data 可用字段：
- data['status'] -> HTTP 状态码
- data['headers'] -> 响应头字典
- data['content'] -> 页面内容
- data['title'] -> 页面标题
- data['url'] -> 请求 URL
"""

import re
from core.fingerprint import FingerprintData, FingerprintMatch


def match_example(data: FingerprintData) -> FingerprintMatch:
    content = data.get("content", "") or ""
    headers = data.get("headers", {}) or {}
    title = data.get("title", "") or ""

    # 关键词匹配
    if "nginx" in content.lower() or "nginx" in str(headers).lower():
        return {"type": "Web Server", "fingerprint": "nginx"}

    # 正则匹配
    if re.search(r"wordpress", content, re.IGNORECASE):
        return {"type": "CMS", "fingerprint": "wordpress"}

    # 标题关键词
    if "登录" in title or "后台" in title:
        return {"type": "Service", "fingerprint": "login-panel"}

    return {"type": "Unknown", "fingerprint": "Unknown"}
    
