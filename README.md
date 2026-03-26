# SlowScanner - HTTP/HTTPS 网络扫描器

一个功能强大的慢速网络扫描工具，支持大规模CIDR范围扫描和断点续传。

## 特性

- 👀 慢有时候就是优势
- 👀 而且他的指纹就是原生的 Chromium
- ✅ 支持大规模 CIDR 范围扫描（内存优化模式）
- ✅ 断点续传功能（基于 SQLite 数据库）
- ✅ SSL/TLS 证书信息提取
- ✅ 自定义指纹库（自动加载目录内规则文件）
- ✅ 灵活的配置文件系统
- ✅ 详细的扫描日志和结果分类
- ✅ 随机延迟和抖动避免检测

## 注意事项

- 请确保您有权限扫描目标网络
- 大规模扫描可能触发网络安全设备
- 建议配置适当的延迟避免过快扫描
- 使用内存优化模式处理大型 CIDR 范围

## 自定义指纹库

在 `config.yaml` 中启用并指定目录：

- `fingerprint.enable`: 是否启用指纹引擎
- `fingerprint.dir`: 指纹规则目录（默认 `./fingerprints`）

规则目录中的每个 `.py` 文件都应实现：

- `match(data)` 函数
- 命中返回：`[type, fingerprint]` 或 `[[type, fingerprint], ...]`
- 未命中返回：`[]`

程序会自动遍历并执行所有规则，多个命中会进行拼接后写入数据库字段：

- `type`
- `fingerprint`

数据库字段顺序：

`ip, port, status, type, fingerprint, title, ssl_cert, scanned_at`

## 许可证

请遵守当地法律法规，仅在授权的网络环境中使用此工具。
