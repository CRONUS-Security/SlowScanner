"""
自定义指纹引擎
支持动态加载指纹库目录下的 .py 文件并执行匹配逻辑
"""

import importlib.util
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Literal, Optional, TypedDict, cast, get_args


FingerprintType = Literal[
    "Device",
    "Service",
    "Virtualization",
    "Windows Server",
    "Unknown",
]

ALLOWED_FINGERPRINT_TYPES = frozenset(get_args(FingerprintType))


class FingerprintData(TypedDict):
    ip: str
    port: int
    protocol: str
    url: str
    status: int
    title: str
    headers: Dict[str, Any]
    content: str
    ssl_certificate: Any
    raw: Dict[str, Any]


class FingerprintMatch(TypedDict):
    type: FingerprintType
    fingerprint: str


class FingerprintEngine:
    """自定义指纹规则引擎"""

    def __init__(self, fingerprint_dir: str, logger: logging.Logger, enabled: bool = True):
        self.fingerprint_dir = Path(fingerprint_dir)
        self.logger = logger
        self.enabled = enabled
        self._plugins: list[tuple[str, Callable[[FingerprintData], Dict[str, Any]]]] = []

        if self.enabled:
            self._load_plugins()
        else:
            self.logger.info("Custom fingerprint engine is disabled")

    def _load_plugins(self) -> None:
        """加载指纹目录中的所有 .py 插件"""
        try:
            self.fingerprint_dir.mkdir(parents=True, exist_ok=True)

            plugin_files = sorted(
                p for p in self.fingerprint_dir.glob("*.py")
                if not p.name.startswith("_")
            )

            for plugin_file in plugin_files:
                try:
                    module_name = f"fingerprint_plugin_{plugin_file.stem}"
                    spec = importlib.util.spec_from_file_location(module_name, str(plugin_file))
                    if spec is None or spec.loader is None:
                        self.logger.warning(f"Skip invalid fingerprint plugin: {plugin_file}")
                        continue

                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, "match") and callable(module.match):
                        self._plugins.append((plugin_file.name, module.match))
                        self.logger.info(f"Loaded fingerprint plugin: {plugin_file.name}")
                    else:
                        self.logger.warning(
                            f"Skip fingerprint plugin {plugin_file.name}: missing callable match(data) -> dict"
                        )
                except Exception as e:
                    self.logger.warning(f"Failed to load fingerprint plugin {plugin_file.name}: {e}")

            self.logger.info(f"Fingerprint plugins loaded: {len(self._plugins)}")
        except Exception as e:
            self.logger.error(f"Failed to initialize fingerprint directory: {e}")

    def _unknown_match(self) -> FingerprintMatch:
        return {"type": "Unknown", "fingerprint": "Unknown"}

    def _normalize_type(self, raw_type: Any) -> FingerprintType:
        type_text = str(raw_type).strip()
        if type_text in ALLOWED_FINGERPRINT_TYPES:
            return cast(FingerprintType, type_text)
        return "Unknown"

    def _normalize_result(self, result: Any) -> Optional[FingerprintMatch]:
        """将插件返回值标准化为 {'type': ..., 'fingerprint': ...}"""
        if not isinstance(result, dict):
            return None

        fp_type = self._normalize_type(result.get("type", "Unknown"))
        fp_value = str(result.get("fingerprint", "")).strip()
        if not fp_value:
            return None

        return {"type": fp_type, "fingerprint": fp_value}

    def identify(self, scan_result: Dict[str, Any]) -> FingerprintMatch:
        """执行所有指纹插件并返回首个命中的 {'type', 'fingerprint'}"""
        if not self.enabled or not self._plugins:
            return self._unknown_match()

        payload: FingerprintData = {
            "ip": scan_result.get("ip", ""),
            "port": scan_result.get("port", 0),
            "protocol": scan_result.get("protocol", ""),
            "url": scan_result.get("url", ""),
            "status": scan_result.get("status", 0),
            "title": scan_result.get("title", ""),
            "headers": scan_result.get("headers", {}),
            "content": scan_result.get("content", ""),
            "ssl_certificate": scan_result.get("ssl_certificate"),
            "raw": scan_result,
        }

        for plugin_name, matcher in self._plugins:
            try:
                plugin_result = matcher(payload)
                normalized = self._normalize_result(plugin_result)
                if normalized is None:
                    self.logger.warning(
                        f"Fingerprint plugin {plugin_name} returned invalid result; expected dict with keys: type, fingerprint"
                    )
                    continue
                if normalized["type"] != "Unknown":
                    return normalized
            except Exception as e:
                self.logger.warning(f"Fingerprint plugin {plugin_name} execution failed: {e}")

        return self._unknown_match()
