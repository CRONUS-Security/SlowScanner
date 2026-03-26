"""
自定义指纹引擎
支持动态加载指纹库目录下的 .py 文件并执行匹配逻辑
"""

import importlib.util
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple


class FingerprintEngine:
    """自定义指纹规则引擎"""

    def __init__(self, fingerprint_dir: str, logger: logging.Logger, enabled: bool = True):
        self.fingerprint_dir = Path(fingerprint_dir)
        self.logger = logger
        self.enabled = enabled
        self._plugins: List[Tuple[str, Any]] = []

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
                            f"Skip fingerprint plugin {plugin_file.name}: missing callable match(data)"
                        )
                except Exception as e:
                    self.logger.warning(f"Failed to load fingerprint plugin {plugin_file.name}: {e}")

            self.logger.info(f"Fingerprint plugins loaded: {len(self._plugins)}")
        except Exception as e:
            self.logger.error(f"Failed to initialize fingerprint directory: {e}")

    def _normalize_result(self, result: Any) -> List[Tuple[str, str]]:
        """将插件返回值标准化为 [(type, fingerprint), ...]"""
        if not result:
            return []

        normalized: List[Tuple[str, str]] = []

        # 单条: [type, fingerprint] 或 (type, fingerprint)
        if isinstance(result, (list, tuple)) and len(result) == 2 and not isinstance(result[0], (list, tuple)):
            fp_type = str(result[0]).strip()
            fp_value = str(result[1]).strip()
            if fp_type and fp_value:
                normalized.append((fp_type, fp_value))
            return normalized

        # 多条: [[type, fingerprint], ...] 或 [(type, fingerprint), ...]
        if isinstance(result, list):
            for item in result:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    fp_type = str(item[0]).strip()
                    fp_value = str(item[1]).strip()
                    if fp_type and fp_value:
                        normalized.append((fp_type, fp_value))

        return normalized

    def identify(self, scan_result: Dict[str, Any]) -> Tuple[str, str]:
        """执行所有指纹插件并返回拼接后的 (type, fingerprint)"""
        if not self.enabled or not self._plugins:
            return "", ""

        payload = {
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

        matches: List[Tuple[str, str]] = []
        seen = set()

        for plugin_name, matcher in self._plugins:
            try:
                plugin_result = matcher(payload)
                normalized = self._normalize_result(plugin_result)
                for pair in normalized:
                    if pair not in seen:
                        seen.add(pair)
                        matches.append(pair)
            except Exception as e:
                self.logger.warning(f"Fingerprint plugin {plugin_name} execution failed: {e}")

        if not matches:
            return "", ""

        types = " | ".join([m[0] for m in matches])
        fingerprints = " | ".join([m[1] for m in matches])
        return types, fingerprints
