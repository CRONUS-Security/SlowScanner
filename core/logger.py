"""
日志管理模块
"""
import logging
from rich.logging import RichHandler
from .config import ScanConfig


class LoggerManager:
    """日志管理器，负责配置和管理各种日志器"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.main_logger: logging.Logger
        self.success_logger: logging.Logger
        self.failure_logger: logging.Logger
        self._setup_loggers()

    def _setup_loggers(self):
        """设置所有日志器"""
        # 主日志器（控制台输出）
        logging.basicConfig(
            level=logging.DEBUG if self.config.verbose_logging else logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True)],
        )
        self.main_logger = logging.getLogger("rich")

        # 成功日志器（文件输出）
        self.success_logger = logging.getLogger("success")
        self.success_logger.setLevel(logging.INFO)
        success_handler = logging.FileHandler(self.config.success_log_file)
        success_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self.success_logger.addHandler(success_handler)
        self.success_logger.propagate = False

        # 失败日志器（文件输出）
        self.failure_logger = logging.getLogger("failure")
        self.failure_logger.setLevel(logging.INFO)
        failure_handler = logging.FileHandler(self.config.failure_log_file)
        failure_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self.failure_logger.addHandler(failure_handler)
        self.failure_logger.propagate = False
