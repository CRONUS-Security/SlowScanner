"""
扫描配置模块
"""
from pathlib import Path
from dataclasses import dataclass
from typing import Literal


@dataclass
class ScanConfig:
    """扫描配置类，集中管理所有配置参数"""
    # Local Network CIDR: 172.16.0.0/12 192.168.0.0/16 10.0.0.0/8
    cidr_range: str = "10.0.0.0/8"
    protocol: str = "http"
    port: int = 80
    base_delay: float = 0
    jitter_min: float = 0
    jitter_max: float = 0
    timeout: float = 3
    wait_strategy: Literal["commit", "domcontentloaded", "load", "networkidle"] = (
        "domcontentloaded"  # 页面等待策略
    )
    content_wait_timeout: int = 2000  # 内容等待超时时间(毫秒)
    verbose_logging: bool = True  # 是否启用详细日志（包括预期的失败）

    def __post_init__(self):
        """初始化时计算目录路径并创建必要的目录"""
        self.output_dir = f"./{self.cidr_range.replace('/', '_')}_{self.port}"
        self.html_responses_dir = f"{self.output_dir}/html_responses"
        self.raw_responses_dir = f"{self.output_dir}/raw_responses"
        self.ssl_certificates_dir = f"{self.output_dir}/ssl_certificates"
        self.log_dir = f"{self.output_dir}/logs"
        self.result_dir = f"{self.output_dir}/results"

        # 日志文件路径
        self.success_log_file = f"{self.log_dir}/success.log"
        self.failure_log_file = f"{self.log_dir}/failure.log"

        # 结果文件路径 - 按响应类型分类
        self.response_file = f"{self.result_dir}/response.txt"  # 有响应(任何状态码)
        self.connection_refused_file = (
            f"{self.result_dir}/connection_refused.txt"  # 连接被拒绝
        )
        self.timeout_file = f"{self.result_dir}/timeout.txt"  # 超时
        self.other_errors_file = f"{self.result_dir}/other_errors.txt"  # 其他错误

        # 数据库文件路径 - 使用SQLite替代CSV
        self.database_file = f"{self.output_dir}/scan_progress.db"

        # 立即创建必要的目录
        self._create_directories()

    def _create_directories(self):
        """创建所需的目录结构"""
        directories = [
            self.output_dir,
            self.html_responses_dir,
            self.raw_responses_dir,
            self.ssl_certificates_dir,
            self.log_dir,
            self.result_dir,
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @classmethod
    def create_fast_scan_config(cls, cidr_range: str, port: int = 80) -> "ScanConfig":
        """创建快速扫描配置 - 适用于需要快速获取基本信息的场景"""
        return cls(
            cidr_range=cidr_range,
            port=port,
            base_delay=1.0,
            jitter_min=0.0,
            jitter_max=2.0,
            timeout=3,
            wait_strategy="commit",
            content_wait_timeout=1000,
            verbose_logging=False,
        )

    @classmethod
    def create_stable_scan_config(cls, cidr_range: str, port: int = 80) -> "ScanConfig":
        """创建稳定扫描配置 - 默认配置，平衡速度和稳定性"""
        return cls(
            cidr_range=cidr_range,
            port=port,
            base_delay=3.0,
            jitter_min=0.0,
            jitter_max=5.0,
            timeout=5,
            wait_strategy="domcontentloaded",
            content_wait_timeout=2000,
            verbose_logging=False,
        )

    @classmethod
    def create_thorough_scan_config(
        cls, cidr_range: str, port: int = 80
    ) -> "ScanConfig":
        """创建彻底扫描配置 - 适用于需要完整页面内容的场景"""
        return cls(
            cidr_range=cidr_range,
            port=port,
            base_delay=5.0,
            jitter_min=2.0,
            jitter_max=8.0,
            timeout=10,
            wait_strategy="load",
            content_wait_timeout=5000,
            verbose_logging=True,
        )
