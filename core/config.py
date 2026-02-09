"""
扫描配置模块
"""
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Literal, Optional, Dict, Any


@dataclass
class ScanConfig:
    """扫描配置类，集中管理所有配置参数"""
    # Local Network CIDR: 172.16.0.0/12 192.168.0.0/16 10.0.0.0/8
    range_mode: str = "CIDR"  # CIDR 或 FILE
    cidr_range: str = "10.0.0.0/8"
    ip_file: str = "targets.txt"  # IP文件路径
    protocol: str = "http"
    port: int = 80
    base_delay: float = 0
    jitter_min: float = 0
    jitter_max: float = 0
    timeout: float = 3
    wait_strategy: Literal["commit", "domcontentloaded", "load", "networkidle"] = "domcontentloaded"
    content_wait_timeout: int = 2000  # 内容等待超时时间(毫秒)
    verbose_logging: bool = True  # 是否启用详细日志（包括预期的失败）
    # 代理配置
    proxy_enable: bool = False
    proxy_type: str = "http"  # http, https, socks5
    proxy_address: str = "127.0.0.1"
    proxy_port: int = 8080
    proxy_auth: bool = False
    proxy_username: str = ""
    proxy_password: str = ""
    
    @classmethod
    def from_yaml(cls, config_path: str = "config.yaml") -> "ScanConfig":
        """从YAML配置文件加载配置
        
        Args:
            config_path: 配置文件路径，默认为 config.yaml
            
        Returns:
            ScanConfig实例
        """
        config_file = Path(config_path)
        
        # 如果配置文件不存在，使用默认值并创建示例配置文件
        if not config_file.exists():
            print(f"配置文件 {config_path} 不存在，使用默认配置")
            return cls()
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            if not config_data:
                print(f"配置文件 {config_path} 为空，使用默认配置")
                return cls()
            
            # 检查是否使用预设配置
            preset = config_data.get('preset')
            if preset:
                if preset == 'fast':
                    cidr = config_data.get('scan', {}).get('cidr_range', '10.0.0.0/8')
                    port = config_data.get('scan', {}).get('port', 80)
                    return cls.create_fast_scan_config(cidr, port)
                elif preset == 'stable':
                    cidr = config_data.get('scan', {}).get('cidr_range', '10.0.0.0/8')
                    port = config_data.get('scan', {}).get('port', 80)
                    return cls.create_stable_scan_config(cidr, port)
                elif preset == 'thorough':
                    cidr = config_data.get('scan', {}).get('cidr_range', '10.0.0.0/8')
                    port = config_data.get('scan', {}).get('port', 80)
                    return cls.create_thorough_scan_config(cidr, port)
            
            # 从配置文件构建参数
            scan_config = config_data.get('scan', {})
            delay_config = config_data.get('delay', {})
            network_config = config_data.get('network', {})
            logging_config = config_data.get('logging', {})
            proxy_config = config_data.get('proxy', {})
            
            return cls(
                range_mode=scan_config.get('range_mode', 'CIDR'),
                cidr_range=scan_config.get('cidr_range', '10.0.0.0/8'),
                ip_file=scan_config.get('ip_file', 'targets.txt'),
                protocol=scan_config.get('protocol', 'http'),
                port=scan_config.get('port', 80),
                base_delay=delay_config.get('base_delay', 0.0),
                jitter_min=delay_config.get('jitter_min', 0.0),
                jitter_max=delay_config.get('jitter_max', 0.0),
                timeout=network_config.get('timeout', 3.0),
                wait_strategy=network_config.get('wait_strategy', 'domcontentloaded'),
                content_wait_timeout=network_config.get('content_wait_timeout', 2000),
                verbose_logging=logging_config.get('verbose_logging', True),
                proxy_enable=proxy_config.get('enable', False),
                proxy_type=proxy_config.get('type', 'http'),
                proxy_address=proxy_config.get('address', '127.0.0.1'),
                proxy_port=proxy_config.get('port', 8080),
                proxy_auth=proxy_config.get('auth', False),
                proxy_username=proxy_config.get('username', ''),
                proxy_password=proxy_config.get('password', ''),
            )
            
        except yaml.YAMLError as e:
            print(f"解析配置文件 {config_path} 失败: {e}")
            print("使用默认配置")
            return cls()
        except Exception as e:
            print(f"加载配置文件 {config_path} 时出错: {e}")
            print("使用默认配置")
            return cls()

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
