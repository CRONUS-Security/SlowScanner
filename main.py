import ipaddress
import random
import asyncio
import time
import logging
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Literal
from playwright.async_api import async_playwright
from rich.logging import RichHandler
from rich.progress import Progress
from database import HTTPScanDatabase

# pip install playwright rich pyopenssl 
# playwright install


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


class FileManager:
    """文件管理器，负责文件保存操作"""

    def __init__(self, config: ScanConfig):
        self.config = config

    def save_html_response(
        self, ip: str, protocol: str, port: int, content: str
    ) -> str:
        """保存HTML响应到文件"""
        filename = (
            f"{self.config.html_responses_dir}/{protocol}_{ip}_{port}_response.html"
        )
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        return filename

    def save_raw_response(
        self,
        ip: str,
        protocol: str,
        port: int,
        status: int,
        headers: Dict[str, Any],
        content: str,
    ) -> str:
        """保存原始响应到文件"""
        filename = f"{self.config.raw_responses_dir}/{protocol}_{ip}_{port}_status_{status}.txt"
        response_info = f"Status Code: {status}\n"
        response_info += f"Headers: {headers}\n"
        response_info += f"Content: {content[:1000]}\n"  # 限制长度
        with open(filename, "w", encoding="utf-8") as f:
            f.write(response_info)
        return filename

    def save_ssl_certificate(
        self, ip: str, port: int, cert_info: Dict[str, Any]
    ) -> str:
        """保存SSL证书信息到文件"""
        filename = f"{self.config.ssl_certificates_dir}/{ip}_{port}_certificate.txt"
        
        cert_text = "=" * 80 + "\n"
        cert_text += f"SSL Certificate Information for {ip}:{port}\n"
        cert_text += "=" * 80 + "\n\n"
        
        # 证书基本信息
        if "subject" in cert_info and cert_info["subject"]:
            cert_text += "Subject (CN):\n"
            cert_text += f"  {cert_info['subject']}\n\n"
        
        if "issuer" in cert_info and cert_info["issuer"]:
            cert_text += "Issuer:\n"
            cert_text += f"  {cert_info['issuer']}\n\n"
        
        if "subjectAltName" in cert_info and cert_info['subjectAltName']:
            cert_text += "Subject Alternative Names (SAN):\n"
            san_list = cert_info['subjectAltName']
            if isinstance(san_list, list):
                for san in san_list:
                    cert_text += f"  - {san}\n"
            else:
                cert_text += f"  {san_list}\n"
            cert_text += "\n"
        
        # 有效期信息
        if "validFrom" in cert_info and cert_info["validFrom"]:
            cert_text += f"Valid From: {cert_info['validFrom']}\n"
        
        if "validTo" in cert_info and cert_info["validTo"]:
            cert_text += f"Valid To: {cert_info['validTo']}\n\n"
        
        # 协议和密码套件信息
        if "protocol" in cert_info and cert_info["protocol"]:
            cert_text += f"Protocol: {cert_info['protocol']}\n"
        
        if "cipher" in cert_info and cert_info["cipher"]:
            cert_text += f"Cipher Suite: {cert_info['cipher']}\n"
        
        if "keyExchange" in cert_info and cert_info["keyExchange"]:
            cert_text += f"Key Exchange: {cert_info['keyExchange']}\n"
        
        if "keyExchangeGroup" in cert_info and cert_info["keyExchangeGroup"]:
            cert_text += f"Key Exchange Group: {cert_info['keyExchangeGroup']}\n"
        
        cert_text += "\n"
        
        # 证书链信息（新增）
        if "certificateChain" in cert_info and cert_info["certificateChain"]:
            cert_text += "Certificate Chain:\n"
            cert_text += "=" * 80 + "\n"
            chain = cert_info["certificateChain"]
            cert_text += f"Total certificates in chain: {len(chain)}\n\n"
            
            for idx, chain_cert in enumerate(chain):
                level = chain_cert.get("level", idx)
                # 确定证书类型
                if level == 0:
                    cert_type = "Leaf Certificate (Server Certificate)"
                elif level == len(chain) - 1:
                    cert_type = "Root Certificate"
                else:
                    cert_type = f"Intermediate Certificate #{level}"
                
                cert_text += f"[{level}] {cert_type}\n"
                cert_text += "-" * 80 + "\n"
                
                if chain_cert.get("subject"):
                    cert_text += f"  Subject: {chain_cert['subject']}\n"
                if chain_cert.get("issuer"):
                    cert_text += f"  Issuer:  {chain_cert['issuer']}\n"
                if chain_cert.get("validFrom"):
                    cert_text += f"  Valid From: {chain_cert['validFrom']}\n"
                if chain_cert.get("validTo"):
                    cert_text += f"  Valid To:   {chain_cert['validTo']}\n"
                if chain_cert.get("serialNumber"):
                    cert_text += f"  Serial Number: {chain_cert['serialNumber']}\n"
                
                cert_text += "\n"
            
            cert_text += "=" * 80 + "\n\n"
        
        # 其他详细信息
        additional_details = False
        excluded_keys = ["issuer", "subject", "subjectAltName", "validFrom", "validTo", 
                        "protocol", "cipher", "keyExchange", "keyExchangeGroup", "certificateChain"]
        
        for key, value in cert_info.items():
            if key not in excluded_keys:
                if not additional_details:
                    cert_text += "Additional Details:\n"
                    cert_text += "-" * 80 + "\n"
                    additional_details = True
                
                if value:  # 只显示非空值
                    # 格式化key的显示
                    display_key = key.replace("_", " ").title()
                    cert_text += f"{display_key}: {value}\n"
        
        if additional_details:
            cert_text += "\n"
        
        cert_text += "=" * 80 + "\n"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(cert_text)
        
        return filename

    def save_categorized_results(
        self, scan_results: Dict[str, List[str]]
    ) -> Dict[str, str]:
        """保存按类型分类的扫描结果"""
        file_map = {
            "response": self.config.response_file,
            "timeout": self.config.timeout_file,
            "connection_refused": self.config.connection_refused_file,
            "other_errors": self.config.other_errors_file,
        }

        saved_files = {}

        for category, ips in scan_results.items():
            if category in file_map and ips:  # 只保存非空的结果
                filename = file_map[category]
                with open(filename, "w") as f:
                    for ip in ips:
                        f.write(f"{ip}\n")
                saved_files[category] = filename

        return saved_files


class DelayGenerator:
    """延迟生成器，负责生成随机延迟时间"""

    def __init__(self, config: ScanConfig, logger):
        self.config = config
        self.logger = logger

    def generate_random_delay(self) -> float:
        """生成随机延迟时间：基础时间 + 随机抖动"""
        jitter = random.uniform(self.config.jitter_min, self.config.jitter_max)
        total_delay = self.config.base_delay + jitter
        self.logger.info(
            f"Sleep {self.config.base_delay} + {jitter:.2f} = {total_delay:.2f} seconds"
        )
        return total_delay


class IPGenerator:
    """IP地址生成器，负责根据CIDR生成IP列表"""

    @staticmethod
    def generate_ip_list(cidr: str) -> List[str]:
        """根据CIDR生成IP地址列表并随机打乱"""
        network = ipaddress.ip_network(cidr, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        random.shuffle(ip_list)
        return ip_list
    
    @staticmethod
    def generate_ip_stream(cidr: str):
        """根据CIDR生成IP地址流（生成器），节省内存"""
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            yield str(ip)
    
    @staticmethod
    def get_ip_count(cidr: str) -> int:
        """获取CIDR范围内的IP数量（不生成实际IP）"""
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses - 2  # 减去网络地址和广播地址


class CheckpointManager:
    """检查点管理器，负责保存和恢复扫描进度 - 使用SQLite数据库"""

    def __init__(self, config: ScanConfig, logger):
        self.config = config
        self.logger = logger
        self.db = HTTPScanDatabase(self.config.database_file, logger)

    def initialize_checkpoint(self, ip_list: List[str], port: int) -> None:
        """初始化数据库，一次性写入所有IP地址"""
        try:
            self.logger.info("Initializing database with IP list...")
            self.db.initialize_ips(ip_list, port)
            self.logger.info(f"Initialized database with {len(ip_list)} IPs")
        except Exception as e:
            self.logger.error(f"Failed to initialize checkpoint: {e}")
    
    def initialize_checkpoint_stream(self, ip_generator, port: int, batch_size: int = 10000) -> int:
        """使用生成器初始化数据库，批量写入，节省内存
        
        Args:
            ip_generator: IP地址生成器
            port: 端口号
            batch_size: 每批插入的数量
            
        Returns:
            初始化的总IP数量
        """
        try:
            self.logger.info("Initializing database with IP stream...")
            total = self.db.initialize_ips_batch(ip_generator, port, batch_size)
            self.logger.info(f"Initialized database with {total} IPs using stream")
            return total
        except Exception as e:
            self.logger.error(f"Failed to initialize checkpoint from stream: {e}")
            raise

    def load_checkpoint(self) -> Dict[str, Any]:
        """加载数据库中的所有记录"""
        try:
            records = self.db.get_all_records()
            self.logger.info(f"Loaded checkpoint with {len(records)} IPs")
            # 返回字典格式以保持兼容性
            return {record['ip']: record for record in records}
        except Exception as e:
            self.logger.error(f"Failed to load checkpoint: {e}")
            return {}

    def get_scanned_ips(self) -> set:
        """获取已扫描的IP集合"""
        return self.db.get_scanned_ips()
    
    def get_unscanned_count(self) -> int:
        """获取未扫描的IP数量"""
        return self.db.get_unscanned_count()
    
    def get_random_unscanned_ips(self, limit: int = 100) -> List[Dict[str, Any]]:
        """随机获取未扫描的IP"""
        return self.db.get_random_unscanned_ips(limit)

    def mark_ip_scanned(self, ip: str, port: int, status: str = "", title: str = "", ssl_cert: str = "", fingerprint: str = "") -> None:
        """标记IP为已扫描状态"""
        try:
            self.db.mark_ip_scanned(ip, port, status, title, ssl_cert, fingerprint)
            self.logger.debug(f"Marked {ip}:{port} as scanned")
        except Exception as e:
            self.logger.error(f"Failed to mark IP as scanned: {e}")

    def clear_checkpoint(self) -> None:
        """清除数据库中的所有记录"""
        try:
            self.db.clear_all()
            self.logger.info("Database cleared")
        except Exception as e:
            self.logger.error(f"Failed to clear checkpoint: {e}")

    def checkpoint_exists(self) -> bool:
        """检查数据库是否存在且有记录"""
        if not Path(self.config.database_file).exists():
            return False
        try:
            return self.db.has_records()
        except Exception:
            return False
    
    def close(self):
        """关闭数据库连接"""
        if self.db:
            self.db.close()


class WebScanner:
    """Web扫描器，负责执行HTTP/HTTPS请求"""

    def __init__(self, config: ScanConfig, logger):
        self.config = config
        self.logger = logger
        self.ssl_certificate = None  # 存储捕获到的SSL证书信息

    def _get_ssl_certificate_openssl(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """使用 pyOpenSSL 直接获取完整的 SSL 证书链"""
        try:
            from OpenSSL import SSL, crypto
            import socket
            import select
        except ImportError:
            self.logger.warning("pyOpenSSL not installed, cannot retrieve full certificate chain")
            return None
        
        try:
            # 创建 SSL 上下文
            context = SSL.Context(SSL.SSLv23_METHOD)
            context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
            
            # 连接到服务器
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            
            # 包装为 SSL 连接
            ssl_conn = SSL.Connection(context, sock)
            ssl_conn.set_tlsext_host_name(hostname.encode())
            ssl_conn.set_connect_state()
            
            # 执行握手 - 处理 WantRead/WantWrite
            while True:
                try:
                    ssl_conn.do_handshake()
                    break
                except SSL.WantReadError:
                    select.select([sock], [], [])
                    continue
                except SSL.WantWriteError:
                    select.select([], [sock], [])
                    continue
            
            # 获取对等证书和证书链
            peer_cert = ssl_conn.get_peer_certificate()
            cert_chain = ssl_conn.get_peer_cert_chain()
            
            if not peer_cert:
                return None
            
            # 提取证书信息
            subject = peer_cert.get_subject()
            issuer = peer_cert.get_issuer()
            
            cert_info = {
                "protocol": ssl_conn.get_protocol_version_name(),
                "cipher": ssl_conn.get_cipher_name(),
                "subject": subject.CN if hasattr(subject, 'CN') else str(subject),
                "issuer": issuer.CN if hasattr(issuer, 'CN') else str(issuer),
                "validFrom": peer_cert.get_notBefore().decode('utf-8'),
                "validTo": peer_cert.get_notAfter().decode('utf-8'),
                "serialNumber": str(peer_cert.get_serial_number()),
                "version": peer_cert.get_version(),
                "signatureAlgorithm": peer_cert.get_signature_algorithm().decode('utf-8'),
            }
            
            # 获取 SAN
            san_list = []
            try:
                for i in range(peer_cert.get_extension_count()):
                    ext = peer_cert.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_list = str(ext).split(', ')
            except:
                pass
            
            if san_list:
                cert_info["subjectAltName"] = san_list
            
            # 提取证书链
            if cert_chain and len(cert_chain) > 0:
                cert_info["certificateChain"] = []
                for idx, chain_cert in enumerate(cert_chain):
                    chain_subject = chain_cert.get_subject()
                    chain_issuer = chain_cert.get_issuer()
                    
                    # 构建完整的 subject 和 issuer 字符串
                    subject_components = chain_subject.get_components()
                    issuer_components = chain_issuer.get_components()
                    
                    subject_str = '/' + '/'.join([f"{name.decode('utf-8')}={value.decode('utf-8')}" 
                                                  for name, value in subject_components])
                    issuer_str = '/' + '/'.join([f"{name.decode('utf-8')}={value.decode('utf-8')}" 
                                                 for name, value in issuer_components])
                    
                    chain_info = {
                        "level": idx,
                        "subject": subject_str,
                        "issuer": issuer_str,
                        "serialNumber": str(chain_cert.get_serial_number()),
                        "validFrom": chain_cert.get_notBefore().decode('utf-8'),
                        "validTo": chain_cert.get_notAfter().decode('utf-8'),
                        "signatureAlgorithm": chain_cert.get_signature_algorithm().decode('utf-8'),
                    }
                    
                    cert_info["certificateChain"].append(chain_info)
                
                self.logger.debug(f"Certificate chain retrieved: {len(cert_chain)} certificates")
            
            # 关闭连接
            try:
                ssl_conn.shutdown()
            except:
                pass
            ssl_conn.close()
            sock.close()
            
            return cert_info
            
        except Exception as e:
            self.logger.debug(f"Failed to get SSL certificate via OpenSSL for {hostname}:{port}: {e}")
            return None

    async def _get_page_content_safely(self, page, url: str) -> str:
        """安全地获取页面内容，包含错误处理和重试逻辑"""
        try:
            # 根据等待策略做不同处理
            if self.config.wait_strategy == "commit":
                # 对于commit策略，需要额外等待确保内容加载
                await page.wait_for_timeout(500)  # 等待500ms
                try:
                    # 尝试等待body元素出现
                    await page.wait_for_selector(
                        "body", timeout=self.config.content_wait_timeout
                    )
                except Exception:
                    # 如果没有body，尝试等待html元素
                    try:
                        await page.wait_for_selector("html", timeout=1000)
                    except Exception:
                        pass  # 继续尝试获取内容

            # 等待页面稳定（避免导航冲突）
            try:
                await page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:
                # 如果等待网络空闲失败，继续尝试获取内容
                pass

            # 获取页面内容，增加重试机制
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    content = await page.content()

                    # 检查内容是否有效
                    if len(content.strip()) < 50:
                        if attempt < max_retries - 1:
                            self.logger.debug(
                                f"Content seems incomplete for {url}, attempt {attempt + 1}/{max_retries}"
                            )
                            await page.wait_for_timeout(1000)  # 等待1秒后重试
                            continue

                    return content

                except Exception as retry_error:
                    if "navigating and changing" in str(retry_error):
                        # 页面仍在导航，等待更长时间
                        if attempt < max_retries - 1:
                            self.logger.debug(
                                f"Page still navigating for {url}, waiting... (attempt {attempt + 1}/{max_retries})"
                            )
                            await page.wait_for_timeout(2000)
                            continue
                    raise retry_error

            # 如果所有重试都失败，返回当前可获取的内容
            return await page.content()

        except Exception as content_error:
            error_msg = str(content_error)

            # 根据错误类型提供更详细的信息
            if "navigating and changing" in error_msg:
                self.logger.warning(
                    f"Page navigation conflict for {url}: Content unstable due to redirects or JS navigation"
                )
            elif "Unable to retrieve content" in error_msg:
                self.logger.warning(
                    f"Content retrieval failed for {url}: {content_error}"
                )
            else:
                self.logger.warning(
                    f"Content loading warning for {url}: {content_error}"
                )

            # 最后尝试获取内容
            try:
                return await page.content()
            except Exception:
                return f"<!-- Content loading failed: {error_msg} -->"

    async def perform_web_scan(
        self, ip: str, protocol: str, port: int
    ) -> Dict[str, Any]:
        """执行Web扫描，访问指定IP和端口"""
        url = f"{protocol}://{ip}:{port}"
        self.logger.info(f"Visiting {url}")
        
        # 重置SSL证书信息
        self.ssl_certificate = None

        try:
            async with async_playwright() as p:
                # 使用更严格的启动参数
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-images",
                        "--disable-javascript",
                        "--disable-plugins",
                        "--disable-webgl",
                        "--no-sandbox",
                        "--disable-extensions",
                    ],
                )

                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                )

                page = await context.new_page()

                # 拦截所有非文档请求
                async def handle_route(route):
                    if route.request.resource_type == "document":
                        await route.continue_()
                    else:
                        await route.abort("blockedbyclient")

                await page.route("**/*", handle_route)

                await page.set_extra_http_headers(
                    {
                        "Sec-Ch-Ua-Platform": "Windows",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Upgrade-Insecure-Requests": "1",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                        "Sec-Fetch-Site": "none",
                        "Sec-Fetch-Mode": "navigate",
                        "Sec-Fetch-User": "?1",
                        "Sec-Fetch-Dest": "document",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Priority": "u=0, i",
                    }
                )

                # 使用配置的等待策略
                response = await page.goto(
                    url,
                    timeout=self.config.timeout * 1000,
                    wait_until=self.config.wait_strategy,
                )

                if response:
                    status = response.status
                    headers = response.headers
                    
                    # 检查最终URL是否是HTTPS，如果是则使用OpenSSL获取证书
                    final_url = page.url
                    if final_url.startswith("https://"):
                        from urllib.parse import urlparse
                        parsed_url = urlparse(final_url)
                        cert_hostname = parsed_url.hostname
                        cert_port = parsed_url.port or 443
                        
                        self.logger.info(f"HTTPS detected for {ip}, retrieving SSL certificate via OpenSSL...")
                        cert_info = self._get_ssl_certificate_openssl(cert_hostname, cert_port)
                        
                        if cert_info:
                            self.ssl_certificate = cert_info
                            chain_len = len(cert_info.get("certificateChain", []))
                            self.logger.info(f"SSL certificate info: Subject={cert_info.get('subject')}, Issuer={cert_info.get('issuer')}, Chain length={chain_len}")
                        else:
                            self.logger.warning(f"Failed to retrieve SSL certificate for {cert_hostname}:{cert_port}")

                    # 根据等待策略进行不同的内容获取处理
                    content = await self._get_page_content_safely(page, url)
                    
                    # 提取页面标题
                    try:
                        page_title = await page.title()
                        # 清理标题：移除换行符
                        page_title = page_title.replace("\n", " ").strip()
                    except Exception as title_error:
                        self.logger.debug(f"Failed to extract title for {url}: {title_error}")
                        page_title = ""
                else:
                    status = 404
                    headers = {}
                    content = ""
                    page_title = ""

                await browser.close()

                result = {
                    "status": status,
                    "headers": headers,
                    "content": content,
                    "title": page_title,
                    "url": url,
                    "ip": ip,
                    "protocol": protocol,
                    "port": port,
                }
                
                # 添加SSL证书信息到结果中
                if self.ssl_certificate:
                    result["ssl_certificate"] = self.ssl_certificate
                
                return result

        except Exception as e:
            error_msg = str(e)
            error_type = self._classify_error(error_msg)

            # 根据错误类型使用不同的日志级别
            if error_type == "timeout":
                self.logger.info(
                    f"Timeout visiting {url} (normal - service may not be running)"
                )
            elif error_type == "connection_refused":
                self.logger.info(
                    f"Connection refused for {url} (port closed or filtered)"
                )
            elif error_type == "network_error":
                self.logger.warning(f"Network error visiting {url}: {e}")
            else:
                self.logger.warning(f"Error visiting {url}: {e}")

            return {
                "error": error_msg,
                "error_type": error_type,
                "ip": ip,
                "protocol": protocol,
                "port": port,
                "url": url,
            }

    def _classify_error(self, error_msg: str) -> str:
        """分类错误类型以提供更好的用户体验"""
        error_msg_lower = error_msg.lower()

        if "timeout" in error_msg_lower:
            return "timeout"
        elif (
            "connection_refused" in error_msg_lower
            or "err_connection_refused" in error_msg_lower
        ):
            return "connection_refused"
        elif "err_empty_response" in error_msg_lower:
            return "empty_response"
        elif "network" in error_msg_lower or "dns" in error_msg_lower:
            return "network_error"
        elif "ssl" in error_msg_lower or "certificate" in error_msg_lower:
            return "ssl_error"
        else:
            return "unknown_error"


class SlowHTTPScanner:
    """慢速HTTP扫描器主类，整合所有组件"""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.logger_manager = LoggerManager(self.config)
        self.file_manager = FileManager(self.config)
        self.delay_generator = DelayGenerator(
            self.config, self.logger_manager.main_logger
        )
        self.web_scanner = WebScanner(self.config, self.logger_manager.main_logger)
        self.ip_generator = IPGenerator()
        self.checkpoint_manager = CheckpointManager(
            self.config, self.logger_manager.main_logger
        )

    def save_response(self, result: Dict[str, Any]) -> str:
        """保存响应结果并记录日志"""
        ip = result["ip"]
        protocol = result["protocol"]
        port = result["port"]

        # 保存SSL证书（如果有）
        if "ssl_certificate" in result and result["ssl_certificate"]:
            try:
                cert_filename = self.file_manager.save_ssl_certificate(
                    ip, port, result["ssl_certificate"]
                )
                self.logger_manager.success_logger.info(
                    f"SSL certificate saved for {ip}:{port} -> {cert_filename}"
                )
                self.logger_manager.main_logger.info(
                    f"SSL_CERT {ip}:{port} - Certificate captured and saved"
                )
            except Exception as e:
                self.logger_manager.main_logger.warning(
                    f"Failed to save SSL certificate for {ip}:{port}: {e}"
                )

        if "error" in result:
            error_type = result.get("error_type", "unknown")
            error_msg = result["error"]

            # 根据错误类型和配置记录不同级别的日志
            if error_type in ["timeout", "connection_refused", "empty_response"]:
                self.logger_manager.failure_logger.info(
                    f"{protocol}://{ip}:{port} - {error_type.replace('_', ' ').title()}: {error_msg}"
                )
                if self.config.verbose_logging:
                    self.logger_manager.main_logger.info(
                        f"EXPECTED_FAIL {protocol}://{ip}:{port} - {error_type}"
                    )
                else:
                    # 对于非详细模式，也显示 empty_response，但更简洁
                    self.logger_manager.main_logger.info(
                        f"FAILED {protocol}://{ip}:{port} - {error_type}"
                    )
            else:
                self.logger_manager.failure_logger.info(
                    f"{protocol}://{ip}:{port} - Unexpected error: {error_msg}"
                )
                self.logger_manager.main_logger.info(
                    f"FAILED {protocol}://{ip}:{port} - {error_type}"
                )

            return "failed"

        status = result["status"]
        content = result["content"]

        if status == 200:
            filename = self.file_manager.save_html_response(ip, protocol, port, content)
            self.logger_manager.success_logger.info(
                f"{protocol}://{ip}:{port} - Status {status} - HTML saved to {filename}"
            )
            self.logger_manager.main_logger.info(
                f"SUCCESS {protocol}://{ip}:{port} - Status {status} - HTML saved"
            )
            return "success"
        else:
            filename = self.file_manager.save_raw_response(
                ip, protocol, port, status, result["headers"], content
            )
            self.logger_manager.success_logger.info(
                f"{protocol}://{ip}:{port} - Status {status} - Raw response saved to {filename}"
            )
            self.logger_manager.main_logger.info(
                f"WARNING {protocol}://{ip}:{port} - Status {status} - Raw response saved"
            )
            return "success"

    async def scan_ips_from_db(
        self, protocol: str, port: int, batch_size: int = 100
    ) -> Dict[str, List[str]]:
        """从数据库随机抽取未扫描的IP进行扫描（内存优化版本）
        
        Args:
            protocol: 协议（http/https）
            port: 端口号
            batch_size: 每批扫描的IP数量
            
        Returns:
            按类型分类的扫描结果
        """
        results = {
            "response": [],
            "timeout": [],
            "connection_refused": [],
            "other_errors": [],
        }
        
        # 获取总的未扫描IP数量
        total_unscanned = self.checkpoint_manager.get_unscanned_count()
        total_ips = self.checkpoint_manager.db.has_records()
        
        self.logger_manager.main_logger.info(f"Starting {protocol}:{port} scan...")
        self.logger_manager.main_logger.info(f"{total_unscanned} IPs remaining to scan")
        
        # 计算已扫描的数量（用于进度显示）
        cursor = self.checkpoint_manager.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM scan_records")
        total_count = cursor.fetchone()['count']
        scanned_count = total_count - total_unscanned
        
        with Progress() as progress:
            task = progress.add_task(
                f"Scanning {protocol}:{port}...", total=total_count
            )
            # 更新进度到已扫描的位置
            progress.update(task, completed=scanned_count)
            
            try:
                # 持续从数据库随机获取未扫描的IP
                while True:
                    # 随机获取一批未扫描的IP
                    unscanned_batch = self.checkpoint_manager.get_random_unscanned_ips(batch_size)
                    
                    if not unscanned_batch:
                        # 没有更多未扫描的IP
                        break
                    
                    # 扫描这一批IP
                    for record in unscanned_batch:
                        ip = record['ip']
                        result = await self.web_scanner.perform_web_scan(ip, protocol, port)
                        category = self._categorize_result(result)
                        results[category].append(ip)
                        
                        # 保存响应详情
                        self.save_response(result)
                        
                        # 根据扫描结果确定状态和标题
                        if "error" in result:
                            error_type = result.get("error_type", "unknown")
                            if error_type == "timeout":
                                status = "timeout"
                            elif error_type == "connection_refused":
                                status = "connection_refused"
                            else:
                                status = f"error_{error_type}"
                            title = ""
                        else:
                            # 有响应，记录状态码和页面标题
                            http_status = result.get("status", 0)
                            status = f"HTTP_{http_status}"
                            title = result.get("title", "")
                        
                        # 标记IP为已扫描，记录状态和标题
                        self.checkpoint_manager.mark_ip_scanned(ip, port, status=status, title=title)
                        
                        progress.update(task, advance=1)
                        
                        delay = self.delay_generator.generate_random_delay()
                        time.sleep(delay)
                        
            except KeyboardInterrupt:
                self.logger_manager.main_logger.warning(
                    "\nScan interrupted by user. Progress saved to database."
                )
                remaining = self.checkpoint_manager.get_unscanned_count()
                self.logger_manager.main_logger.info(
                    f"Progress: {total_count - remaining}/{total_count} IPs scanned. You can resume later."
                )
                raise
            except Exception as e:
                self.logger_manager.main_logger.error(
                    f"Unexpected error during scan: {e}. Progress saved to database."
                )
                raise
        
        # 保存分类结果
        saved_files = self.file_manager.save_categorized_results(results)
        
        self.logger_manager.main_logger.info(f"{protocol}:{port} scan completed!")
        self._log_scan_summary(results, saved_files)
        
        return results

    async def scan_ips(
        self, ip_list: List[str], protocol: str, port: int
    ) -> Dict[str, List[str]]:
        """扫描IP列表，返回按类型分类的结果，支持断点续传（基于数据库）"""
        # 检查是否存在检查点
        if self.checkpoint_manager.checkpoint_exists():
            # 加载现有检查点
            self.checkpoint_manager.load_checkpoint()
            scanned_ips = self.checkpoint_manager.get_scanned_ips()
            self.logger_manager.main_logger.info(
                f"Resuming from checkpoint: {len(scanned_ips)} IPs already scanned"
            )
        else:
            # 初始化新的检查点，一次性写入所有IP
            self.checkpoint_manager.initialize_checkpoint(ip_list, port)
            scanned_ips = set()
            self.logger_manager.main_logger.info(
                "Initialized new checkpoint with all IPs"
            )
        
        # 过滤出未扫描的IP
        remaining_ips = [ip for ip in ip_list if ip not in scanned_ips]
        
        results = {
            "response": [],
            "timeout": [],
            "connection_refused": [],
            "other_errors": [],
        }

        self.logger_manager.main_logger.info(f"Starting {protocol}:{port} scan...")
        self.logger_manager.main_logger.info(f"{len(remaining_ips)} IPs remaining to scan")

        with Progress() as progress:
            task = progress.add_task(
                f"Scanning {protocol}:{port}...", total=len(ip_list)
            )
            # 更新进度到已扫描的位置
            progress.update(task, completed=len(scanned_ips))

            try:
                for ip in remaining_ips:
                    result = await self.web_scanner.perform_web_scan(ip, protocol, port)
                    category = self._categorize_result(result)
                    results[category].append(ip)

                    # 保存响应详情
                    self.save_response(result)
                    
                    # 根据扫描结果确定状态和标题
                    if "error" in result:
                        error_type = result.get("error_type", "unknown")
                        if error_type == "timeout":
                            status = "timeout"
                        elif error_type == "connection_refused":
                            status = "connection_refused"
                        else:
                            status = f"error_{error_type}"
                        title = ""
                    else:
                        # 有响应，记录状态码和页面标题
                        http_status = result.get("status", 0)
                        status = f"HTTP_{http_status}"
                        title = result.get("title", "")
                    
                    # 标记IP为已扫描，记录状态和标题
                    self.checkpoint_manager.mark_ip_scanned(ip, port, status=status, title=title)
                    
                    progress.update(task, advance=1)

                    delay = self.delay_generator.generate_random_delay()
                    time.sleep(delay)

            except KeyboardInterrupt:
                self.logger_manager.main_logger.warning(
                    "\nScan interrupted by user. Progress saved to CSV checkpoint."
                )
                scanned_count = len(scanned_ips) + len([ip for ip in remaining_ips if ip in self.checkpoint_manager.get_scanned_ips()])
                self.logger_manager.main_logger.info(
                    f"Progress: {scanned_count}/{len(ip_list)} IPs scanned. You can resume later."
                )
                raise
            except Exception as e:
                self.logger_manager.main_logger.error(
                    f"Unexpected error during scan: {e}. Progress saved to CSV checkpoint."
                )
                raise

        # 保存分类结果
        saved_files = self.file_manager.save_categorized_results(results)

        self.logger_manager.main_logger.info(f"{protocol}:{port} scan completed!")
        self._log_scan_summary(results, saved_files)

        return results

    def _categorize_result(self, result: Dict[str, Any]) -> str:
        """根据扫描结果确定分类"""
        if "error" not in result:
            return "response"  # 有响应，无论状态码

        error_type = result.get("error_type", "unknown")
        if error_type == "timeout":
            return "timeout"
        elif error_type == "connection_refused":
            return "connection_refused"
        else:
            return "other_errors"

    def _log_scan_summary(
        self, results: Dict[str, List[str]], saved_files: Dict[str, str]
    ):
        """记录扫描摘要"""
        total_ips = sum(len(ips) for ips in results.values())

        self.logger_manager.main_logger.info("Scan Summary:")
        self.logger_manager.main_logger.info(f"  - Total IPs scanned: {total_ips}")
        self.logger_manager.main_logger.info(
            f"  - Responses received: {len(results['response'])}"
        )
        self.logger_manager.main_logger.info(f"  - Timeouts: {len(results['timeout'])}")
        self.logger_manager.main_logger.info(
            f"  - Connection refused: {len(results['connection_refused'])}"
        )
        self.logger_manager.main_logger.info(
            f"  - Other errors: {len(results['other_errors'])}"
        )

        if saved_files:
            self.logger_manager.main_logger.info("Results saved to:")
            for category, filename in saved_files.items():
                count = len(results[category])
                self.logger_manager.main_logger.info(
                    f"  - {category.replace('_', ' ').title()}: {count} IPs -> {filename}"
                )

    async def run_scan(
        self, cidr: Optional[str] = None, resume: bool = True, clear_checkpoint: bool = False,
        memory_optimized: bool = False, batch_size: int = 100
    ) -> Dict[str, Any]:
        """运行扫描任务
        
        Args:
            cidr: CIDR范围，如果为None则使用配置中的范围
            resume: 是否从检查点恢复（默认True）
            clear_checkpoint: 是否清除现有检查点并重新开始（默认False）
            memory_optimized: 是否使用内存优化模式（默认False，适用于大CIDR）
            batch_size: 内存优化模式下每批扫描的IP数量（默认100）
        """
        cidr = cidr or self.config.cidr_range

        # 如果指定清除检查点或不恢复
        if clear_checkpoint or not resume:
            self.logger_manager.main_logger.info("Clearing existing checkpoint...")
            self.checkpoint_manager.clear_checkpoint()

        # 检查是否需要初始化数据库
        if not self.checkpoint_manager.checkpoint_exists() or clear_checkpoint:
            if memory_optimized:
                # 内存优化模式：使用生成器流式初始化
                self.logger_manager.main_logger.info(
                    f"Initializing database from {cidr} (memory optimized mode)..."
                )
                ip_generator = self.ip_generator.generate_ip_stream(cidr)
                total_ips = self.checkpoint_manager.initialize_checkpoint_stream(
                    ip_generator, self.config.port, batch_size=10000
                )
                self.logger_manager.main_logger.info(
                    f"Database initialized with {total_ips} IP addresses"
                )
            else:
                # 常规模式：一次性生成所有IP
                self.logger_manager.main_logger.info(f"Generating IP list from {cidr}...")
                ip_list = self.ip_generator.generate_ip_list(cidr)
                self.logger_manager.main_logger.info(
                    f"Total {len(ip_list)} IP addresses to scan"
                )
                self.checkpoint_manager.initialize_checkpoint(ip_list, self.config.port)
        
        # 执行扫描
        if memory_optimized:
            # 内存优化模式：从数据库随机抽取未扫描的IP
            self.logger_manager.main_logger.info(
                "Using memory-optimized scanning mode (random sampling from database)"
            )
            scan_results = await self.scan_ips_from_db(
                self.config.protocol, self.config.port, batch_size=batch_size
            )
            # 获取实际扫描的总数
            cursor = self.checkpoint_manager.db.conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM scan_records")
            total_ips = cursor.fetchone()['count']
        else:
            # 常规模式：按列表扫描
            ip_list = self.ip_generator.generate_ip_list(cidr)
            scan_results = await self.scan_ips(
                ip_list, self.config.protocol, self.config.port
            )
            total_ips = len(ip_list)

        self.logger_manager.main_logger.info("All scans completed!")
        
        # 扫描完成后保留数据库文件
        self.logger_manager.main_logger.info(
            f"Scan results saved in database: {self.config.database_file}"
        )

        return {
            "results": scan_results,
            "total_scanned": total_ips,
            "summary": {
                "responses": len(scan_results["response"]),
                "timeouts": len(scan_results["timeout"]),
                "connection_refused": len(scan_results["connection_refused"]),
                "other_errors": len(scan_results["other_errors"]),
            },
        }


async def main():
    """主函数 - 展示不同配置的使用方法"""

    # 示例1: 使用默认配置 - 支持断点续传
    print("=== 使用默认配置 - 结果按类型分类，支持断点续传 ===")
    scanner = SlowHTTPScanner()

    # 运行扫描（默认会自动从检查点恢复）
    # resume=True: 自动从上次中断的地方继续
    # resume=False: 忽略检查点，从头开始但不清除检查点文件
    # clear_checkpoint=True: 清除检查点并从头开始
    # memory_optimized=True: 内存优化模式，适用于大CIDR（如10.0.0.0/8）
    # batch_size=100: 每批从数据库获取的IP数量
    results = await scanner.run_scan(resume=True, memory_optimized=False)
    
    # 示例1-B: 对于大CIDR范围使用内存优化模式
    # print("=== 大CIDR范围扫描 - 内存优化模式 ===")
    # large_config = ScanConfig(cidr_range="10.0.0.0/8", port=80)
    # scanner = SlowHTTPScanner(large_config)
    # results = await scanner.run_scan(memory_optimized=True, batch_size=100)

    # 示例2: 强制重新开始扫描（清除之前的检查点）
    # results = await scanner.run_scan(clear_checkpoint=True)

    # 示例3: 使用快速扫描配置
    # print("=== 使用快速扫描配置 ===")
    # fast_config = ScanConfig.create_fast_scan_config("192.168.1.0/24", 80)
    # scanner = SlowHTTPScanner(fast_config)
    # results = await scanner.run_scan()

    # 示例4: 使用彻底扫描配置
    # print("=== 使用彻底扫描配置 ===")
    # thorough_config = ScanConfig.create_thorough_scan_config("192.168.1.0/24", 443)
    # thorough_config.protocol = "https"
    # scanner = SlowHTTPScanner(thorough_config)
    # results = await scanner.run_scan()

    # 示例5: 自定义配置 - 启用详细日志
    # print("=== 使用自定义配置 - 详细日志 ===")
    # custom_config = ScanConfig(
    #     cidr_range="10.0.0.0/24",
    #     protocol="http",
    #     port=8080,
    #     wait_strategy="networkidle",  # 等待网络空闲
    #     content_wait_timeout=3000,
    #     verbose_logging=True
    # )
    # scanner = SlowHTTPScanner(custom_config)
    # results = await scanner.run_scan()

    # 打印最终统计
    print("\n=== 扫描统计 ===")
    print(f"总扫描IP数: {results['total_scanned']}")
    print(f"有响应: {results['summary']['responses']}")
    print(f"超时: {results['summary']['timeouts']}")
    print(f"连接被拒绝: {results['summary']['connection_refused']}")
    print(f"其他错误: {results['summary']['other_errors']}")

    return results


if __name__ == "__main__":
    asyncio.run(main())
