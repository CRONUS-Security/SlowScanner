"""
SlowScanner - 慢速HTTP/HTTPS扫描器主程序
一个功能强大的网络扫描工具，支持大规模CIDR范围扫描和断点续传
"""
import asyncio
import time
from typing import Dict, List, Any, Optional
from rich.progress import Progress

# 导入核心模块
from core import (
    ScanConfig,
    LoggerManager,
    FileManager,
    IPGenerator,
    DelayGenerator,
    CheckpointManager,
    WebScanner,
)

# pip install playwright rich pyopenssl pyyaml
# playwright install


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
                    "\nScan interrupted by user. Progress saved to database."
                )
                scanned_count = len(scanned_ips) + len([ip for ip in remaining_ips if ip in self.checkpoint_manager.get_scanned_ips()])
                self.logger_manager.main_logger.info(
                    f"Progress: {scanned_count}/{len(ip_list)} IPs scanned. You can resume later."
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
            cidr: CIDR范围或IP文件路径，如果为None则使用配置中的范围/文件
            resume: 是否从检查点恢复（默认True）
            clear_checkpoint: 是否清除现有检查点并重新开始（默认False）
            memory_optimized: 是否使用内存优化模式（默认False，适用于大范围）
            batch_size: 内存优化模式下每批扫描的IP数量（默认100）
        """
        # 根据配置的范围模式确定数据源
        if self.config.range_mode.upper() == "FILE":
            ip_source = cidr or self.config.ip_file
            self.logger_manager.main_logger.info(f"扫描目标来源: 文件 ({ip_source})")
        else:
            ip_source = cidr or self.config.cidr_range
            self.logger_manager.main_logger.info(f"扫描目标来源: CIDR范围 ({ip_source})")

        # 如果指定清除检查点或不恢复
        if clear_checkpoint or not resume:
            self.logger_manager.main_logger.info("Clearing existing checkpoint...")
            self.checkpoint_manager.clear_checkpoint()

        # 检查是否需要初始化数据库
        if not self.checkpoint_manager.checkpoint_exists() or clear_checkpoint:
            if self.config.range_mode.upper() == "FILE":
                # 从文件读取IP
                if memory_optimized:
                    # 内存优化模式：使用生成器流式初始化
                    self.logger_manager.main_logger.info(
                        f"Initializing database from file {ip_source} (memory optimized mode)..."
                    )
                    ip_generator = self.ip_generator.load_ips_from_file_stream(ip_source)
                    total_ips = self.checkpoint_manager.initialize_checkpoint_stream(
                        ip_generator, self.config.port, batch_size=10000
                    )
                    self.logger_manager.main_logger.info(
                        f"Database initialized with {total_ips} IP addresses from file"
                    )
                else:
                    # 常规模式：一次性读取所有IP
                    self.logger_manager.main_logger.info(f"Reading IP list from {ip_source}...")
                    ip_list = self.ip_generator.load_ips_from_file(ip_source)
                    self.logger_manager.main_logger.info(
                        f"Total {len(ip_list)} IP addresses to scan"
                    )
                    self.checkpoint_manager.initialize_checkpoint(ip_list, self.config.port)
            else:
                # 从CIDR范围生成IP
                if memory_optimized:
                    # 内存优化模式：使用生成器流式初始化
                    self.logger_manager.main_logger.info(
                        f"Initializing database from {ip_source} (memory optimized mode)..."
                    )
                    ip_generator = self.ip_generator.generate_ip_stream(ip_source)
                    total_ips = self.checkpoint_manager.initialize_checkpoint_stream(
                        ip_generator, self.config.port, batch_size=10000
                    )
                    self.logger_manager.main_logger.info(
                        f"Database initialized with {total_ips} IP addresses"
                    )
                else:
                    # 常规模式：一次性生成所有IP
                    self.logger_manager.main_logger.info(f"Generating IP list from {ip_source}...")
                    ip_list = self.ip_generator.generate_ip_list(ip_source)
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
            if self.config.range_mode.upper() == "FILE":
                ip_list = self.ip_generator.load_ips_from_file(ip_source)
            else:
                ip_list = self.ip_generator.generate_ip_list(ip_source)
            
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

    # 示例1: 从配置文件加载配置
    print("=== 从配置文件加载配置 (config.yaml) ===")
    config = ScanConfig.from_yaml("config.yaml")
    scanner = SlowHTTPScanner(config)

    # 运行扫描（默认会自动从检查点恢复）
    # resume=True: 自动从上次中断的地方继续
    # resume=False: 忽略检查点，从头开始但不清除检查点文件
    # clear_checkpoint=True: 清除检查点并从头开始
    # memory_optimized=True: 内存优化模式，适用于大CIDR（如10.0.0.0/8）
    # batch_size=100: 每批从数据库获取的IP数量
    results = await scanner.run_scan(resume=True, memory_optimized=True, batch_size=1000)
    
    # 示例1-B: 使用默认配置（不使用配置文件）
    # print("=== 使用默认配置 ===")
    # scanner = SlowHTTPScanner()
    # results = await scanner.run_scan(resume=True, memory_optimized=True, batch_size=1000)

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
