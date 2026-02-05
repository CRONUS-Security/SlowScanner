"""
检查点管理模块
"""
import logging
from pathlib import Path
from typing import List, Dict, Any
from core.database import HTTPScanDatabase
from .config import ScanConfig


class CheckpointManager:
    """检查点管理器，负责保存和恢复扫描进度 - 使用SQLite数据库"""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
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
