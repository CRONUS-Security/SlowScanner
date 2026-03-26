"""
SQLite数据库管理模块
用于替代CSV文件存储扫描进度和结果
"""
import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass


@dataclass
class ScanRecord:
    """扫描记录数据类"""
    ip: str
    port: int
    status: str = ""
    record_type: str = ""
    fingerprint: str = ""
    title: str = ""
    ssl_cert: str = ""


class DatabaseManager:
    """数据库管理器基类"""
    
    def __init__(self, db_path: str, logger: logging.Logger):
        self.db_path = db_path
        self.logger = logger
        self._ensure_db_directory()
        self.conn: Optional[sqlite3.Connection] = None
        
    def _ensure_db_directory(self):
        """确保数据库文件所在目录存在"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def connect(self):
        """连接到数据库"""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.logger.debug(f"Connected to database: {self.db_path}")
    
    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.logger.debug("Database connection closed")
    
    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()


class HTTPScanDatabase(DatabaseManager):
    """HTTP/HTTPS扫描数据库管理器"""
    
    def __init__(self, db_path: str, logger: logging.Logger):
        super().__init__(db_path, logger)
        self.connect()
        self._create_table()
    
    def _create_table(self):
        """创建扫描记录表"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_records (
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    status TEXT,
                    type TEXT,
                    fingerprint TEXT,
                    title TEXT,
                    ssl_cert TEXT,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (ip, port)
                )
            """)

            self._ensure_schema(cursor)
            
            # 创建索引以提高查询性能
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip 
                ON scan_records(ip)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_status 
                ON scan_records(status)
            """)
            
            self.conn.commit()
            self.logger.debug("HTTP scan table created/verified")
        except sqlite3.Error as e:
            self.logger.error(f"Failed to create table: {e}")
            raise

    def _ensure_schema(self, cursor: sqlite3.Cursor) -> None:
        """确保表结构包含 type 列并保持目标列顺序"""
        cursor.execute("PRAGMA table_info(scan_records)")
        current_columns = [row[1] for row in cursor.fetchall()]
        expected_columns = [
            "ip",
            "port",
            "status",
            "type",
            "fingerprint",
            "title",
            "ssl_cert",
            "scanned_at",
        ]

        if current_columns == expected_columns:
            return

        self.logger.info("Migrating scan_records schema to target column layout")

        # 避免索引名冲突
        cursor.execute("DROP INDEX IF EXISTS idx_ip")
        cursor.execute("DROP INDEX IF EXISTS idx_status")

        cursor.execute("ALTER TABLE scan_records RENAME TO scan_records_old")
        cursor.execute("""
            CREATE TABLE scan_records (
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT,
                type TEXT,
                fingerprint TEXT,
                title TEXT,
                ssl_cert TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ip, port)
            )
        """)

        cursor.execute("PRAGMA table_info(scan_records_old)")
        old_columns = {row[1] for row in cursor.fetchall()}
        common_columns = [col for col in expected_columns if col in old_columns]

        if common_columns:
            cols = ", ".join(common_columns)
            cursor.execute(f"""
                INSERT INTO scan_records ({cols})
                SELECT {cols} FROM scan_records_old
            """)

        cursor.execute("UPDATE scan_records SET type = '' WHERE type IS NULL")
        cursor.execute("DROP TABLE scan_records_old")
    
    def initialize_ips(self, ip_list: List[str], port: int) -> None:
        """初始化IP列表（批量插入）"""
        try:
            cursor = self.conn.cursor()
            
            # 使用批量插入提高性能
            records = [(ip, port, '', '', '', '', '') for ip in ip_list]
            cursor.executemany("""
                INSERT OR IGNORE INTO scan_records 
                (ip, port, status, type, fingerprint, title, ssl_cert)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, records)
            
            self.conn.commit()
            self.logger.info(f"Initialized database with {len(ip_list)} IPs")
        except sqlite3.Error as e:
            self.logger.error(f"Failed to initialize IPs: {e}")
            raise
    
    def initialize_ips_batch(self, ip_generator, port: int, batch_size: int = 10000) -> int:
        """批量初始化IP（使用生成器，避免内存占用过大）
        
        Args:
            ip_generator: IP地址生成器
            port: 端口号
            batch_size: 每批插入的数量
            
        Returns:
            初始化的总IP数量
        """
        try:
            cursor = self.conn.cursor()
            total_count = 0
            batch = []
            
            for ip in ip_generator:
                batch.append((ip, port, '', '', '', '', ''))
                
                if len(batch) >= batch_size:
                    cursor.executemany("""
                        INSERT OR IGNORE INTO scan_records 
                        (ip, port, status, type, fingerprint, title, ssl_cert)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    self.conn.commit()
                    total_count += len(batch)
                    self.logger.debug(f"Initialized batch: {total_count} IPs so far")
                    batch = []
            
            # 插入剩余的记录
            if batch:
                cursor.executemany("""
                    INSERT OR IGNORE INTO scan_records 
                    (ip, port, status, type, fingerprint, title, ssl_cert)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, batch)
                self.conn.commit()
                total_count += len(batch)
            
            self.logger.info(f"Initialized database with {total_count} IPs")
            return total_count
        except sqlite3.Error as e:
            self.logger.error(f"Failed to initialize IPs in batch: {e}")
            raise
    
    def get_scanned_ips(self) -> Set[str]:
        """获取已扫描的IP集合"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT ip FROM scan_records 
                WHERE status != '' OR type != '' OR fingerprint != '' OR title != '' OR ssl_cert != ''
            """)
            
            scanned_ips = {row['ip'] for row in cursor.fetchall()}
            return scanned_ips
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get scanned IPs: {e}")
            return set()
    
    def mark_ip_scanned(
        self, 
        ip: str, 
        port: int,
        status: str = "",
        record_type: str = "",
        fingerprint: str = "",
        title: str = "",
        ssl_cert: str = "",
    ) -> None:
        """标记IP为已扫描"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE scan_records 
                SET status = ?, type = ?, fingerprint = ?, title = ?, ssl_cert = ?,
                    scanned_at = CURRENT_TIMESTAMP
                WHERE ip = ? AND port = ?
            """, (status, record_type, fingerprint, title, ssl_cert, ip, port))
            
            self.conn.commit()
            self.logger.debug(f"Marked {ip}:{port} as scanned")
        except sqlite3.Error as e:
            self.logger.error(f"Failed to mark IP as scanned: {e}")
    
    def get_all_records(self) -> List[Dict[str, Any]]:
        """获取所有扫描记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT ip, port, status, type, fingerprint, title, ssl_cert, scanned_at
                FROM scan_records
                ORDER BY ip
            """)
            
            records = []
            for row in cursor.fetchall():
                records.append(dict(row))
            return records
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get all records: {e}")
            return []
    
    def get_record(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """获取特定IP和端口的扫描记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT ip, port, status, type, fingerprint, title, ssl_cert, scanned_at
                FROM scan_records
                WHERE ip = ? AND port = ?
            """, (ip, port))
            
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get record: {e}")
            return None
    
    def clear_all(self) -> None:
        """清空所有记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM scan_records")
            self.conn.commit()
            self.logger.info("All scan records cleared")
        except sqlite3.Error as e:
            self.logger.error(f"Failed to clear records: {e}")
    
    def has_records(self) -> bool:
        """检查是否有记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM scan_records")
            row = cursor.fetchone()
            return row['count'] > 0 if row else False
        except sqlite3.Error as e:
            self.logger.error(f"Failed to check records: {e}")
            return False
    
    def get_unscanned_count(self) -> int:
        """获取未扫描的IP数量"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as count FROM scan_records 
                WHERE status = '' AND type = '' AND fingerprint = '' AND title = '' AND ssl_cert = ''
            """)
            row = cursor.fetchone()
            return row['count'] if row else 0
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get unscanned count: {e}")
            return 0
    
    def get_random_unscanned_ips(self, limit: int = 100) -> List[Dict[str, Any]]:
        """随机获取未扫描的IP
        
        Args:
            limit: 返回的最大数量
            
        Returns:
            未扫描的IP记录列表
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT ip, port FROM scan_records 
                WHERE status = '' AND type = '' AND fingerprint = '' AND title = '' AND ssl_cert = ''
                ORDER BY RANDOM()
                LIMIT ?
            """, (limit,))
            
            records = []
            for row in cursor.fetchall():
                records.append(dict(row))
            return records
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get random unscanned IPs: {e}")
            return []
