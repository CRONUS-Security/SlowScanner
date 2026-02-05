"""
文件管理模块
"""
from typing import Dict, List, Any
from .config import ScanConfig


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
        response_info += f"Content: {content}\n"
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
        
        # 证书链信息
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
