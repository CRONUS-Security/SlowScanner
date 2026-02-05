"""
Web扫描器模块
"""
import logging
from typing import Dict, Any, Optional
from playwright.async_api import async_playwright
from .config import ScanConfig


class WebScanner:
    """Web扫描器，负责执行HTTP/HTTPS请求"""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
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
