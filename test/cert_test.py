"""使用 OpenSSL 直接获取证书链进行对比"""
import socket
from urllib.parse import urlparse


def get_certificate_chain_openssl(hostname, port=443):
    """使用 pyOpenSSL 获取完整的证书链"""
    print(f"\n{'='*80}")
    print(f"使用 pyOpenSSL 获取证书链: {hostname}:{port}")
    print('='*80)
    
    try:
        from OpenSSL import SSL, crypto
    except ImportError:
        print("\n❌ 需要安装 pyOpenSSL:")
        print("   pip install pyOpenSSL")
        return None, None
    
    # 创建 SSL 上下文
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    
    # 连接到服务器
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
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
                import select
                select.select([sock], [], [])
                continue
            except SSL.WantWriteError:
                import select
                select.select([], [sock], [])
                continue
        
        # 获取对等证书（服务器证书）
        peer_cert = ssl_conn.get_peer_certificate()
        
        # 获取完整证书链
        cert_chain = ssl_conn.get_peer_cert_chain()
        
        print(f"\n✓ 成功获取证书链")
        print(f"  证书链长度: {len(cert_chain) if cert_chain else 0}")
        print(f"  协议版本: {ssl_conn.get_protocol_version_name()}")
        print(f"  密码套件: {ssl_conn.get_cipher_name()}")
        
        if peer_cert:
            subject = peer_cert.get_subject()
            issuer = peer_cert.get_issuer()
            
            print(f"\n📋 服务器证书 (Peer Certificate):")
            print(f"  Subject CN: {subject.CN if hasattr(subject, 'CN') else 'N/A'}")
            print(f"  Subject O: {subject.O if hasattr(subject, 'O') else 'N/A'}")
            print(f"  Issuer CN: {issuer.CN if hasattr(issuer, 'CN') else 'N/A'}")
            print(f"  Issuer O: {issuer.O if hasattr(issuer, 'O') else 'N/A'}")
            print(f"  Serial Number: {peer_cert.get_serial_number()}")
            print(f"  Version: {peer_cert.get_version()}")
            print(f"  Not Before: {peer_cert.get_notBefore().decode('utf-8')}")
            print(f"  Not After: {peer_cert.get_notAfter().decode('utf-8')}")
            print(f"  Signature Algorithm: {peer_cert.get_signature_algorithm().decode('utf-8')}")
            
            # 获取 SAN (Subject Alternative Names)
            try:
                for i in range(peer_cert.get_extension_count()):
                    ext = peer_cert.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        print(f"  Subject Alt Name: {ext}")
            except Exception as e:
                pass
        
        if cert_chain:
            print(f"\n🔗 证书链详情 ({len(cert_chain)} 个证书):")
            print("-" * 80)
            
            for idx, cert_obj in enumerate(cert_chain):
                subject = cert_obj.get_subject()
                issuer = cert_obj.get_issuer()
                
                # 判断证书类型
                cert_type = "Leaf" if idx == 0 else ("Root" if idx == len(cert_chain) - 1 else f"Intermediate #{idx}")
                
                print(f"\n  [{idx}] {cert_type} Certificate:")
                print(f"      Subject CN: {subject.CN if hasattr(subject, 'CN') else 'N/A'}")
                print(f"      Subject O: {subject.O if hasattr(subject, 'O') else 'N/A'}")
                print(f"      Subject C: {subject.C if hasattr(subject, 'C') else 'N/A'}")
                print(f"      Issuer CN: {issuer.CN if hasattr(issuer, 'CN') else 'N/A'}")
                print(f"      Issuer O: {issuer.O if hasattr(issuer, 'O') else 'N/A'}")
                print(f"      Issuer C: {issuer.C if hasattr(issuer, 'C') else 'N/A'}")
                print(f"      Serial: {cert_obj.get_serial_number()}")
                print(f"      Not Before: {cert_obj.get_notBefore().decode('utf-8')}")
                print(f"      Not After: {cert_obj.get_notAfter().decode('utf-8')}")
                print(f"      Signature Algorithm: {cert_obj.get_signature_algorithm().decode('utf-8')}")
                
                # 完整的 Subject 和 Issuer
                subject_components = subject.get_components()
                issuer_components = issuer.get_components()
                
                subject_str = '/' + '/'.join([f"{name.decode('utf-8')}={value.decode('utf-8')}" 
                                              for name, value in subject_components])
                issuer_str = '/' + '/'.join([f"{name.decode('utf-8')}={value.decode('utf-8')}" 
                                             for name, value in issuer_components])
                print(f"      完整 Subject: {subject_str}")
                print(f"      完整 Issuer: {issuer_str}")
                
                # 获取 PEM 格式
                pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_obj).decode('utf-8')
                print(f"      PEM (前3行):")
                for line in pem_cert.split('\n')[:3]:
                    print(f"        {line}")
        
        # 正确关闭连接
        try:
            ssl_conn.shutdown()
        except:
            pass
        ssl_conn.close()
        sock.close()
        
        return peer_cert, cert_chain
        
    except Exception as e:
        print(f"\n✗ 连接错误: {e}")
        import traceback
        traceback.print_exc()
        try:
            sock.close()
        except:
            pass
        return None, None


def main():
    # 测试目标
    test_url = "https://172.25.159.118"
    
    parsed = urlparse(test_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    print("SSL 证书链获取测试 (使用 pyOpenSSL)")
    print("=" * 80)
    print(f"目标: {hostname}:{port}")
    
    try:
        cert, chain = get_certificate_chain_openssl(hostname, port)
        
        print(f"\n{'='*80}")
        if cert and chain:
            print("✓ 测试完成")
            print(f"总结: 成功获取 {len(chain)} 个证书")
        else:
            print("⚠️  测试未完全成功")
        print('='*80)
        
    except Exception as e:
        print(f"\n✗ 错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
