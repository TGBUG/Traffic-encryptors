#!/usr/bin/env python3

import socket
import os
import threading
import time
import argparse
import logging
from Crypto.Cipher import AES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ServerProxy')

class ServerProxy:
    def __init__(self, listen_host, listen_port, key):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.key = key
        self.connections = []
        self.running = True

    def start(self):
        """开启代理服务器"""
        try:
            # Create socket to listen for client proxy connections
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.listen_host, self.listen_port))
            self.server_socket.listen(5)
            logger.info(f"Server proxy listening on {self.listen_host}:{self.listen_port}")

            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    logger.info(f"New connection from client proxy at {client_addr}")
                    
                    # Create new connection handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client_proxy_connection,
                        args=(client_sock, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.connections.append(client_thread)
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error starting server proxy: {e}")
        finally:
            self.stop()

    def stop(self):
        """关闭代理服务器"""
        self.running = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
        logger.info("Server proxy stopped")

    def handle_client_proxy_connection(self, client_sock, client_addr):
        """处理来自客户端代理的连接"""
        tls_sock = None
        
        try:
            length_data = client_sock.recv(4)
            if not length_data or len(length_data) < 4:
                logger.error("Failed to receive initial packet length")
                return
                
            length = int.from_bytes(length_data, 'big')
            packet = self.recv_exact(client_sock, length)
            
            iv = packet[:12]
            tag = packet[-16:]
            ciphertext = packet[12:-16]
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            tls_server_host, tls_server_port = self.extract_tls_target(plaintext)
            logger.info(f"Extracted target: {tls_server_host}:{tls_server_port}")
            
            tls_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tls_sock.connect((tls_server_host, tls_server_port))
            logger.info(f"Connected to TLS server at {tls_server_host}:{tls_server_port}")
            
            tls_sock.sendall(plaintext)
            
            client_to_server = threading.Thread(
                target=self.forward_data, 
                args=(client_sock, tls_sock, "client->server")
            )
            server_to_client = threading.Thread(
                target=self.backward_data,
                args=(tls_sock, client_sock, "server->client")
            )
            
            client_to_server.daemon = True
            server_to_client.daemon = True
            
            client_to_server.start()
            server_to_client.start()
            
            client_to_server.join()
            server_to_client.join()
            
        except Exception as e:
            logger.error(f"Error handling client proxy connection: {e}")
        finally:
            if tls_sock:
                tls_sock.close()
            if client_sock:
                client_sock.close()
            logger.info(f"Closed connection from {client_addr}")

    def extract_tls_target(self, tls_data):
        """对这里就是这样，目标地址就设置在这"""
        return "www.infcraft.cn", 443  # Default target
    
    def recv_exact(self, sock, n):
        """从套接字接收恰好 n 个字节"""
        data = b''
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise Exception(f"Connection closed while trying to receive {n} bytes")
            data += chunk
            remaining -= len(chunk)
        return data

    def forward_data(self, src_sock, dst_sock, direction):
        """从源接收加密数据，解密并转发到目的地"""
        try:
            while self.running:
                length_data = src_sock.recv(4)
                if not length_data or len(length_data) < 4:
                    logger.info(f"{direction}: Connection closed by peer")
                    break
                
                length = int.from_bytes(length_data, 'big')
                
                packet = self.recv_exact(src_sock, length)
                
                iv = packet[:12]
                tag = packet[-16:]
                ciphertext = packet[12:-16]
                
                cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                dst_sock.sendall(plaintext)
                
                logger.debug(f"{direction}: Received {length} bytes (decrypted to {len(plaintext)} bytes)")
        except Exception as e:
            if self.running:
                logger.error(f"{direction}: Error processing encrypted data: {e}")

    def backward_data(self, src_sock, dst_sock, direction):
        """从源读取数据并在转发到目标之前进行加密"""
        try:
            while self.running:
                data = src_sock.recv(8192)
                if not data:
                    logger.info(f"{direction}: Connection closed by peer")
                    break
                
                iv = os.urandom(12)  # Generate random 12-byte IV
                cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
                ciphertext, tag = cipher.encrypt_and_digest(data)
                
                packet = iv + ciphertext + tag
                
                length = len(packet)
                dst_sock.sendall(length.to_bytes(4, 'big'))
                dst_sock.sendall(packet)
                
                logger.debug(f"{direction}: Forwarded {len(data)} bytes (encrypted to {length} bytes)")
        except Exception as e:
            if self.running:
                logger.error(f"{direction}: Error forwarding data: {e}")

def main():
    parser = argparse.ArgumentParser(description='加密代理服务端')
    parser.add_argument('--listen-host', default='0.0.0.0', help='监听地址')
    parser.add_argument('--listen-port', type=int, default=9443, help='监听端口')
    parser.add_argument('--key', required=True, help='加密密钥')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    key = bytes.fromhex(args.key)
    if len(key) != 32:
        parser.error("Key must be 32 bytes (64 hex characters)")
    
    proxy = ServerProxy(args.listen_host, args.listen_port, key)
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        proxy.stop()

if __name__ == "__main__":
    main()

