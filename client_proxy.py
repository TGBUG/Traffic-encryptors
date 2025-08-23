#!/usr/bin/env python3

import socket
import os
import threading
import time
import argparse
import logging
from Crypto.Cipher import AES

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ClientProxy')

class ClientProxy:
    def __init__(self, local_host, local_port, server_host, server_port, key):
        self.local_host = local_host
        self.local_port = local_port
        self.server_host = server_host
        self.server_port = server_port
        self.key = key
        self.connections = []
        self.running = True

    def start(self):
        """开启代理客户端"""
        try:
            self.local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.local_socket.bind((self.local_host, self.local_port))
            self.local_socket.listen(5)
            logger.info(f"Client proxy listening on {self.local_host}:{self.local_port}")

            while self.running:
                try:
                    client_sock, client_addr = self.local_socket.accept()
                    logger.info(f"New client connection from {client_addr}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_sock, client_addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.connections.append(client_thread)
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting client connection: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error starting client proxy: {e}")
        finally:
            self.stop()

    def stop(self):
        """关闭代理客户端"""
        self.running = False
        if hasattr(self, 'local_socket'):
            self.local_socket.close()
        logger.info("Client proxy stopped")

    def handle_client_connection(self, client_sock, client_addr):
        """将客户端收到的连接传输给服务端"""
        server_sock = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.server_host, self.server_port))
            logger.info(f"Connected to server proxy at {self.server_host}:{self.server_port}")
            
            client_to_server = threading.Thread(
                target=self.forward_data, 
                args=(client_sock, server_sock, "client->server")
            )
            server_to_client = threading.Thread(
                target=self.backward_data,
                args=(server_sock, client_sock, "server->client")
            )
            
            client_to_server.daemon = True
            server_to_client.daemon = True
            
            client_to_server.start()
            server_to_client.start()
            
            client_to_server.join()
            server_to_client.join()
            
        except Exception as e:
            logger.error(f"Error handling client connection: {e}")
        finally:
            if server_sock:
                server_sock.close()
            if client_sock:
                client_sock.close()
            logger.info(f"Closed connection from {client_addr}")

    def forward_data(self, src_sock, dst_sock, direction):
        """使用加密将数据从源转发到目标"""
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

    def backward_data(self, src_sock, dst_sock, direction):
        """从源接收加密数据，解密并转发到目的地"""
        try:
            while self.running:
                length_data = src_sock.recv(4)
                if not length_data or len(length_data) < 4:
                    logger.info(f"{direction}: Connection closed by peer")
                    break
                
                length = int.from_bytes(length_data, 'big')
                
                packet = b''
                remaining = length
                while remaining > 0:
                    chunk = src_sock.recv(remaining)
                    if not chunk:
                        raise Exception("Connection closed while reading packet")
                    packet += chunk
                    remaining -= len(chunk)
                
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

def main():
    parser = argparse.ArgumentParser(description='加密代理客户端')
    parser.add_argument('--local-host', default='127.0.0.1', help='监听的本地地址')
    parser.add_argument('--local-port', type=int, default=8443, help='监听的本地端口')
    parser.add_argument('--server-host', required=True, help='服务器地址')
    parser.add_argument('--server-port', type=int, default=9443, help='服务器端口)
    parser.add_argument('--key', default=None, help='加密密钥')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) != 32:
            parser.error("Key must be 32 bytes (64 hex characters)")
    else:
        key = os.urandom(32)
        logger.info(f"Generated random key: {key.hex()}")
    
    proxy = ClientProxy(args.local_host, args.local_port, args.server_host, args.server_port, key)
    
    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        proxy.stop()

if __name__ == "__main__":
    main()

