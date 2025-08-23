#!/usr/bin/env python3
# generate_key.py - Generate a shared key for the TLS masking proxie
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description='Generate a shared key for TLS masking proxies')
    parser.add_argument('--output', '-o', help='Output file (optional)')
    
    args = parser.parse_args()
    
    key = os.urandom(32)
    key_hex = key.hex()
    
    print(f"Generated key: {key_hex}")
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(key_hex)
        print(f"密钥已写入 {args.output}")
    
    print("\n使用指导:")
    print(f"  1. 开启代理服务器: python server_proxy.py --key {key_hex} --listen-port 9443")
    print(f"  2. 开启代理客户端: python client_proxy.py --server-host <remote_server_ip> --server-port 9443 --local-port 8443 --key {key_hex}")

if __name__ == "__main__":
    main()
