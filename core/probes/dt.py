"""
DT 探针
漏洞知识: https://portswigger.net/web-security/file-path-traversal
"""

import os
import sys

from utils.utils import send_request
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    if not probe_ins.is_resource_param():
        print("[*] DT detection skipped")
        return

    vulnerable = False
    try:
        for payload in probe_ins.probes_payload['dt']:
            # 将 payload 中的占位符 filepath 替换为平台特定文件
            payload = payload.replace('filepath', '/boot.ini' if os.environ['platform'] == 'windows' else '/etc/passwd')
                
            payload_request = probe_ins.gen_payload_request(payload)
            poc_rsp = send_request(payload_request)
            if poc_rsp.get('response') and any(kw in poc_rsp.get('response', '') for kw in ['root:', 'boot loader']):
                vulnerable = True

            if vulnerable:
                print("[+] Found Directory Traversal!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'Directory Traversal'
                })
                break

        if not vulnerable:
            print("[-] Not Found Directory Traversal.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:dt) {e}:{exc_tb.tb_lineno}")
