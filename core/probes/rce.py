"""
RCE 探针
漏洞知识: https://portswigger.net/web-security/os-command-injection
"""

import sys
import time
import random
import os

from utils.utils import get_random_str, send_request
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    vulnerable = False
    try:
        platform = os.environ.get('platform')
        domain = f"{get_random_str(6)}.{probe_ins.oob_detector.domain}"
        for payload in probe_ins.probes_payload.get('rce'):
            payload = payload.replace('option', '-n' if platform == 'windows' else '-c').replace('domain', domain)
            payload_request = probe_ins.gen_payload_request(payload)
            poc_rsp = send_request(payload_request)

            if 'ping' in payload:
                time.sleep(random.random())
                records = probe_ins.oob_detector.pull_logs(domain[:6])
                if records and domain in str(records):
                    vulnerable = True
            else:
                if payload not in poc_rsp.get('response', '') and domain in poc_rsp.get('response', ''):
                    vulnerable = True

            if vulnerable:
                print("[+] Found RCE!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'RCE'
                })
                break

        if not vulnerable:
            print("[-] Not Found RCE.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:rce) {e}:{exc_tb.tb_lineno}")
