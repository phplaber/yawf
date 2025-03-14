"""
Log4Shell 探针
漏洞知识: https://www.anquanke.com/post/id/263325
"""

import sys
import time
import random

from utils.utils import get_random_str, send_request
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    vulnerable = False
    try:
        domain = f"{get_random_str(6)}.{probe_ins.oob_detector.domain}"
        for payload in probe_ins.probes_payload['log4shell']:
            payload = payload.replace('domain', domain)
            payload_request = probe_ins.gen_payload_request(payload)
            _ = send_request(payload_request)
            time.sleep(random.random())

            records = probe_ins.oob_detector.pull_logs(domain[:6])
            if records and domain in str(records):
                vulnerable = True

            if vulnerable:
                print("[+] Found Log4Shell!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'Log4Shell'
                })
                break

        if not vulnerable:
            print("[-] Not Found Log4Shell.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:log4shell) {e}:{exc_tb.tb_lineno}")
