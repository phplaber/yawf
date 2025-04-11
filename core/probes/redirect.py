"""
REDIRECT 探针
漏洞知识: https://cwe.mitre.org/data/definitions/601.html
"""

import sys

from utils.utils import send_request
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    if probe_ins.base_http.get('request').get('method') != 'GET' or not probe_ins.is_resource_param():
        print("[*] REDIRECT detection skipped")
        return
        
    vulnerable = False
    try:
        payload = 'localhost'
        payload_request = probe_ins.gen_payload_request(payload)
        response = send_request(payload_request, True)
        if response.get('status') in [301, 302, 307, 308] and payload in response.get('headers').get('location'):
            vulnerable = True

        if vulnerable:
            print("[+] Found REDIRECT!")
            probe_ins.fuzz_results.put({
                'request': probe_ins.request,
                'payload': payload,
                'poc': payload_request,
                'type': 'REDIRECT'
            })
        else:
            print("[-] Not Found REDIRECT.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:redirect) {e}:{exc_tb.tb_lineno}")
