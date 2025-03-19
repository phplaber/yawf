"""
Fastjson 探针
检测到使用 Fastjson 后，再通过 rce payload 确认漏洞是否存在（目前只检测目标是否使用 Fastjson，暂不支持验证漏洞是否存在）
漏洞知识: https://paper.seebug.org/1192/
"""

import sys
import time
import random

from utils.constants import MARK_POINT
from utils.utils import get_random_str, send_request, get_content_type
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    """
    场景1: GET xxx.php?foo={"a":"b","c":"d"}&bar={"aa":"bb"}
    参数 foo 和 bar 各自执行一次 fastjson 探针

    场景2: POST {"a":"b","c":"d"}
    只执行一次 fastjson 探针
    """
    is_run = False
    for k, v in probe_ins.request['params'].items():
        if get_content_type(v) == 'json' and MARK_POINT in v and not probe_ins.direct_use_payload_flag['params'].get(k):
            is_run = True
            break

    if probe_ins.content_type == 'json':
        if MARK_POINT in str(probe_ins.request['data']) and not probe_ins.direct_use_payload_flag['data']:
            is_run = True

    if not is_run:
        print("[*] Fastjson detection skipped")
        return 
        
    vulnerable = False
    try:
        domain = f"{get_random_str(6)}.{probe_ins.oob_detector.domain}"
        for payload in probe_ins.probes_payload['fastjson']:
            payload = payload.replace('domain', domain)
            payload_request = probe_ins.gen_payload_request(payload, False, True)
            _ = send_request(payload_request)
            time.sleep(random.random())

            records = probe_ins.oob_detector.pull_logs(domain[:6])
            if records and domain in str(records):
                vulnerable = True

            if vulnerable:
                print("[+] Found Fastjson!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'Fastjson'
                })
                break

        if not vulnerable:
            print("[-] Not Found Fastjson.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:fastjson) {e}:{exc_tb.tb_lineno}")
