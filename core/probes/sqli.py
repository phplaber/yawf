"""
SQLI 探针
漏洞知识: https://portswigger.net/web-security/sql-injection
"""

import re
import sys

from bs4 import BeautifulSoup

from utils.constants import DBMS_ERRORS, DIFF_THRESHOLD
from utils.utils import get_random_str, send_request, similar
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    # 某些测试点不影响程序执行，无论怎么改变其值，页面内容都不会发生变化。
    # 需提前识别出这些测试点，减少误报。
    is_html = True
    invalid_mark_point = False
    test_rsp = send_request(probe_ins.gen_payload_request(get_random_str(10)))
    if test_rsp.get('response'):
        # 如果响应体为 HTML，则比较文本内容，否则，直接比较
        if 'text/html' in probe_ins.base_http.get('headers').get('content-type'):
            base_rsp_body = BeautifulSoup(probe_ins.base_http.get('response'), "html.parser").get_text()
            test_rsp_body = BeautifulSoup(test_rsp.get('response'), "html.parser").get_text()
        else:
            is_html = False
            base_rsp_body = probe_ins.base_http.get('response')
            test_rsp_body = test_rsp.get('response')

        if similar(base_rsp_body, test_rsp_body) > DIFF_THRESHOLD:
            invalid_mark_point = True

    if invalid_mark_point:
        print("[*] SQLI detection skipped")
        return 

    vulnerable = False
    try:
        for payload in probe_ins.probes_payload['sqli']:
            payload_request = probe_ins.gen_payload_request(payload, True)
            poc_rsp = send_request(payload_request)

            if not poc_rsp.get('response'):
                continue

            if 'and' not in payload:
                # 基于报错判断
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if re.search(regex, poc_rsp.get('response'), re.I) and not re.search(regex, probe_ins.base_http.get('response'), re.I):
                        vulnerable = True
                        break
            else:
                # 基于内容相似度判断
                poc_rsp_body = BeautifulSoup(poc_rsp.get('response'), "html.parser").get_text() if is_html else poc_rsp.get('response')
                if similar(base_rsp_body, poc_rsp_body) > DIFF_THRESHOLD:
                    # 参数可能被消杀（如整数化）处理，使用反向 payload 再确认一遍
                    reverse_payload_request = probe_ins.gen_payload_request(payload.replace('1','0') if '=' not in payload else payload.replace('1','0',1), True)
                    reverse_poc_rsp = send_request(reverse_payload_request)
                    if reverse_poc_rsp.get('response'):
                        reverse_rsp_body = BeautifulSoup(reverse_poc_rsp.get('response'), "html.parser").get_text() if is_html else reverse_poc_rsp.get('response')
                        # 一般来说，如果漏洞存在，取反后内容差异更大
                        if similar(base_rsp_body, reverse_rsp_body) < DIFF_THRESHOLD * 0.8:
                            vulnerable = True

            if vulnerable:
                print("[+] Found SQL Injection!")
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'SQL Injection'
                })
                break

        if not vulnerable:
            print("[-] Not Found SQL Injection.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:sqli) {e}:{exc_tb.tb_lineno}")
