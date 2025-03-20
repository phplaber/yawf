"""
JSONP 探针
漏洞知识: https://blog.knownsec.com/2015/03/jsonp_security_technic/
"""

import os
import re
import sys
import copy

from utils.utils import send_request, get_jsonp_keys
from utils.constants import EFFICIENCY_CONF
from core.probe import Probe

def run(probe_ins: Probe) -> None:
    base_request = probe_ins.base_http.get('request')
    regexp = re.compile(r'(?i)callback|jsonp|success|complete|done|function|^cb$|^fn$')
    # 跳过检测的条件：
    # 1. 请求方法不是 GET
    # 2. 参数名中不包含 callback、jsonp 等关键词
    # 3. 响应内容类型不是 json 或 javascript
    if (base_request.get('method') != 'GET' or 
        not any(regexp.search(par) for par in base_request.get('params')) or 
        not any(ct in probe_ins.base_http.get('headers').get('content-type') for ct in ['json', 'javascript'])):
        print("[*] JSONP detection skipped")
        return
    
    try:
        sens_info_keywords = EFFICIENCY_CONF.get('sens_info_keywords')

        # 空 referer 测试
        if not base_request.get('headers').get('referer'):
            jsonp = probe_ins.base_http.get('response')
        else:
            empty_referer_request = copy.deepcopy(base_request)
            del empty_referer_request['headers']['referer']
            empty_referer_response = send_request(empty_referer_request)
            jsonp = empty_referer_response.get('response')
        
        # 语义分析，获取 jsonp 中所有的 Literal 和 Identifier key
        jsonp_keys = get_jsonp_keys(jsonp)
        if any(key.lower() in sens_info_keywords for key in jsonp_keys):
            print("[+] Found JSONP information leakage!")
            probe_ins.fuzz_results.put({
                'request': base_request,
                'payload': 'N/A',
                'poc': 'N/A',
                'type': 'JSONP'
            })
        else:
            print("[-] Not Found JSONP information leakage.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:jsonp) {e}:{exc_tb.tb_lineno}")
