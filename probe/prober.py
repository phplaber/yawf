# -*- coding: utf-8 -*-

import os
import re
import copy
from utils.shared import Shared
from utils.constants import *
from utils.utils import *

class Prober:
    def __init__(self, request):
        self.request = request
        self.dictpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dict')

    def gen_payload_request(self, payload):
        """
        生成带 payload 的 request 对象
        """
        payload_request = copy.deepcopy(self.request)
        for k, v in payload_request.items():
            if k in ['url', 'data', 'cookies']:
                if k == 'url':
                    if MARK_POINT in v:
                        payload_request[k] = v.replace(MARK_POINT, payload)
                        break
                else:
                    if v:
                        flag = False
                        for kk, vv in v.items():
                            if MARK_POINT in vv:
                                payload_request[k][kk] = vv.replace(MARK_POINT, payload)
                                flag = True
                                break
                        if flag:
                            break
        
        return payload_request

    def xss(self):
        """
        XSS 漏洞探测器
        """
        
        vulnerable = False
        try:
            rsp = send_request(self.request)
            if MARK_POINT in rsp.response:
                xss_payloads = parse_dict(os.path.join(self.dictpath, 'xss.txt'))
                for payload in xss_payloads:
                    payload_request = self.gen_payload_request(payload)
                    poc_rsp = send_request(payload_request)
                    if payload in poc_rsp.response:
                        vulnerable = True
                        print("[+] Found XSS! Vulnerable request is: {}".format(payload_request))

                    if vulnerable:
                        Shared.fuzz_results.append({
                            'request': self.request,
                            'payload': payload,
                            'poc': payload_request,
                            'type': 'XSS'
                        })
                        break
            
            if not vulnerable:
                print("[-] Not Found XSS.")
        except Exception as e:
            pass

    def sqli(self):
        """
        SQLI 漏洞探测器
        """

        vulnerable = False
        try:
            base_http_response = Shared.base_response.response

            sqli_payloads = parse_dict(os.path.join(self.dictpath, 'sqli.txt'))
            for payload in sqli_payloads:
                payload_request = self.gen_payload_request(payload)
                poc_rsp = send_request(payload_request)

                # 基于报错判断漏洞是否存在
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, base_http_response, re.I):
                        vulnerable = True
                        print("[+] Found SQL Injection! Vulnerable request is: {}".format(payload_request))
                        break

                if vulnerable:
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'SQL Injection'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found SQL Injection.")
        except Exception as e:
            pass

    def dt(self):
        """
        DT 漏洞探测器
        """

        vulnerable = False
        try:
            dt_payloads = parse_dict(os.path.join(self.dictpath, 'dt.txt'))
            for payload in dt_payloads:
                payload_request = self.gen_payload_request(payload)
                poc_rsp = send_request(payload_request)

                if 'root:' in poc_rsp.response or 'boot loader' in poc_rsp.response:
                    vulnerable = True
                    print("[+] Found Directory Traversal! Vulnerable request is: {}".format(payload_request))

                if vulnerable:
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'Directory Traversal'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Directory Traversal.")
        except Exception as e:
            pass