# -*- coding: utf-8 -*-

import os
import re
import copy
import random
import time
from utils.shared import Shared
from utils.constants import *
from utils.utils import *
from urllib.parse import quote

class Prober:
    def __init__(self, request, need_dnslog=False):
        self.request = request
        self.base_request = Shared.base_response.request
        self.base_response = Shared.base_response.response
        if need_dnslog:
            self.req_session = requests.session()
            req = self.req_session.get("http://www.dnslog.cn/getdomain.php", proxies=self.request['proxies'], timeout=30)
            self.dnslog_domain = req.text
        self.dictpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dict')

    def pull_dnslog_records(self):
        """
        拉取 dnslog.cn 记录
        """

        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", proxies=self.request['proxies'], timeout=30)

        return req.json()

    def gen_payload_request(self, payload, reserve_original_params=False, need_dnslog=False):
        """
        生成带 payload 的 request 对象
        """

        payload_request = copy.deepcopy(self.request)
        for k, v in payload_request.items():
            if k == 'url' and MARK_POINT in v:
                if not reserve_original_params:
                    payload_request['url'] = v.replace(MARK_POINT, payload)
                else:
                    tail_index = v.index(MARK_POINT) + len(MARK_POINT) - len(v)
                    payload_request['url'] = self.base_request['url'][:tail_index] + payload + self.base_request['url'][tail_index:] if tail_index else self.base_request['url'] + payload
                break
            elif k in ['data', 'cookies'] and v:
                flag = False
                for kk, vv in v.items():
                    if vv == MARK_POINT:
                        if k == 'data' and need_dnslog:
                            payload_request['data'] = payload
                        else:
                            payload_request[k][kk] = payload if not reserve_original_params else self.base_request[k][kk] + payload
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

                    if vulnerable:
                        print("[+] Found XSS!")
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
            print("[*] {}".format(e))

    def sqli(self):
        """
        SQLI 漏洞探测器
        """

        vulnerable = False
        try:
            sqli_payloads = parse_dict(os.path.join(self.dictpath, 'sqli.txt'))
            for payload in sqli_payloads:
                payload_request = self.gen_payload_request(payload, True)
                poc_rsp = send_request(payload_request)

                # 基于报错判断漏洞是否存在
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, self.base_response, re.I):
                        vulnerable = True
                        break
                
                # 基于内容相似度判断漏洞是否存在
                if similar(self.base_response, poc_rsp.response) > 0.8:
                    vulnerable = True

                if vulnerable:
                    print("[+] Found SQL Injection!")
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
            print("[*] {}".format(e))

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

                if vulnerable:
                    print("[+] Found Directory Traversal!")
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

    def rce_fastjson(self):
        """
        Fastjson RCE 漏洞探测器
        """
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(5)), self.dnslog_domain)
            fastjsonrce_payloads = parse_dict(os.path.join(self.dictpath, 'rce_fastjson.txt'))
            for payload in fastjsonrce_payloads:
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload, False, True)
                _ = send_request(payload_request)
                time.sleep(1)
                dnslog_records = self.pull_dnslog_records()
                if dnslog_records:
                    vulnerable = True

                if vulnerable:
                    print("[+] Found Fastjson RCE!")
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'Fastjson RCE'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Fastjson RCE.")
        except Exception as e:
            print("[*] {}".format(e))