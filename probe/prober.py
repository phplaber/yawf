# -*- coding: utf-8 -*-

import re
import copy
import time
import requests
from utils.shared import Shared
from utils.constants import MARK_POINT, DBMS_ERRORS
from utils.utils import get_random_str

class Dnslog:
    def __init__(self, proxies=None):
        self.proxies = proxies
        self.req_session = requests.session()
        req = self.req_session.get("http://www.dnslog.cn/getdomain.php", proxies=self.proxies, timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", proxies=self.proxies, timeout=30)

        return req.json()

class Prober:
    def __init__(self, request):
        self.request = request
        self.base_request = Shared.base_response.request
        self.base_response = Shared.base_response.response
        self.dnslog = Shared.dnslog

    def gen_payload_request(self, payload, reserve_original_params=False, direct_use_payload=False):
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
                if type(v) is str:
                    if MARK_POINT in v:
                        payload_request['data'] = v.replace(MARK_POINT, payload)
                        break
                else:
                    flag = False
                    for kk, vv in v.items():
                        if vv == MARK_POINT:
                            if k == 'data' and direct_use_payload:
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
        XSS 探针
        漏洞知识: https://portswigger.net/web-security/cross-site-scripting
        """
        
        vulnerable = False
        try:
            rsp = send_request(self.request)
            if MARK_POINT in rsp.response:
                for payload in Shared.probes_dict['xss']:
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
            print("[*] (probe:xss) {}".format(e))

    def sqli(self):
        """
        SQLI 探针
        漏洞知识: https://portswigger.net/web-security/sql-injection
        """

        vulnerable = False
        try:
            for payload in Shared.probes_dict['sqli']:
                payload_request = self.gen_payload_request(payload, True)
                poc_rsp = send_request(payload_request)

                # 基于报错判断
                for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                    if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, self.base_response, re.I):
                        vulnerable = True
                        break
                
                # 基于内容相似度判断
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
            print("[*] (probe:sqli) {}".format(e))

    def dt(self):
        """
        DT 探针
        漏洞知识: https://portswigger.net/web-security/file-path-traversal
        """

        vulnerable = False
        try:
            for payload in Shared.probes_dict['dt']:
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
            print("[*] (probe:dt) {}".format(e))

    def rce_fastjson(self):
        """
        Fastjson RCE 探针
        漏洞知识: https://xz.aliyun.com/t/8979
        """
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_dict['rce_fastjson']:
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload, False, True)
                _ = send_request(payload_request)
                time.sleep(1)

                dnslog_records = self.dnslog.pull_logs()
                if dnslog_records and dnslog_domain in str(dnslog_records):
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
            print("[*] (probe:rce_fastjson) {}".format(e))
    
    def rce_log4j(self):
        """
        Log4j RCE 探针
        漏洞知识: https://www.anquanke.com/post/id/263325
        """
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_dict['rce_log4j']:
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload)
                _ = send_request(payload_request)
                time.sleep(1)

                dnslog_records = self.dnslog.pull_logs()
                if dnslog_records and dnslog_domain in str(dnslog_records):
                    vulnerable = True

                if vulnerable:
                    print("[+] Found Log4j RCE!")
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'Log4j RCE'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Log4j RCE.")
        except Exception as e:
            print("[*] (probe:rce_log4j) {}".format(e))

    def xxe(self):
        """
        XXE 探针
        漏洞知识: https://portswigger.net/web-security/xxe
        """

        if type(self.base_request['data']) is not str:
            print("[*] XXE detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_dict['xxe']:
                payload_request = self.gen_payload_request('&xxe;')
                if 'dnslog' not in payload:
                    # 有回显
                    payload_request['data'] = payload_request['data'].replace('?>', '?>'+payload)
                    poc_rsp = send_request(payload_request)

                    if 'root:' in poc_rsp.response or 'boot loader' in poc_rsp.response:
                        vulnerable = True
                else:
                    # 无回显
                    payload = payload.replace('dnslog', dnslog_domain)
                    payload_request['data'] = payload_request['data'].replace('?>', '?>'+payload)
                    _ = send_request(payload_request)
                    time.sleep(1)

                    dnslog_records = self.dnslog.pull_logs()
                    if dnslog_records and dnslog_domain in str(dnslog_records):
                        vulnerable = True

                if vulnerable:
                    print("[+] Found XXE!")
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'XXE'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found XXE.")
        except Exception as e:
            print("[*] (probe:xxe) {}".format(e))