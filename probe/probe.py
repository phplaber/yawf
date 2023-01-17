# -*- coding: utf-8 -*-

import re
import copy
import time
import requests
from selenium import webdriver
from utils.shared import Shared
from utils.constants import MARK_POINT, DBMS_ERRORS
from utils.utils import get_random_str, send_request, similar

class DetectWaf:
    def __init__(self):
        pass

    def detect(self, response):
        rsp = response.response
        headers = response.headers
        status = response.status

        # 请求失败，直接返回
        if status is None:
            return 

        # 阿里云盾
        if status == 405:
            detection_schema = (
                re.compile(r"error(s)?.aliyun(dun)?.(com|net)", re.I),
                re.compile(r"http(s)?://(www.)?aliyun.(com|net)", re.I)
            )
            for detection in detection_schema:
                if detection.search(rsp):
                    return 'AliYunDun'

        # 云加速
        detection_schema = (
            re.compile(r"fh(l)?", re.I),
            re.compile(r"yunjiasu.nginx", re.I)
        )
        for detection in detection_schema:
            if detection.search(headers.get('x-server', '')) or detection.search(headers.get('server', '')):
                return 'Yunjiasu'

        # 安全狗
        detection_schema = (
            re.compile(r"(http(s)?)?(://)?(www|404|bbs|\w+)?.safedog.\w", re.I),
            re.compile(r"waf(.?\d+.?\d+)", re.I),
        )
        for detection in detection_schema:
            if detection.search(rsp) or detection.search(headers.get('x-powered-by', '')):
                return 'SafeDog'

        # 加速乐
        detection_schema = (
            re.compile(r"^jsl(_)?tracking", re.I),
            re.compile(r"(__)?jsluid(=)?", re.I),
            re.compile(r"notice.jiasule", re.I),
            re.compile(r"(static|www|dynamic).jiasule.(com|net)", re.I)
        )
        for detection in detection_schema:
            set_cookie = headers.get('set-cookie', '')
            server = headers.get('server', '')
            if any(detection.search(item) for item in [set_cookie, server]) or detection.search(rsp):
                return 'Jiasule'
            
        # CloudFlare
        detection_schemas = (
            re.compile(r"cloudflare.ray.id.|var.cloudflare.", re.I),
            re.compile(r"cloudflare.nginx", re.I),
            re.compile(r"..cfduid=([a-z0-9]{43})?", re.I),
            re.compile(r"cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?", re.I),
            re.compile(r".>attention.required!.\|.cloudflare<.+", re.I),
            re.compile(r"http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?", re.I),
            re.compile(r"ray.id", re.I)
        )
        server = headers.get('server', '')
        cookie = headers.get('cookie', '')
        set_cookie = headers.get('set-cookie', '')
        cf_ray = headers.get('cf-ray', '')
        expect_ct = headers.get('expect-ct', '')
        if cf_ray or "__cfduid" in set_cookie or "cloudflare" in expect_ct:
            return 'CloudFlare'
        for detection in detection_schemas:
            if detection.search(rsp) \
                    or detection.search(server) \
                    or detection.search(cookie) \
                    or detection.search(set_cookie) \
                    or detection.search(expect_ct):
                return 'CloudFlare'
        
        return 

class Webdriver:
    def __init__(self):
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        self.driver = webdriver.Chrome(options=options)

class Dnslog:
    def __init__(self, proxies=None):
        self.proxies = proxies
        self.req_session = requests.session()
        req = self.req_session.get("http://www.dnslog.cn/getdomain.php", proxies=self.proxies, timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", proxies=self.proxies, timeout=30)

        return req.json()

class Probe:
    def __init__(self, request):
        self.request = request
        self.base_request = Shared.base_response.request
        self.base_response = Shared.base_response.response
        self.dnslog = Shared.dnslog
        self.web_driver = Shared.web_driver

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
                if k == 'data' and type(v) is str:
                    # post body 为 xml 的场景，仅检测 xxe 和 fastjson rce
                    if MARK_POINT in v :
                        if direct_use_payload:
                            # 直接使用 payload 的 POST 请求，只需测试一次
                            payload_request['data'] = payload
                            Shared.direct_use_payload_flag = True
                        else:
                            payload_request['data'] = v.replace(MARK_POINT, payload)
                        break
                else:
                    flag = False
                    for kk, vv in v.items():
                        if vv == MARK_POINT:
                            if k == 'data' and direct_use_payload:
                                payload_request['data'] = payload
                                Shared.direct_use_payload_flag = True
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

        if type(self.base_request['data']) is str and MARK_POINT in self.base_request['data']:
            print("[*] XSS detection skipped")
            return 
        
        vulnerable = False
        try:
            rsp = send_request(self.request)
            if rsp.response and MARK_POINT in rsp.response:
                for payload in Shared.probes_payload['xss']:
                    payload_request = self.gen_payload_request(payload)
                    poc_rsp = send_request(payload_request)

                    if not poc_rsp.response:
                        continue
                    
                    self.web_driver.get(url=payload_request['url'])
                    # 检查页面上是否有弹出的 XSS 警告框
                    try:
                        alert = self.web_driver.switch_to.alert
                        vulnerable = True
                        alert.accept()
                    except:
                        pass

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

        if type(self.base_request['data']) is str and MARK_POINT in self.base_request['data']:
            print("[*] SQLI detection skipped")
            return 

        vulnerable = False
        try:
            for payload in Shared.probes_payload['sqli']:
                payload_request = self.gen_payload_request(payload, True)
                poc_rsp = send_request(payload_request)

                if not poc_rsp.response:
                    continue

                if 'and' not in payload:
                    # 基于报错判断
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, self.base_response, re.I):
                            vulnerable = True
                            break
                else:
                    # 基于内容相似度判断
                    if similar(self.base_response, poc_rsp.response) > 0.95:
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

        if type(self.base_request['data']) is str and MARK_POINT in self.base_request['data']:
            print("[*] DT detection skipped")
            return 

        vulnerable = False
        try:
            for payload in Shared.probes_payload['dt']:
                if Shared.conf['misc_platform'] and Shared.conf['misc_platform'].lower() == 'windows':
                    # Windows 平台
                    if 'passwd' in payload:
                        continue
                else:
                    # Linux 平台
                    if 'passwd' not in payload:
                        continue
                payload_request = self.gen_payload_request(payload)
                poc_rsp = send_request(payload_request)
                if poc_rsp.response and ('root:' in poc_rsp.response or 'boot loader' in poc_rsp.response):
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

        if Shared.direct_use_payload_flag and MARK_POINT in str(self.base_request['data']):
            print("[*] Fastjson RCE detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_payload['rce_fastjson']:
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

        if type(self.base_request['data']) is str and MARK_POINT in self.base_request['data']:
            print("[*] Log4j RCE detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_payload['rce_log4j']:
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
            for payload in Shared.probes_payload['xxe']:
                payload_request = self.gen_payload_request('&xxe;')
                if 'dnslog' not in payload:
                    # 有回显
                    if Shared.conf['misc_platform'] and Shared.conf['misc_platform'].lower() == 'windows':
                        # Windows 平台
                        if 'passwd' in payload:
                            continue
                    else:
                        # Linux 平台
                        if 'passwd' not in payload:
                            continue
                    payload_request['data'] = payload_request['data'].replace('?>', '?>'+payload)
                    poc_rsp = send_request(payload_request)

                    if poc_rsp.response and ('root:' in poc_rsp.response or 'boot loader' in poc_rsp.response):
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