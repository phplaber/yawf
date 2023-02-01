# -*- coding: utf-8 -*-

import re
import copy
import time
import requests
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException
from utils.shared import Shared
from utils.constants import MARK_POINT, DBMS_ERRORS, DIFF_THRESHOLD
from utils.utils import get_random_str, send_request, similar

class DetectWaf:
    def __init__(self):
        pass

    def detect(self, req_rsp):
        response = req_rsp.get('response')
        headers = req_rsp.get('headers')
        status = req_rsp.get('status')

        # 请求失败，直接返回
        if status is None:
            return 

        # 阿里云盾
        if status == 405:
            # 阻断
            detection_schema = (
                re.compile(r"error(s)?.aliyun(dun)?.(com|net)", re.I),
                re.compile(r"http(s)?://(www.)?aliyun.(com|net)", re.I)
            )
            for detection in detection_schema:
                if detection.search(response):
                    return 'AliYunDun'
        
        elif status == 200:
            # 非阻断，如滑块验证
            detection = re.compile(r"TraceID: [0-9a-z]{30}", re.I)
            if detection.search(response):
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
            if detection.search(response) or detection.search(headers.get('x-powered-by', '')):
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
            if any(detection.search(item) for item in [set_cookie, server]) or detection.search(response):
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
            if detection.search(response) \
                    or detection.search(server) \
                    or detection.search(cookie) \
                    or detection.search(set_cookie) \
                    or detection.search(expect_ct):
                return 'CloudFlare'
        
        return 

class Webdriver:
    def __init__(self):
        options = webdriver.ChromeOptions()
        # 以 headless 模式运行 Chrome
        options.add_argument('--headless')
        # 仅 Windows 上运行有效
        options.add_argument('--disable-gpu')
        # 仅 Docker 上运行有效
        options.add_argument('--no-sandbox')
        # 在内存资源有限的环境中运行需要
        options.add_argument('--disable-dev-shm-usage')
        # 忽略 DevTools 监听 ws 信息
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        self.driver = webdriver.Chrome(options=options)

class Dnslog:
    def __init__(self):
        self.proxies = Shared.base_response.get('request').get('proxies')
        self.timeout = Shared.base_response.get('request').get('timeout')
        self.req_session = requests.session()
        req = self.req_session.get("http://www.dnslog.cn/getdomain.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )
        self.domain = req.text

    def pull_logs(self):
        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json()

class Probe:
    def __init__(self, request):
        self.request = request
        self.base_request = Shared.base_response.get('request')
        self.base_response = Shared.base_response.get('response')
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
                    # post body 为 xml 和 json 类型的场景
                    if MARK_POINT in v :
                        if direct_use_payload:
                            # 直接使用 payload 的 POST 请求（如：检测 fastjson rce），只需测试一次
                            payload_request['data'] = payload
                            Shared.direct_use_payload_flag = True
                        else:
                            payload_request['data'] = v.replace(MARK_POINT, payload)
                        break
                else:
                    flag = False
                    for kk, vv in v.items():
                        if vv == MARK_POINT:
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

        if self.request['url_json_flag'] \
                or (self.request['content_type'] == 'xml' and MARK_POINT in self.request['data']):
            print("[*] XSS detection skipped")
            return 
        
        vulnerable = False
        try:
            for payload in Shared.probes_payload['xss']:
                # 使用 AngularJS payload，页面需使用 AngularJS 指令
                if '{{' in payload and 'ng-app' not in self.base_response:
                    continue
                payload_request = self.gen_payload_request(payload.replace('[UI]', ''))
                poc_rsp = send_request(payload_request)

                if not poc_rsp.get('response'):
                    continue
                    
                self.web_driver.get(url=payload_request['url'])
                if '[UI]' not in payload:
                    # 不需要用户交互就能弹框
                    try:
                        # 在切换执行 alert 前，等待 3 秒
                        WebDriverWait(self.web_driver, 3).until (EC.alert_is_present())
                        alert = self.web_driver.switch_to.alert
                        alert.accept()
                        vulnerable = True
                    except TimeoutException:
                        pass
                else:
                    # 需要用户交互才能弹框
                    try:
                        links = self.web_driver.find_elements(By.TAG_NAME, "a")
                        for link in links:
                            if link.get_attribute("href") == payload.replace('[UI]', ''):
                                vulnerable = True
                                break
                    except StaleElementReferenceException:
                        pass

                if vulnerable:
                    print("[+] Found XSS!")
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload.replace('[UI]', ''),
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

        # 某些测试点不影响程序执行，无论怎么改变其值，页面内容都不会发生变化。需提前识别出这些测试点，减少误报。
        test_rsp = send_request(self.gen_payload_request(get_random_str(10)))
        invalid_mark_point = False
        if test_rsp.get('status') is not None and test_rsp.get('status') != Shared.base_response.get('status'):
            invalid_mark_point = False
        elif test_rsp.get('response') is not None and similar(self.base_response, test_rsp.get('response')) > DIFF_THRESHOLD:
            invalid_mark_point = True

        if invalid_mark_point \
                or self.request['url_json_flag'] \
                or (self.request['content_type'] == 'xml' and MARK_POINT in self.request['data']):
            print("[*] SQLI detection skipped")
            return 

        vulnerable = False
        try:
            for payload in Shared.probes_payload['sqli']:
                payload_request = self.gen_payload_request(payload, True)
                poc_rsp = send_request(payload_request)

                if not poc_rsp.get('response'):
                    continue

                if 'and' not in payload:
                    # 基于报错判断
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, poc_rsp.get('response'), re.I) and not re.search(regex, self.base_response, re.I):
                            vulnerable = True
                            break
                else:
                    # 基于内容相似度判断
                    if similar(self.base_response, poc_rsp.get('response')) > DIFF_THRESHOLD:
                        # 参数可能被消杀（如整数化）处理，使用反向 payload 再确认一遍
                        reverse_payload_request = self.gen_payload_request(payload.replace('1','0') if '=' not in payload else payload.replace('1','0',1), True)
                        reverse_poc_rsp = send_request(reverse_payload_request)
                        if reverse_poc_rsp.get('response'):
                            if similar(self.base_response, reverse_poc_rsp.get('response')) < DIFF_THRESHOLD:
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

        if self.request['url_json_flag'] \
                or (self.request['content_type'] == 'xml' and MARK_POINT in self.request['data']) \
                or not self.request['dt_detect_flag']:
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
                if poc_rsp.get('response') and ('root:' in poc_rsp.get('response') or 'boot loader' in poc_rsp.get('response')):
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

        if (self.request['url_json_flag'] \
                or (self.request['content_type'] == 'json' \
                    and MARK_POINT in self.request['data'] \
                    and not Shared.direct_use_payload_flag)) is False:
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

        if self.request['content_type'] != 'xml' \
                or (self.request['content_type'] == 'xml' and MARK_POINT not in self.request['data']):
            print("[*] XXE detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(5), self.dnslog.domain)
            for payload in Shared.probes_payload['xxe']:
                payload_request = self.gen_payload_request('&xxe;')
                payload = payload.replace('dnslog', dnslog_domain)
                if '?>' in payload_request['data']:
                    payload_request['data'] = payload_request['data'].replace('?>', '?>'+payload)
                else:
                    payload_request['data'] = payload + payload_request['data']
                if 'http' not in payload:
                    # 有回显
                    if Shared.conf['misc_platform'] and Shared.conf['misc_platform'].lower() == 'windows':
                        # Windows 平台
                        if 'passwd' in payload:
                            continue
                    else:
                        # Linux 平台
                        if 'passwd' not in payload:
                            continue
                    poc_rsp = send_request(payload_request)

                    if poc_rsp.get('response') and ('root:' in poc_rsp.get('response') or 'boot loader' in poc_rsp.get('response')):
                        vulnerable = True
                else:
                    # 无回显
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