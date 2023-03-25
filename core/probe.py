# -*- coding: utf-8 -*-

import re
import copy
import json
import random
import time
import requests
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException, NoAlertPresentException
from utils.constants import MARK_POINT, DBMS_ERRORS, DIFF_THRESHOLD
from utils.utils import get_random_str, send_request, similar
from bs4 import BeautifulSoup

class Browser:
    def __init__(self, proxies, user_agent):
        options = webdriver.ChromeOptions()
        # 以 headless 模式运行 Chrome
        options.add_argument('--headless')
        # 仅 Windows 上运行有效
        options.add_argument('--disable-gpu')
        # 仅 Docker 上运行有效
        options.add_argument('--no-sandbox')
        # 在内存资源有限的环境中运行需要
        options.add_argument('--disable-dev-shm-usage')
        # 禁用扩展程序
        options.add_argument('--disable-extensions')
        # 设置 user-agent
        options.add_argument('user-agent={}'.format(user_agent))
        # 设置网络代理
        if proxies:
            options.add_argument('--proxy-server={}'.format(proxies['http']))
        # 忽略证书错误
        options.add_argument('--ignore-ssl-errors=yes')
        options.add_argument('--ignore-certificate-errors')
        # 忽略 DevTools 监听 ws 信息
        options.add_experimental_option('excludeSwitches', ['enable-logging'])

        self.options = options

    def run(self):
        return webdriver.Chrome(options=self.options)

class Dnslog:
    def __init__(self, proxies, timeout):
        self.proxies = proxies
        self.timeout = timeout
        self.req_session = requests.Session()
        req = self.req_session.get("http://www.dnslog.cn/getdomain.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )
        self.domain = req.text

    def pull_logs(self, _):
        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json()

class Ceye:
    def __init__(self, proxies, timeout, id, token):
        self.proxies = proxies
        self.timeout = timeout
        
        self.domain = id
        self.token  = token

    def pull_logs(self, filter):
        req = requests.get("http://api.ceye.io/v1/records?token={}&type=dns&filter={}".format(self.token, filter), 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json().get('data')

class Probe:
    def __init__(self, request, browser, content_type, platform, base_http, probes_payload, dnslog, fuzz_results, flag):
        self.request = request
        self.browser = browser
        self.content_type = content_type
        self.platform = platform
        self.base_http = base_http
        self.probes_payload = probes_payload
        self.dnslog = dnslog
        self.fuzz_results = fuzz_results
        self.direct_use_payload_flag = flag

    def gen_payload_request(self, payload, reserve_original_params=False, direct_use_payload=False):
        """
        生成带 payload 的 request 对象
        reserve_original_params：是否保留原始参数值，默认 False。用于 sqli 探针
        direct_use_payload：直接使用 payload，默认 False。用于 fastjson 探针，减少重复测试
        """

        payload_request = copy.deepcopy(self.request)
        for k, v in payload_request.items():
            if k not in ['params', 'data', 'cookies']:
                continue
            if type(v) is str:
                # data 为 xml 编码数据
                if MARK_POINT in v:
                    payload_request[k] = v.replace(MARK_POINT, payload)
                    break
            else:
                flag = False
                for kk, vv in v.items():
                    if type(vv) is str and MARK_POINT in vv:
                        if not direct_use_payload:
                            if not payload_request['url_json_flag']:
                                if not reserve_original_params:
                                    payload_request[k][kk] = payload
                                else:
                                    payload_request[k][kk] = str(self.base_http.get('request')[k][kk]) + payload
                            else:
                                # 标记点在查询字符串 json 中
                                val_dict = json.loads(payload_request[k][kk])
                                base_val_dict = json.loads(self.base_http.get('request')[k][kk])
                                for kkk, vvv in val_dict.items():
                                    if type(vvv) is str and MARK_POINT in vvv:
                                        if not reserve_original_params:
                                            base_val_dict[kkk] = payload
                                        else:
                                            base_val_dict[kkk] = str(base_val_dict[kkk]) + payload
                                        payload_request[k][kk] = json.dumps(base_val_dict)
                                        break
                        else:
                            # 直接使用 payload 替代查询字符串参数值或 post body
                            if k == 'params':
                                payload_request[k][kk] = payload
                                self.direct_use_payload_flag[k][kk] = True
                            elif k == 'data':
                                payload_request[k] = payload
                                self.direct_use_payload_flag[k] = True
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

        # 只在 GET 请求时，执行 xss 探针
        # 因而 xss 探针更有可能检测到反射型 XSS 和 DOM XSS
        if self.request['method'] == 'POST':
            print("[*] XSS detection skipped")
            return 
        
        vulnerable = False
        try:
            for payload in self.probes_payload['xss']:
                no_alert = False
                alert_text = ''
                # 使用 AngularJS payload，页面需使用 AngularJS 指令
                if '{{' in payload and 'ng-app' not in self.base_http.get('response'):
                    continue
                payload_request = self.gen_payload_request(payload)
                
                query_list = ['{}={}'.format(par, val) for par, val in payload_request['params'].items()] if payload_request['params'] else []
                url = payload_request['url'] + '?' + '&'.join(query_list) if query_list else payload_request['url']
                
                # 添加 cookie
                if payload_request['cookies']:
                    for n, v in payload_request['cookies'].items():
                        self.browser.add_cookie({'name': n, 'value': v})

                # 添加额外的 header
                self.browser.execute_cdp_cmd('Network.setExtraHTTPHeaders', {'headers': payload_request['headers']})

                # 加载页面
                self.browser.get(url)
                time.sleep(random.random())
                try:
                    # 在切换执行 alert 前，等待 3 秒
                    WebDriverWait(self.browser, 3).until(EC.alert_is_present())
                    try:
                        alert = self.browser.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                    except NoAlertPresentException:
                        no_alert = True
                        
                    if not no_alert and alert_text == '1':
                        vulnerable = True
                except TimeoutException:
                    pass

                if vulnerable:
                    print("[+] Found XSS!")
                    self.fuzz_results.put({
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

        # 某些测试点不影响程序执行，无论怎么改变其值，页面内容都不会发生变化。
        # 需提前识别出这些测试点，减少误报。
        is_html = True
        invalid_mark_point = False
        test_rsp = send_request(self.gen_payload_request(get_random_str(10)))
        if test_rsp.get('response') is None:
            return 

        # 如果响应体为 HTML，则比较文本内容，否则，直接比较
        if 'text/html' in self.base_http.get('headers').get('content-type'):
            base_rsp_body = BeautifulSoup(self.base_http.get('response'), "html.parser").get_text()
            test_rsp_body = BeautifulSoup(test_rsp.get('response'), "html.parser").get_text()
        else:
            is_html = False
            base_rsp_body = self.base_http.get('response')
            test_rsp_body = test_rsp.get('response')

        if similar(base_rsp_body, test_rsp_body) > DIFF_THRESHOLD:
            invalid_mark_point = True

        if invalid_mark_point \
                or (self.content_type == 'xml' and MARK_POINT in self.request['data']):
            print("[*] SQLI detection skipped")
            return 

        vulnerable = False
        try:
            for payload in self.probes_payload['sqli']:
                payload_request = self.gen_payload_request(payload, True)
                poc_rsp = send_request(payload_request)
                time.sleep(random.random())

                if not poc_rsp.get('response'):
                    continue

                if 'and' not in payload:
                    # 基于报错判断
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, poc_rsp.get('response'), re.I) and not re.search(regex, self.base_http.get('response'), re.I):
                            vulnerable = True
                            break
                else:
                    # 基于内容相似度判断
                    poc_rsp_body = BeautifulSoup(poc_rsp.get('response'), "html.parser").get_text() if is_html else poc_rsp.get('response')
                    
                    if similar(base_rsp_body, poc_rsp_body) > DIFF_THRESHOLD:
                        # 参数可能被消杀（如整数化）处理，使用反向 payload 再确认一遍
                        reverse_payload_request = self.gen_payload_request(payload.replace('1','0') if '=' not in payload else payload.replace('1','0',1), True)
                        reverse_poc_rsp = send_request(reverse_payload_request)
                        if reverse_poc_rsp.get('response'):
                            reverse_rsp_body = BeautifulSoup(reverse_poc_rsp.get('response'), "html.parser").get_text() if is_html else reverse_poc_rsp.get('response')
                            
                            if similar(base_rsp_body, reverse_rsp_body) < DIFF_THRESHOLD:
                                vulnerable = True

                if vulnerable:
                    print("[+] Found SQL Injection!")
                    self.fuzz_results.put({
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

        if (self.content_type == 'xml' and MARK_POINT in self.request['data']) \
                or not self.request['dt_and_ssrf_detect_flag']:
            print("[*] DT detection skipped")
            return 

        vulnerable = False
        try:
            for payload in self.probes_payload['dt']:
                # 将 payload 中的占位符 filepath 替换为平台特定文件
                payload = payload.replace('filepath', '/boot.ini') \
                    if self.platform == 'windows' \
                    else payload.replace('filepath', '/etc/passwd')
                
                payload_request = self.gen_payload_request(payload)
                poc_rsp = send_request(payload_request)
                time.sleep(random.random())
                if poc_rsp.get('response') and ('root:' in poc_rsp.get('response') or 'boot loader' in poc_rsp.get('response')):
                    vulnerable = True

                if vulnerable:
                    print("[+] Found Directory Traversal!")
                    self.fuzz_results.put({
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

    def fastjson(self):
        """
        Fastjson 探针
        检测到使用 Fastjson 后，再通过 rce payload 确认漏洞是否存在
        （目前只检测目标是否使用 Fastjson，暂不支持验证漏洞是否存在）
        漏洞知识: https://paper.seebug.org/1192/
        """

        # 确保针对查询字符串和 POST Body 中 json 多值标记只执行一次 fastjson 探针
        is_run = False
        if self.request['url_json_flag']:
            for k, v in self.request['params'].items():
                if MARK_POINT in v and not self.direct_use_payload_flag['params'].get(k):
                    is_run = True

        if self.content_type == 'json':
            if MARK_POINT in str(self.request['data']) and not self.direct_use_payload_flag['data']:
                is_run = True

        if not is_run:
            print("[*] Fastjson detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(6), self.dnslog.domain)
            for payload in self.probes_payload['fastjson']:
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload, False, True)
                _ = send_request(payload_request)
                time.sleep(random.random())

                dnslog_records = self.dnslog.pull_logs(dnslog_domain[:-3])
                if dnslog_records and dnslog_domain in str(dnslog_records):
                    vulnerable = True

                if vulnerable:
                    print("[+] Found Fastjson!")
                    self.fuzz_results.put({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'Fastjson'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Fastjson.")
        except Exception as e:
            print("[*] (probe:fastjson) {}".format(e))
    
    def log4shell(self):
        """
        Log4Shell 探针
        漏洞知识: https://www.anquanke.com/post/id/263325
        """
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(6), self.dnslog.domain)
            for payload in self.probes_payload['log4shell']:
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload)
                _ = send_request(payload_request)
                time.sleep(random.random())

                dnslog_records = self.dnslog.pull_logs(dnslog_domain[:-3])
                if dnslog_records and dnslog_domain in str(dnslog_records):
                    vulnerable = True

                if vulnerable:
                    print("[+] Found Log4Shell!")
                    self.fuzz_results.put({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'Log4Shell'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Log4Shell.")
        except Exception as e:
            print("[*] (probe:log4shell) {}".format(e))

    def xxe(self):
        """
        XXE 探针
        漏洞知识: https://portswigger.net/web-security/xxe
        """

        if self.content_type != 'xml' \
                or (self.content_type == 'xml' and MARK_POINT not in self.request['data']):
            print("[*] XXE detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(6), self.dnslog.domain)
            for payload in self.probes_payload['xxe']:
                # 将 payload 中的占位符 filepath 替换为平台特定文件
                payload = payload.replace('filepath', '/c:/boot.ini') \
                    if self.platform == 'windows' \
                    else payload.replace('filepath', '/etc/passwd')
                # 将 payload 中的占位符 dnslog 替换为 dnslog 子域名
                payload = payload.replace('dnslog', dnslog_domain)

                payload_request = self.gen_payload_request('&xxe;')
                if '?>' in payload_request['data']:
                    payload_request['data'] = payload_request['data'].replace('?>', '?>'+payload)
                else:
                    payload_request['data'] = payload + payload_request['data']
                if 'http' not in payload:
                    # 有回显
                    poc_rsp = send_request(payload_request)
                    time.sleep(random.random())

                    if poc_rsp.get('response') and ('root:' in poc_rsp.get('response') or 'boot loader' in poc_rsp.get('response')):
                        vulnerable = True
                else:
                    # 无回显
                    _ = send_request(payload_request)
                    time.sleep(random.random())

                    dnslog_records = self.dnslog.pull_logs(dnslog_domain[:-3])
                    if dnslog_records and dnslog_domain in str(dnslog_records):
                        vulnerable = True

                if vulnerable:
                    print("[+] Found XXE!")
                    self.fuzz_results.put({
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

    def ssrf(self):
        """
        SSRF 探针
        漏洞知识: https://portswigger.net/web-security/ssrf
        """

        if (self.content_type == 'xml' and MARK_POINT in self.request['data']) \
                or not self.request['dt_and_ssrf_detect_flag']:
            print("[*] SSRF detection skipped")
            return 
        
        vulnerable = False
        try:
            dnslog_domain = "{}.{}".format(get_random_str(6), self.dnslog.domain)
            for payload in self.probes_payload['ssrf']:
                # 无回显
                payload = payload.replace('dnslog', dnslog_domain)
                payload_request = self.gen_payload_request(payload)
                _ = send_request(payload_request)
                time.sleep(random.random())

                dnslog_records = self.dnslog.pull_logs(dnslog_domain[:-3])
                if dnslog_records and dnslog_domain in str(dnslog_records):
                    vulnerable = True

                if vulnerable:
                    print("[+] Found SSRF!")
                    self.fuzz_results.put({
                        'request': self.request,
                        'payload': payload,
                        'poc': payload_request,
                        'type': 'SSRF'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found SSRF.")
        except Exception as e:
            print("[*] (probe:ssrf) {}".format(e))
