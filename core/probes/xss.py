"""
XSS 探针
漏洞知识: https://portswigger.net/web-security/cross-site-scripting
"""

import sys
from urllib.parse import quote, urlparse

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException

from core.probe import Probe

def run(probe_ins: Probe) -> None:
    # 只在 GET 请求时，执行 xss 探针
    # 因而 xss 探针更有可能检测到反射型 XSS 和 DOM XSS
    if probe_ins.request['method'] == 'POST':
        print("[*] XSS detection skipped")
        return 
    
    vulnerable = False
    try:
        # headless chrome 着陆页
        o = urlparse(probe_ins.base_http['request']['url'])
        load_page = f'{o.scheme}://{o.netloc}/robots.txt'
        # 添加请求头（请求头不支持标记）
        probe_ins.browser.execute_cdp_cmd('Network.setExtraHTTPHeaders', {'headers': probe_ins.request['headers']})
        for payload in probe_ins.probes_payload['xss']:
            no_alert = False
            alert_text = ''
            # 使用 AngularJS payload，页面需使用 AngularJS 指令
            if '{{' in payload and 'ng-app' not in probe_ins.base_http.get('response'):
                continue
            payload_request = probe_ins.gen_payload_request(payload)
            
            query_list = [f'{par}={val}' for par, val in payload_request['params'].items()] if payload_request['params'] else []
            url = payload_request['url'] + '?' + '&'.join(query_list) if query_list else payload_request['url']
            
            # 在添加 cookie 前，需导航到目标域名某个页面（不必存在），然后再加载目标页面
            if payload_request['cookies']:
                probe_ins.browser.get(load_page)
                for n, v in payload_request['cookies'].items():
                    probe_ins.browser.add_cookie({'name': n, 'value': quote(v)})
            probe_ins.browser.get(url)

            try:
                # 在切换执行 alert 前，等待 3 秒
                WebDriverWait(probe_ins.browser, 3).until(EC.alert_is_present())
                try:
                    alert = probe_ins.browser.switch_to.alert
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
                probe_ins.fuzz_results.put({
                    'request': probe_ins.request,
                    'payload': payload,
                    'poc': payload_request,
                    'type': 'XSS'
                })
                break
        
        if not vulnerable:
            print("[-] Not Found XSS.")
    except Exception as e:
        _, _, exc_tb = sys.exc_info()
        print(f"[*] (probe:xss) {e}:{exc_tb.tb_lineno}")
