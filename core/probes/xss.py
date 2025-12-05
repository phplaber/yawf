"""
XSS 探针
漏洞知识: https://portswigger.net/web-security/cross-site-scripting
"""

import sys
from urllib.parse import quote, urlparse

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
        probe_ins.browser.page.set_extra_http_headers(probe_ins.request['headers'])
        
        for payload in probe_ins.probes_payload['xss']:
            alert_text = ''
            alert_triggered = False

            # 使用 AngularJS payload，页面需使用 AngularJS 指令
            if '{{' in payload and 'ng-app' not in probe_ins.base_http.get('response'):
                continue
            payload_request = probe_ins.gen_payload_request(payload)
            
            query_list = [f'{par}={val}' for par, val in payload_request['params'].items()] if payload_request['params'] else []
            url = payload_request['url'] + '?' + '&'.join(query_list) if query_list else payload_request['url']
            
            # 在添加 cookie 前，需导航到目标域名某个页面（不必存在），然后再加载目标页面
            if payload_request['cookies']:
                try:
                    probe_ins.browser.page.goto(load_page, timeout=10000)
                except Exception:
                    pass
                
                cookies = []
                for n, v in payload_request['cookies'].items():
                    cookies.append({'name': n, 'value': quote(v), 'url': load_page})
                probe_ins.browser.context.add_cookies(cookies)
            
            # 监听 dialog 事件
            def handle_dialog(dialog):
                nonlocal alert_triggered, alert_text
                alert_text = dialog.message
                alert_triggered = True
                try:
                    dialog.accept()
                except Exception:
                    pass

            probe_ins.browser.page.on("dialog", handle_dialog)

            try:
                probe_ins.browser.page.goto(url, timeout=10000)
                # 等待 3 秒，给 JS 执行留出时间
                probe_ins.browser.page.wait_for_timeout(3000)
            except Exception:
                pass
            
            probe_ins.browser.page.remove_listener("dialog", handle_dialog)

            if alert_triggered and alert_text == '1':
                vulnerable = True

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
