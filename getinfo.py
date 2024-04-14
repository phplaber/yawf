#!/usr/bin/env python3

import re
import sys
import ssl
import time
import socket
import optparse
import requests
import nmap
import dns.resolver
from tabulate import tabulate
from urllib.parse import urlparse, unquote

# 忽略 SSL 告警信息
try:
    from requests.packages import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def detect_waf(req_rsp):
    """
    检测目标对象前是否部署 WAF，以及是哪种 WAF
    检测原理：在 url 中传递 xss 和 sqli payload，检测 response 对象是否包含 Waf 特征。
    参考：https://github.com/Ekultek/WhatWaf
    """
    response = req_rsp.get('response')
    headers = req_rsp.get('headers')
    status = req_rsp.get('status')

    # 请求失败，直接返回
    if status is None:
        return '未知'

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

    # 腾讯云 waf
    elif status == 202:
        if 'waf' in headers.get('Set-Cookie'):
            return 'T-Sec-Waf'

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
        
    return '未知'

if __name__ == '__main__':

    # 记录启动时间
    start_time = time.time()

    parser = optparse.OptionParser(description='+ Get infomation of target +')
    parser.add_option("-u", "--url", dest="url", help='Target URL(e.g. "http://www.target.com")')
    options, _ = parser.parse_args()

    if not options.url:
        parser.error('url not given')

    # URL 解析
    o = urlparse(unquote(options.url))
    scheme = o.scheme.lower() if o.scheme else 'http'
    domain = o.hostname
    port = o.port if o.port else (443 if scheme == 'https' else 80)

    """
    信息收集

    1、基本信息；2、端口信息；3、SSL 证书；4、DNS 记录；5、杂项
    """

    # 基本信息
    # 是否 Web 站点、Web Server 和框架/脚本语言等
    print(f'\n{"-"*10} 基本信息 {"-"*10}')
    is_server_up, is_website = (True,)*2
    web_server, framework, waf = ('未知',)*3
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((domain, port))
    if result:
        is_server_up = False
    sock.close()

    if is_server_up:
        # 判断是否部署了 Waf
        for payload in ['<img/src=1 onerror=alert(1)>', "' and 'a'='a"]:
            url = f'{options.url}&ispayload={payload}' \
                if '?' in options.url                  \
                else f'{options.url}?ispayload={payload}'
            r = requests.get(url, verify=False)
            r_obj = {
                'status': r.status_code,
                'headers': r.headers,
                'response': r.text
            }
            waf = detect_waf(r_obj)
            if waf != '未知': break
        
        if waf == '未知':
            # 是否 Web 站点
            r = requests.get(options.url, verify=False)
            if r.status_code not in [200, 403, 404]:
                is_website = False

            # Web Server 和框架/脚本语言
            headers = r.headers
            web_server = headers.get('Server', '未知')
            framework = headers.get('X-Powered-By', '未知')

    basic_info = f"""
服务状态：{bcolors.OKGREEN + "运行" if is_server_up else bcolors.FAIL + "停止"}{bcolors.ENDC}
是否 Web 站点：{bcolors.OKGREEN + "是" if is_website else bcolors.FAIL + "否"}{bcolors.ENDC}
WAF：{bcolors.BOLD + waf + bcolors.ENDC}
Web 服务软件：{bcolors.BOLD + web_server + bcolors.ENDC}
框架/脚本语言：{bcolors.BOLD + framework + bcolors.ENDC}
    """
    print(basic_info)

    # 端口信息
    print(f'{"-"*10} 端口信息 {"-"*10}\n')
    ports_info = []
    nm = nmap.PortScanner()
    nm.scan(domain)
    for host in nm.all_hosts():
        print(f'主机 IP：{host}')
        #print(f'状态：{nm[host].state()}')
        for proto in nm[host].all_protocols():
            if proto not in ["tcp", "udp"]:
                continue

            lport = list(nm[host][proto].keys())
            lport.sort()
            for pt in lport:
                ports_info.append([f'{pt}/{proto}', nm[host][proto][pt]["state"], nm[host][proto][pt]["name"], f'{nm[host][proto][pt]["product"]} {nm[host][proto][pt]["version"]}'])
    
    print(tabulate(ports_info, headers=['端口', '状态', '服务', '版本'], tablefmt='simple_grid'))

    # SSL 证书信息
    print(f'\n{"-"*10} SSL 证书信息 {"-"*10}')
    if scheme == 'https':
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, port))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get('subject'))
        issuer = dict(x[0] for x in cert.get('issuer'))
        valid_period = {
            'start': cert.get('notBefore'),
            'end': cert.get('notAfter')
        }
        subject_altname = ', '.join([x[1] for x in cert.get('subjectAltName')])

        ssl_info = f"""
颁发对象：
    通用名称：{subject.get('commonName')}
    国家/地区：{subject.get('countryName', '未知')}
    组织：{subject.get('organizationName', '未知')}
颁发者：
    通用名称：{issuer.get('commonName')}
    国家/地区：{issuer.get('countryName')}
    组织：{issuer.get('organizationName')}
有效期：
    颁发日期：{valid_period.get('start')}
    截止日期：{valid_period.get('end')}
颁发对象替代名称：
    DNS：{subject_altname}
        """
    else:
        ssl_info = f'\n{bcolors.WARNING}未检测到 SSL 证书，可能是 HTTP 站点{bcolors.ENDC}\n'
    print(ssl_info)

    # DNS 记录
    print(f'{"-"*10} DNS 记录信息 {"-"*10}\n')
    dns_records_info = []
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['114.114.114.114']

    for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR']:
        try:
            answers = my_resolver.resolve(domain, rtype)
            for rdata in answers:
                dns_records_info.append([rtype, rdata.to_text()])
        except dns.exception.DNSException as e:
            pass

    print(tabulate(dns_records_info, headers=['类型', '记录值'], tablefmt='simple_grid'))

    print(f"\n[+] 信息收集完成，总耗时：{time.time() - start_time:.2f}秒")
