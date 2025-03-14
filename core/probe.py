import copy
import json

import requests
from selenium import webdriver

from utils.constants import MARK_POINT

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
        options.add_argument(f'user-agent={user_agent}')
        # 设置网络代理
        if proxies:
            options.add_argument(f"--proxy-server={proxies['http']}")
        # 忽略证书错误
        options.add_argument('--ignore-ssl-errors=yes')
        options.add_argument('--ignore-certificate-errors')
        # 禁用 xss auditor
        options.add_argument('--disable-xss-auditor')
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
        req = requests.get(f"http://api.ceye.io/v1/records?token={self.token}&type=dns&filter={filter}", 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json().get('data')

class Probe:
    def __init__(self, request, browser, base_http, probes_payload, dnslog, fuzz_results, flag):
        self.request = request
        self.browser = browser
        self.base_http = base_http
        self.probes_payload = probes_payload
        self.dnslog = dnslog
        self.fuzz_results = fuzz_results
        self.direct_use_payload_flag = flag

        content_type = base_http.get('request').get('headers').get('content-type', '')
        if 'json' in content_type:
            self.content_type = 'json'
        elif 'xml' in content_type:
            self.content_type = 'xml'
        elif 'form' in content_type:
            self.content_type = 'form'
        else:
            self.content_type = ''

    def gen_payload_request(self, payload, reserve_original_params=False, direct_use_payload=False):
        """
        生成带 payload 的 request 对象
        reserve_original_params：保留原始参数值，默认 False。用于 sqli 探针
        direct_use_payload：直接使用 payload，默认 False。用于 fastjson 探针，减少重复测试
        """

        payload_request = copy.deepcopy(self.request)
        for k, v in payload_request.items():
            if k not in ['params', 'data', 'cookies', 'headers']:
                continue
            if type(v) is str:
                # data 为 xml 编码数据
                if MARK_POINT in v:
                    payload_request[k] = v.replace(MARK_POINT, payload)
                    break
            else:
                flag = False
                for kk, vv in v.items():
                    if (type(vv) is not str) or (MARK_POINT not in vv):
                        continue
                    if not direct_use_payload:
                        if not payload_request['fastjson_detect_flag']:
                            if not reserve_original_params:
                                payload_request[k][kk] = payload
                            else:
                                payload_request[k][kk] = vv.replace(MARK_POINT, payload)
                        else:
                            # 标记点在查询字符串 json 中
                            val_dict = json.loads(payload_request[k][kk])
                            base_val_dict = json.loads(self.base_http.get('request')[k][kk])
                            for kkk, vvv in val_dict.items():
                                if (type(vvv) is not str) or (MARK_POINT not in vvv):
                                    continue
                                if not reserve_original_params:
                                    base_val_dict[kkk] = payload
                                else:
                                    base_val_dict[kkk] += payload
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
