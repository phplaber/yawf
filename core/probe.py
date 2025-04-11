import copy
import json
from xml.etree import ElementTree as ET

from utils.constants import MARK_POINT, EFFICIENCY_CONF
from utils.utils import get_content_type

class Probe:
    def __init__(self, request, browser, base_http, probes_payload, oob_detector, fuzz_results, flag):
        self.request = request
        self.browser = browser
        self.base_http = base_http
        self.probes_payload = probes_payload
        self.oob_detector = oob_detector
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
            if k not in ('params', 'data', 'cookies', 'headers') or not v:
                continue
            if type(v) is str:
                # data 为 xml 编码数据
                if MARK_POINT in v:
                    payload_request[k] = v.replace(MARK_POINT, payload)
                    break
            else:
                break_status = False
                for kk, vv in v.items():
                    if (type(vv) is not str) or (MARK_POINT not in vv):
                        continue
                    if direct_use_payload:
                        # 直接使用 payload
                        if k == 'params':
                            payload_request[k][kk] = payload
                            self.direct_use_payload_flag[k][kk] = True
                        if k == 'data':
                            payload_request[k] = payload
                            self.direct_use_payload_flag[k] = True
                    else:
                        if k == 'params' and get_content_type(vv) == 'json':
                            # GET xxx.php?foo={"a":"b","c":"d"}&bar={"aa":"bb"}
                            val_dict = json.loads(payload_request[k][kk])
                            base_val_dict = json.loads(self.base_http.get('request')[k][kk])
                            for kkk, vvv in val_dict.items():
                                if (type(vvv) is not str) or (MARK_POINT not in vvv):
                                    continue
                                base_val_dict[kkk] = payload if not reserve_original_params else (base_val_dict[kkk] + payload)
                                payload_request[k][kk] = json.dumps(base_val_dict)
                                break
                        else:
                            payload_request[k][kk] = payload if not reserve_original_params else vv.replace(MARK_POINT, payload)  
                    break_status = True
                    break
                if break_status:
                    break
        
        return payload_request
    
    def is_resource_param(self):
        """
        检查标记的字段名称是否为资源相关参数，用于判断是否执行某些特定探针（如：dt、ssrf等）。
        """

        # 本地和远程资源参数集合（包含匹配）
        local_and_remote_resource_params = EFFICIENCY_CONF.get('local_and_remote_resource_params')
        if any(param in self._get_mark_field_name().lower() for param in local_and_remote_resource_params):
            return True
        return False

    def _get_mark_field_name(self):
        """
        获取标记位置对应的字段名称。
        分别从查询字符串、Cookie、POST Body和请求头处查找。
        """

        # 查询字符串
        for par, val in self.request.get('params').items():
            if type(val) is not str or MARK_POINT not in val:
                continue

            if get_content_type(val) == 'json':
                val_dict = json.loads(val)
                for d_par, d_val in val_dict.items():
                    if type(d_val) is str and MARK_POINT in d_val:
                        return d_par
            else:
                return par

        # Cookie
        for name, value in self.request.get('cookies').items():
            if type(value) is str and MARK_POINT in value:
                return name

        # POST Body
        if type(self.request.get('data')) is str:
            # xml
            if MARK_POINT in self.request.get('data'):
                xmlTree = ET.fromstring(self.request.get('data'))
                for elem in xmlTree.iter():
                    if elem.text and MARK_POINT in elem.text:
                        return elem.tag
        else:
            # form、json
            for field, value in self.request.get('data').items():
                if type(value) is str and MARK_POINT in value:
                    return field

        # 请求头
        for header, value in self.request.get('headers').items():
            if type(value) is str and MARK_POINT in value:
                return header

        return ''
