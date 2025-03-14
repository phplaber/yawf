import copy
import json

from utils.constants import MARK_POINT

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
