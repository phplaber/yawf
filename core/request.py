# -*- coding: utf-8 -*-


from urllib.parse import *
from utils.constants import MARK_POINT, HTTP_METHOD


class Request:
    """
    模糊测试对象生成器
    """

    def __init__(self):
        pass

    def gene_url_list(self, url):
        """
        通过 URL 获取全部模糊测试 request 对象
        """

        requests = []
        params = parse_qsl(urlparse(url).query)
        base_url = str(url[:url.find("?") + 1])

        urls = self.fuzz_finder(params, base_url, "&")
        for url in urls:
            requests.append({"url": url})

        return requests

    def gene_requestfile_list(self, request):
        """
        通过 request 获取全部模糊测试 request 对象
        """

        requests = []
        # 标记查询字符串 Fuzz 点
        if "=" in request["url"]:
            url = request["url"]
            params = parse_qsl(urlparse(url).query)
            base_url = str(url[:url.find("?") + 1])

            urls = self.fuzz_finder(params, base_url, "&")
            for fuzz_url in urls:
                new_request = request.copy()
                new_request["url"] = fuzz_url
                requests.append(new_request)

        # 标记 Cookie Fuzz 点
        if request['cookie'] is not None:
            cookie_list = request['cookie'].split(";")
            params = []
            for cookie in cookie_list:
                cookie = cookie.strip()
                key, value = cookie.split("=", 1)
                params.append((key.encode("utf-8"), value.encode("utf-8")))

            cookies = self.fuzz_finder(params, "", "; ")
            for fuzz_cookie in cookies:
                new_request = request.copy()
                new_request["cookie"] = fuzz_cookie
                requests.append(new_request)

        # 标记 FORM DATA Fuzz 点
        if request['method'] != HTTP_METHOD['GET'] and request['data'] is not None:
            formdata_list = request['data'].split("&")
            params = []
            for formdata in formdata_list:
                formdata = formdata.strip()
                key, value = formdata.split("=", 1)
                params.append((key.encode("utf-8"), value.encode("utf-8")))

            formdatas = self.fuzz_finder(params, "", "&")
            for fuzz_formdata in formdatas:
                new_request = request.copy()
                new_request["data"] = fuzz_formdata
                requests.append(new_request)

        return requests

    def fuzz_finder(self, params, origin_base, symbol):
        """
        查找可能的测试输入点并做标记
        """

        base = origin_base[:]
        params_list = []
        param_length = 0
        for k, v in params:
            params_list.extend([str(k + "=" + quote(v))])
            param_length += 1

        active_fuzz = 1
        i = 1

        fuzz_params = []
        while i <= param_length and active_fuzz <= param_length:

            if i < param_length and i == active_fuzz:
                base += params_list[i-1] + MARK_POINT + symbol
                i += 1

            elif i == param_length and i == active_fuzz:
                base += params_list[i-1] + MARK_POINT
                active_fuzz += 1
                i += 1
                fuzz_params.extend([base])
                base = origin_base[:]

            elif i == param_length and i != active_fuzz:
                base += params_list[i-1]
                active_fuzz += 1
                i = 1
                fuzz_params.extend([base])
                base = origin_base[:]

            else:
                base += params_list[i-1] + symbol
                i += 1

        return fuzz_params