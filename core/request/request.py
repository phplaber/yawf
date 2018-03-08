# -*- coding: utf-8 -*-


import urlparse
import urllib
from core.constants import PAYLOAD, HTTP_METHOD


class Request:
    def __init__(self):
        pass

    def gene_url_list(self, url):

        requests = []
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)
        base_url = str(url[:url.find("?") + 1])

        urls = self.fuzz_finder(params, base_url, "&")
        for url in urls:
            requests.append({"url": url})

        return requests

    def gene_requestfile_list(self, request):

        requests = []
        # 标注查询字符串 Fuzz 点
        if "=" in request["url"]:
            url = request["url"]
            parsed = urlparse.urlparse(url)
            params = urlparse.parse_qsl(parsed.query)
            base_url = str(url[:url.find("?") + 1])

            urls = self.fuzz_finder(params, base_url, "&")
            for fuzz_url in urls:
                new_request = request.copy()
                new_request["url"] = fuzz_url
                requests.append(new_request)

        # 标注 Cookie Fuzz 点
        if request['cookie'] is not None:
            cookie_list = request['cookie'].split(";")
            params = []
            for cookie in cookie_list:
                cookie = cookie.strip()
                key, value = cookie.split("=", 1)
                params.append((unicode(key, "utf-8"), unicode(value, "utf-8")))

            cookies = self.fuzz_finder(params, "", "; ")
            for fuzz_cookie in cookies:
                new_request = request.copy()
                new_request["cookie"] = fuzz_cookie
                requests.append(new_request)

        # 标注 FORM DATA Fuzz 点
        if request['method'] != HTTP_METHOD['GET'] and request['data'] is not None:
            formdata_list = request['data'].split("&")
            params = []
            for formdata in formdata_list:
                formdata = formdata.strip()
                key, value = formdata.split("=", 1)
                params.append((unicode(key, "utf-8"), unicode(value, "utf-8")))

            formdatas = self.fuzz_finder(params, "", "&")
            for fuzz_formdata in formdatas:
                new_request = request.copy()
                new_request["data"] = fuzz_formdata
                requests.append(new_request)

        return requests

    def fuzz_finder(self, params, origin_base, symbol):

        base = origin_base[:]
        params_list = []
        param_length = 0
        for k, v in params:
            params_list.extend([str(k + "=" + urllib.quote_plus(v))])
            param_length += 1

        active_fuzz = 1
        i = 1

        fuzz_params = []
        while i <= param_length and active_fuzz <= param_length:

            if i < param_length and i == active_fuzz:
                base += params_list[i-1] + PAYLOAD + symbol
                i += 1

            elif i == param_length and i == active_fuzz:
                base += params_list[i-1] + PAYLOAD
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