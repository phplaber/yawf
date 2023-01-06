# -*- coding: utf-8 -*-

from utils.shared import Shared
from utils.constants import *
from urllib.parse import quote
from utils.utils import *

class Prober:
    def __init__(self, request):
        self.request = request
    
    def xss(self):
        """
        XSS 漏洞探测器
        """

        vulnerable = False
        try:
            rsp = send_request(self.request)

            if PAYLOAD in rsp.response:
                for payload in xss.xss_dict:
                    new_request = self.request.copy()
                    for k, v in new_request.items():
                        new_request[k] = v.replace(PAYLOAD, quote(payload)) if PAYLOAD in v else v
                        break
                    poc_rsp = send_request(new_request)
                    if payload in poc_rsp.response:
                        vulnerable = True
                        print("[+] Found XSS! Vulnerable request is: {}".format(new_request))

                    if vulnerable:
                        Shared.fuzz_results.append({
                            'request': self.request,
                            'payload': payload,
                            'poc': new_request,
                            'type': 'XSS'
                        })
                        break

            if not vulnerable:
                print("[-] Not Found XSS.")
        except Exception as e:
            pass

    def sqli(self):
        """
        SQLI 漏洞探测器
        """

        vulnerable = False
        try:
            base_http_response = Shared.base_request.response
            # base_http_length = Shared.base_request.length

            for payload in sqli.sqli_dict:
                new_request = self.request.copy()
                for k, v in new_request.items():
                    new_request[k] = v.replace(PAYLOAD, quote(payload)) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if poc_rsp.status == 500 or poc_rsp.status == 503:
                    vulnerable = True
                    print("[+] Found SQL Injection! Vulnerable request is: {}".format(new_request))
                else:
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, base_http_response, re.I):
                            vulnerable = True
                            print("[+] Found SQL Injection! Vulnerable request is: {}".format(new_request))
                            break

                if vulnerable:
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': new_request,
                        'type': 'SQL Injection'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found SQL Injection.")
        except Exception as e:
            pass

    def dt(self):
        """
        DT 漏洞探测器
        """

        vulnerable = False
        try:
            for payload in dt.dt_dict:
                new_request = self.request.copy()
                for k, v in new_request.items():
                    new_request[k] = clear_param(v).replace(PAYLOAD, payload) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if 'root:' in poc_rsp.response or 'boot loader' in poc_rsp.response:
                    vulnerable = True
                    print("[+] Found Directory Traversal! Vulnerable request is: {}".format(new_request))

                if vulnerable:
                    Shared.fuzz_results.append({
                        'request': self.request,
                        'payload': payload,
                        'poc': new_request,
                        'type': 'Directory Traversal'
                    })
                    break

            if not vulnerable:
                print("[-] Not Found Directory Traversal.")
        except Exception as e:
            pass