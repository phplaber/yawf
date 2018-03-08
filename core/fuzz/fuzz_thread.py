# -*- coding: utf-8 -*-

from threading import Thread
from core.request.dict import *
from core.utils.utils import *
from core.utils.shared import Shared


class FuzzThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        self.fuzz()

    def get_request(self):

        request = None
        Shared.condition.acquire()

        try:
            if Shared.requests_index < len(Shared.requests):
                request = Shared.requests[Shared.requests_index]
                Shared.requests_index += 1
        finally:
            Shared.condition.notifyAll()
            Shared.condition.release()

        return request

    def fuzz(self):
        """
        线程不停的用各种漏洞字典去检测 HTTP Request 某个输入的漏洞
        """
        try:
            while True:

                request = self.get_request()

                if request is None:
                    break

                self.xss(request)
                self.sqli(request)
                self.lfi(request)
                self.rfi(request)
                self.dt(request)

        except KeyboardInterrupt:
            print "\nTerminated by user"
            try:
                Shared.condition.release()
                sys.exit(1)
            except Exception as e:
                pass

    def xss(self, request):

        vulnerable = False
        try:
            rsp = send_request(request)

            if PAYLOAD in rsp.response:
                for payload in xss.xss_dict:
                    new_request = request.copy()
                    for k, v in new_request.items():
                        new_request[k] = v.replace(PAYLOAD, urllib.quote_plus(payload)) if PAYLOAD in v else v
                        break
                    poc_rsp = send_request(new_request)
                    if payload in poc_rsp.response:
                        vulnerable = True
                        print "[+] XSS Found! Vulnerable request is: %s" % new_request

                    if vulnerable:
                        break

            if not vulnerable:
                print "[-] XSS Failed."
        except Exception as e:
            pass

    def sqli(self, request):

        vulnerable = False
        try:
            base_http_response = Shared.base_request.response
            # base_http_length = Shared.base_request.length

            for payload in sqli.sqli_dict:
                new_request = request.copy()
                for k, v in new_request.items():
                    new_request[k] = v.replace(PAYLOAD, urllib.quote_plus(payload)) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if poc_rsp.status == 500 or poc_rsp.status == 503:
                    vulnerable = True
                    print "[+] SQL Injection Found! Vulnerable request is: %s" % new_request
                else:
                    for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                        if re.search(regex, poc_rsp.response, re.I) and not re.search(regex, base_http_response, re.I):
                            vulnerable = True
                            print "[+] SQL Injection Found! Vulnerable request is: %s" % new_request
                            break

                if vulnerable:
                    break

            if not vulnerable:
                print "[-] SQL Injection Failed."
        except Exception as e:
            pass

    def lfi(self, request):

        vulnerable = False
        try:
            for payload in lfi.lfi_dict:
                new_request = request.copy()
                for k, v in new_request.items():
                    new_request[k] = clear_param(v).replace(PAYLOAD, urllib.quote_plus(payload)) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if 'root:' in poc_rsp.response or 'boot loader' in poc_rsp.response:
                    vulnerable = True
                    print "[+] Local File Inclusion Found! Vulnerable request is: %s" % new_request

                if vulnerable:
                    break

            if not vulnerable:
                print "[-] Local File Inclusion Failed."
        except Exception as e:
            pass

    def rfi(self, request):

        vulnerable = False
        try:
            for payload in rfi.rfi_dict:
                new_request = request.copy()
                for k, v in new_request.items():
                    new_request[k] = clear_param(v).replace(PAYLOAD, urllib.quote_plus(payload)) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if '705cd559b16e6946826207c2199bd890' in poc_rsp.response:
                    vulnerable = True
                    print "[+] Remote File Inclusion Found! Vulnerable request is: %s" % new_request

                if vulnerable:
                    break

            if not vulnerable:
                print "[-] Remote File Inclusion Failed."
        except Exception as e:
            pass

    def dt(self, request):

        vulnerable = False
        try:
            for payload in dt.dt_dict:
                new_request = request.copy()
                for k, v in new_request.items():
                    new_request[k] = clear_param(v).replace(PAYLOAD, urllib.quote_plus(payload)) if PAYLOAD in v else v
                    break
                poc_rsp = send_request(new_request)

                if 'root:' in poc_rsp.response or 'boot loader' in poc_rsp.response:
                    vulnerable = True
                    print "[+] Directory Traversal Found! Vulnerable request is: %s" % new_request

                if vulnerable:
                    break

            if not vulnerable:
                print "[-] Directory Traversal Failed."
        except Exception as e:
            pass