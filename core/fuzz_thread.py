# -*- coding: utf-8 -*-

from threading import Thread
from probe.prober import Prober
from utils.shared import Shared


class FuzzThread(Thread):
    """
    模糊测试器
    """

    def __init__(self, dnslog=None):
        Thread.__init__(self)
        self.dnslog = dnslog

    def run(self):
        """
        启动线程时执行方法
        """

        try:
            while True:

                request = self.get_request()

                if request is None:
                    break

                prober = Prober(request, self.dnslog)
                for probe in Shared.probes:
                    if hasattr(Prober, probe) and callable(getattr(Prober, probe)):
                        getattr(Prober, probe)(prober)

        except KeyboardInterrupt:
            print("\nTerminated by user")
            Shared.condition.release()
            exit(1)
        except Exception as e:
            print('[*] {}'.format(e))

    def get_request(self):
        """
        获取队列中请求对象用于消费
        """

        request = None
        Shared.condition.acquire()

        try:
            if Shared.request_index < len(Shared.requests):
                request = Shared.requests[Shared.request_index]
                Shared.request_index += 1
        finally:
            Shared.condition.notify_all()
            Shared.condition.release()

        return request
