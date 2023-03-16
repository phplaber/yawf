# -*- coding: utf-8 -*-

from threading import Thread
from probe.probe import Probe
from utils.shared import Shared


class FuzzThread(Thread):
    """
    模糊测试器
    """

    def __init__(self):
        Thread.__init__(self)

    def run(self):
        """
        启动线程时执行方法
        """

        try:
            while True:

                request = self.get_request()

                if request is None:
                    break

                probe_ins = Probe(request)
                for probe in Shared.probes:
                    if hasattr(Probe, probe) and callable(getattr(Probe, probe)):
                        getattr(Probe, probe)(probe_ins)
                    else:
                        if probe not in ['jsonp']:
                            print('[*] invalid probe: {}'.format(probe))

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
