import queue
from core.probe import Probe
from multiprocessing import Process, Queue, Manager, cpu_count
from urllib.parse import urlparse

class Fuzzer:
    """
    模糊测试器
    """

    def __init__(self, requests, base_http, probes, probes_payload, dnslog, browser):

        self.requests = requests
        self.base_http = base_http
        self.probes = probes
        self.probes_payload = probes_payload
        self.dnslog = dnslog
        self.browser = browser
        
    def do_fuzz(self, requests, fuzz_results, flag, load_page):
        """
        进程执行目标
        requests: 请求对象队列
        fuzz_results: 漏洞详情队列
        flag: 控制 fastjson 探针智能化检测开关
        load_page: headless chrome 着陆页
        """

        # 启动 Chrome 浏览器
        chrome = self.browser.run() if self.browser else None

        while True:
            try:
                # 从队列中获取待检测 request 对象，如队列为空，抛出异常跳出循环
                request = requests.get_nowait()
            except queue.Empty:
                break
            else:
                # 调用探针检测漏洞
                probe_ins = Probe(
                    request, 
                    chrome, 
                    self.base_http, 
                    self.probes_payload, 
                    self.dnslog,
                    fuzz_results,
                    flag,
                    load_page
                )
                
                for probe in self.probes:
                    if hasattr(Probe, probe) and callable(getattr(Probe, probe)):
                        getattr(Probe, probe)(probe_ins)
                
        # 关闭 Chrome 浏览器
        if chrome:
            chrome.quit()

    def run(self):
        """
        启动多进程并行处理
        """

        fuzz_workers = []
        # 请求对象队列
        requests = Queue()
        # 存储漏洞队列
        fuzz_results = Queue()
        # 用于 fastjson 探针，减少重复测试
        manager = Manager()
        # 创建可在多进程间共享的字典
        flag = manager.dict()
        # 注意这里不能使用常规的字典
        flag['params'] = manager.dict()
        flag['data'] = False
        # headless chrome 着陆页
        o = urlparse(self.base_http['request']['url'])
        load_page = f'{o.scheme}://{o.netloc}/robots.txt'

        requests_num = 0
        for request in self.requests:
            requests_num += 1
            requests.put(request)

        # 进程数
        cpus_num = cpu_count()
        processes_num = requests_num if requests_num < cpus_num else cpus_num
        
        for _ in range(processes_num):
            fuzz_worker = Process(target=self.do_fuzz, args=(requests, fuzz_results, flag, load_page,))
            fuzz_workers.append(fuzz_worker)
            fuzz_worker.start()

        # 等待全部进程结束
        for fuzz_worker in fuzz_workers:
            fuzz_worker.join()

        # 从队列获取漏洞结果并返回
        results = []
        while not fuzz_results.empty():
            results.append(fuzz_results.get())

        return results
