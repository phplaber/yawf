# -*- coding: utf-8 -*- 


class Shared:
    """
    全局共享数据
    """

    base_response = None
    requests = []
    request_index = 0

    condition = None

    fuzz_results = []

    probes = []

    conf = {}

    probes_dict = {}

    dnslog = None

    web_driver = None

    direct_use_payload_flag = False