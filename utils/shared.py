# -*- coding: utf-8 -*- 

class Shared:
    """
    全局共享数据（静态变量）
    """

    base_response = None
    requests = []
    request_index = 0

    condition = None

    fuzz_results = []

    probes = []

    platform = None

    probes_payload = {}

    dnslog = None

    web_driver = None

    direct_use_payload_flag = {'params': {}, 'data': False}

    content_type = None

    req_pool = None

    cookiejar = None
