## Yawf - Yet Another Web Fuzzer

**Yawf** 是一个开源的 Web 漏洞模糊测试工具，能够帮助发现一些常见 Web 漏洞，包括：XSS、SQL injection、Fastjson RCE 和 Log4j RCE 等。

## 特性

1.  支持动态 URL 和 Request 文件的模糊测试；
2.  支持自动搜索所有测试锚点并标注，目前搜索范围包括 URL 中查询字符串，Cookie 和表单数据。同时，支持手动标注测试锚点；
3.  支持多线程对测试目标进行模糊测试，默认 10 个线程；
4.  目前支持检测漏洞类型包括：XSS、SQL injection、Fastjson RCE 和 Log4j RCE 等；
5.  容易扩展，漏洞测试器和 Payload 字典分离；
6.  支持配置 HTTP 网络代理。

## 安装

### 环境

1.  Python 3+

### 运行

```console
$ git clone https://github.com/phplaber/yawf.git yawf
$ python yawf/yawf.py -h
```

## 使用

```
$ python yawf/yawf.py -h
_____.___.  _____  __      _____________
\__  |   | /  _  \/  \    /  \_   _____/
 /   |   |/  /_\  \   \/\/   /|    __)  
 \____   /    |    \        / |     \   
 / ______\____|__  /\__/\  /  \___  /   
 \/              \/      \/       \/    

Automated Web Vulnerability Fuzz Tester
version 2.0.0                           
Created by yns0ng (@phplaber)           

Usage: yawf.py [options]

Options:
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  -r REQUESTFILE     Load HTTP request from a file
  -n THREADS         Number of parallel threads (default: 10)
  -p PROXY           Specify a proxy in the request http|s://[IP]:[PORT]
```

支持动态 URL 和 Request 文件的模糊测试，当需要测试某个单独的输入点时，仅需在参数值后手动标注上 **[fuzz]**，Yawf 就只会对该位置进行模糊测试。如：

```
http://test.sqlilab.local/Less-1/?id=3[fuzz]
```

Request 文件可以通过 Live HTTP Headers 或 Burp Suite 获取得到。

```
GET /Less-1/?id=3 HTTP/1.1
Host: test.sqlilab.local
User-Agent: Yawf 2.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```
