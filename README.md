## Yawf - Yet Another Web Fuzz

**Yawf** 是一个开源的 Web 漏洞模糊测试工具，能够帮助发现 OWASP 披露的一些常见漏洞，包括：XSS，SQL injection，LFI，RFI 和 Directory traversal等。

## 特性

1.  支持动态 URL 和 Request 文件的模糊测试；
2.  支持自动搜索所有测试锚点并标注，目前搜索范围包括 URL 中查询字符串，Cookie 和表单数据。同时，支持手动标注测试锚点；
3.  支持多线程对测试目标进行模糊测试，默认 10 个线程；
4.  基于 OWASP 进行 Web 漏洞挖掘，目前支持：XSS，SQL injection，LFI，RFI 和 Directory traversal；
5.  容易扩展，漏洞测试器和 Payload 字典分离；
6.  支持配置 HTTP 网络代理；
7.  支持通过调用 shodan api，检测目标为蜜罐的概率。

## 安装

### 环境

1.  Python 2.7.x
2.  MySQL-python（可选项）

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
version 1.0.0                           
Created by Yns0ng (@phplaber)           

Usage: yawf.py [options]

Options:
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  -r REQUESTFILE     Load HTTP request from a file
  -n THREADS         Number of parallel threads (default: 10)
  -p PROXY           Specify a proxy in the request http|s://[IP]:[PORT]
  -t TARGET          Check if the target is a honeypot
```

支持动态 URL 和 Request 文件的模糊测试，当需要测试某个单独的输入点时，仅需在参数值后手动标注上 **[fuzz]**，Yawf 就只会对该位置进行模糊测试。如：

```
http://test.sqlilab.local/Less-1/?id=3[fuzz]
```

Request 文件可以通过 Live HTTP Headers 或 Burp Suite 获取得到。

```
GET /Less-1/?id=3 HTTP/1.1
Host: test.sqlilab.local
User-Agent: Yawf 1.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

当使用 Yawf API 进行批量 URL 测试时，你可能想使用 MySQL 存储测试结果而不是直接打印在终端。首先需安装 MySQL 的 Python 客户端，即：MySQL-python。安装方法参考：[How do I connect to a MySQL Database in Python
](https://stackoverflow.com/questions/372885/how-do-i-connect-to-a-mysql-database-in-python)。安装完成后，在配置文件 **yawf.conf** 中配置 DB 项即可，可参考示例配置文件 yawf.conf.example。如果不需要用到 MySQL，只需将 **host** 留空即可。
