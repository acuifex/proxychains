# proxychains #

This is a pretty heavily modified [pyChainedProxy](https://github.com/nighthawkk/pyChainedProxy), 
which is a fork of [socksipy](https://socksipy.sourceforge.net/), 
and is somehow related to [PySocksipyChain](https://github.com/pagekite/PySocksipyChain). 

I'm not entirely sure about the hierarchy of those projects, so i'm going to mention everyone, and use a GPL license.

Copyright (c) 2020 Aman Kumar. All rights reserved. <br/>
Copyright 2011 Bjarni R. Einarsson. All rights reserved. <br/>
Copyright 2006 Dan-Haim. All rights reserved.

Changes include:
* Dropped python 2 support
* Code readability changes
* https/ssl connect chaining support

https://pypi.org/project/proxychains/

## Proxy support ##

* SOCKS4
* SOCKS5
* HTTP: Cannot be anywhere except the end of the chain, or proxy anything except http requests, unless the proxy supports the [connect method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT), in which case the library will use HTTP_CONNECT
* HTTPS: Same as above
* HTTP_CONNECT
* HTTPS_CONNECT
* SSL: Unsure about the usage.
* DEFAULT: Use the global chain. Unsure about the usage.
* TOR: Should be completely identical to SOCKS5


## Install ##

```
pip install proxychains
```

## Example ##
Note that the example isn't complete. Check the source code for other methods or use the documentation of the other projects.
```
import requests
from requests.structures import CaseInsensitiveDict
from http.client import HTTPConnection
from urllib.parse import urlparse
import proxychains as socks
# socks.ENABLE_DEBUG = True

# https://stackoverflow.com/questions/46446904/encoding-an-http-request-in-python/46448489
class TunneledHTTPConnection(HTTPConnection):
    def __init__(self, transport, *args, **kwargs):
        self.transport = transport
        HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.transport.connect((self.host, self.port))
        self.sock = self.transport

class TunneledHTTPAdapter(requests.adapters.BaseAdapter):
    def __init__(self, transport):
        self.transport = transport

    def close(self):
        pass

    def send(self, request, **kwargs):
        scheme, location, path, params, query, anchor = urlparse(request.url)
        if ':' in location:
            host, port = location.split(':')
            port = int(port)
        else:
            host = location
            port = 80

        connection = TunneledHTTPConnection(self.transport, host, port)
        connection.request(method=request.method,
                           url=request.url,
                           body=request.body,
                           headers=request.headers)
        r = connection.getresponse()
        resp = requests.Response()
        resp.status_code = r.status
        resp.headers = CaseInsensitiveDict(r.headers)
        resp.raw = r
        resp.reason = r.reason
        resp.url = request.url
        resp.request = request
        resp.connection = connection
        resp.encoding = requests.utils.get_encoding_from_headers(r.headers)
        requests.cookies.extract_cookies_to_jar(resp.cookies, request, r)
        return resp

if __name__ == '__main__':
    with requests.Session() as session:
        sock = socks.socksocket()
        sock.addproxy(socks.parseproxy("httpcs://127.0.0.1:8080"))  # this will use HTTPS_CONNECT
        sock.addproxy(socks.Proxy(
            socks.ProxyType.SOCKS5,  # the proxy type
            "127.0.0.1",  # host
            8081,  # port
            remote_dns=False,  # whether we should resolve the next host locally, or let this host handle it. Default: False
            username="login",  # proxy login
            password="hunter2"  # proxy password
        ))
        # socks.usesystemdefaults()  # this will use enviroment variables to set proxy. there is no support for chains
        session.mount("http://", TunneledHTTPAdapter(sock))
        session.mount("https://", TunneledHTTPAdapter(sock))
        print(session.get("https://httpbin.org/ip").json()["origin"])
```