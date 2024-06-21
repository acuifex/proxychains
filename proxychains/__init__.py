# A python module for Chaining of Proxies
# Copyright (C) 2023  acuifex
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import re
import socket
import ssl
import struct
import sys
import threading
from dataclasses import dataclass
from enum import IntEnum, auto
from urllib.parse import urlparse
from urllib3.util.ssltransport import SSLTransport

ENABLE_DEBUG = False
def DEBUG(foo): print(foo)

class ProxyType(IntEnum):
    DEFAULT = -1
    NONE = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()
    HTTP = auto()
    SSL = auto()
    SSL_WEAK = auto()
    SSL_ANON = auto()
    TOR = auto()
    HTTPS = auto()
    HTTP_CONNECT = auto()
    HTTPS_CONNECT = auto()

@dataclass
class Proxy:
    type: ProxyType = ProxyType.DEFAULT
    host: str = None
    port: int = 0
    remote_dns: bool = True
    username: str = None
    password: str = None

PROXY_SSL_TYPES = (ProxyType.SSL, ProxyType.SSL_WEAK,
                   ProxyType.SSL_ANON, ProxyType.HTTPS,
                   ProxyType.HTTPS_CONNECT)
PROXY_HTTP_TYPES = (ProxyType.HTTP, ProxyType.HTTPS)
PROXY_HTTPC_TYPES = (ProxyType.HTTP_CONNECT, ProxyType.HTTPS_CONNECT)
PROXY_SOCKS5_TYPES = (ProxyType.SOCKS5, ProxyType.TOR)
PROXY_DEFAULT_PORT = {
    ProxyType.NONE: 0,
    ProxyType.DEFAULT: 0,
    ProxyType.HTTP: 8080,
    ProxyType.HTTP_CONNECT: 8080,
    ProxyType.SOCKS4: 1080,
    ProxyType.SOCKS5: 1080,
    ProxyType.TOR: 9050,
    ProxyType.HTTPS: 443,
    ProxyType.HTTPS_CONNECT: 443,
    ProxyType.SSL: 443,
    ProxyType.SSL_WEAK: 443,
    ProxyType.SSL_ANON: 443,
}
PROTOCOL_NAMES = {
    'none': ProxyType.NONE,
    'default': ProxyType.DEFAULT,
    'defaults': ProxyType.DEFAULT,
    'http': ProxyType.HTTP,
    'httpc': ProxyType.HTTP_CONNECT,
    'socks': ProxyType.SOCKS5,
    'socks4': ProxyType.SOCKS4,
    'socks4a': ProxyType.SOCKS4,
    'socks5': ProxyType.SOCKS5,
    'tor': ProxyType.TOR,
    'https': ProxyType.HTTPS,
    'httpcs': ProxyType.HTTPS_CONNECT,
    'ssl': ProxyType.SSL,
    'ssl-anon': ProxyType.SSL_ANON,
    'ssl-weak': ProxyType.SSL_WEAK,
}

DEFAULT_ROUTE = '*'

# map[list[Proxy]]
_proxyroutes = {}
_orgsocket = socket.socket
_orgcreateconn = getattr(socket, 'create_connection', None)
_thread_locals = threading.local()


class ProxyError(Exception): pass
class GeneralProxyError(ProxyError): pass
class Socks5AuthError(ProxyError): pass
class Socks5Error(ProxyError): pass
class Socks4Error(ProxyError): pass
class HTTPError(ProxyError): pass


_generalerrors = (
    "success",
    "invalid data",
    "not connected",
    "not available",
    "bad proxy type",
    "bad input")

_socks5errors = (
    "succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "Network unreachable",
    "Host unreachable",
    "Connection refused",
    "TTL expired",
    "Command not supported",
    "Address type not supported",
    "Unknown error")

_socks5autherrors = (
    "succeeded",
    "authentication is required",
    "all offered authentication methods were rejected",
    "unknown username or invalid password",
    "unknown error")

_socks4errors = (
    "request granted",
    "request rejected or failed",
    "request rejected because SOCKS server cannot connect to identd on the client",
    "request rejected because the client program and identd report different user-ids",
    "unknown error")


def parseproxy(proxy_url: str) -> Proxy:
    # This silly function will do a quick-and-dirty parse of our argument
    # into a proxy specification array. It lets people omit stuff.
    if re.match("\w+://", proxy_url) is None:
        # doesn't start with a protocol. assume http
        proxy_url = "http://" + proxy_url
    parsed_url = urlparse(proxy_url)
    scheme = PROTOCOL_NAMES[parsed_url.scheme]
    return Proxy(
        scheme,
        parsed_url.hostname,
        PROXY_DEFAULT_PORT[scheme] if parsed_url.port is None else parsed_url.port,
        False,
        parsed_url.username,
        parsed_url.password,
    )


def addproxy(dest: str, proxy: Proxy):
    global _proxyroutes
    route = _proxyroutes.get(dest.lower(), None)
    if route is None:
        route = _proxyroutes.get(DEFAULT_ROUTE, [])[:]
    route.append(proxy)
    _proxyroutes[dest.lower()] = route
    if ENABLE_DEBUG: DEBUG('Routes are: %s' % (_proxyroutes,))


def setproxy(dest: str, proxy: Proxy | None):
    global _proxyroutes
    dest = dest.lower()
    if proxy is not None:
        _proxyroutes[dest] = []
        return addproxy(dest, proxy)
    else:
        if dest in _proxyroutes:
            del _proxyroutes[dest.lower()]


def setdefaultproxy(proxy: Proxy | None):
    """setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed.
    """
    if proxy is not None and proxy.type == ProxyType.DEFAULT:
        raise ValueError("Circular reference to default proxy.")
    return setproxy(DEFAULT_ROUTE, proxy)


def adddefaultproxy(proxy: Proxy):
    if proxy.type == ProxyType.DEFAULT:
        raise ValueError("Circular reference to default proxy.")
    return addproxy(DEFAULT_ROUTE, proxy)


def usesystemdefaults():
    import os

    no_proxy = ['localhost', 'localhost.localdomain', '127.0.0.1']
    no_proxy.extend(os.environ.get('NO_PROXY',
                                   os.environ.get('NO_PROXY',
                                                  '')).split(','))
    for host in no_proxy:
        setproxy(host, Proxy(ProxyType.NONE))

    for var in ('ALL_PROXY', 'HTTPS_PROXY', 'http_proxy'):
        val = os.environ.get(var.lower(), os.environ.get(var, None))
        if val:
            setdefaultproxy(parseproxy(val))
            os.environ[var] = ''
            return


def sockcreateconn(*args, **kwargs):
    _thread_locals.create_conn = args[0]
    try:
        rv = _orgcreateconn(*args, **kwargs)
        return rv
    finally:
        del (_thread_locals.create_conn)


def _pascal_encode(s: str) -> bytes:
    length = len(s) if len(s) <= 255 else 255  # this will cut the rest.
    return struct.pack("B%ds" % length, length, s.encode())


class socksocket(socket.socket):
    """socksocket([family[, type[, proto]]]) -> socket object
    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0,
                 *args, **kwargs):
        self.__family = family
        self.__type = type
        self.__proto = proto
        self.__args = args
        self.__kwargs = kwargs
        self.__sock = _orgsocket(family, self.__type, self.__proto,
                                 *self.__args, **self.__kwargs)
        self.__proxy = None
        self.__proxysockname = None
        self.__proxypeername = None
        self.__makefile_refs = 0
        self.__buffer = b''
        self.__negotiating = False
        self.__override = ['addproxy', 'setproxy',
                           'getproxysockname', 'getproxypeername',
                           'close', 'connect', 'getpeername', 'makefile',
                           'recv', 'recv_into']  # , 'send', 'sendall']

    def __getattribute__(self, name):
        if name.startswith('_socksocket__'):
            return object.__getattribute__(self, name)
        elif name in self.__override:
            return object.__getattribute__(self, name)
        else:
            return getattr(object.__getattribute__(self, "_socksocket__sock"),
                           name)

    def __setattr__(self, name, value):
        if name.startswith('_socksocket__'):
            return object.__setattr__(self, name, value)
        else:
            return setattr(object.__getattribute__(self, "_socksocket__sock"),
                           name, value)

    def __recvall(self, count: int) -> bytes:
        """__recvall(count) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received or a
        timeout occurs.
        """
        # FIXME: this is a workaround for SSLTransport.
        if getattr(self.__sock, "setblocking", None):
            self.__sock.setblocking(True)
        self.__sock.settimeout(20)

        data = self.recv(count)
        while len(data) < count:
            d = self.recv(count - len(data))
            if d == '':
                raise GeneralProxyError((0, "connection closed unexpectedly"))
            data = data + d
        return data

    def close(self):
        if self.__makefile_refs < 1:
            self.__sock.close()
        else:
            self.__makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self.__makefile_refs += 1
        return socket.SocketIO(self, mode)

    def addproxy(self, proxy: Proxy):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
        Sets the proxy to be used.
        proxytype -    The type of the proxy to be used. Three types
                are supported: ProxyType.SOCKS4 (including socks4a),
                ProxyType.SOCKS5 and ProxyType.HTTP
        addr -        The address of the server (IP or DNS).
        port -        The port of the server. Defaults to 1080 for SOCKS
                servers and 8080 for HTTP proxy servers.
        rdns -        Should DNS queries be preformed on the remote side
                (rather than the local side). The default is True.
                Note: This has no effect with SOCKS4 servers.
        username -    Username to authenticate with to the server.
                The default is no authentication.
        password -    Password to authenticate with to the server.
                Only relevant when username is also provided.
        """
        if not self.__proxy:
            self.__proxy = []
        self.__proxy.append(proxy)

    def setproxy(self, *args, **kwargs):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
           (see addproxy)
        """
        self.__proxy = []
        self.addproxy(*args, **kwargs)

    def __negotiatesocks5(self, destaddr: str, destport: int, proxy: Proxy):
        """__negotiatesocks5(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if proxy.username is not None and proxy.password is not None:
            # The username/password details were supplied to the
            # setproxy method so we support the USERNAME/PASSWORD
            # authentication (in addition to the standard none).
            self.sendall(struct.pack('BBBB', 0x05, 0x02, 0x00, 0x02))
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall(struct.pack('BBB', 0x05, 0x01, 0x00))
        # We'll receive the server's response to determine which
        # method was selected
        chosenauth = self.__recvall(2)
        if chosenauth[0] != 0x05:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        # Check the chosen authentication method
        if chosenauth[1] == 0x00:
            # No authentication is required
            pass
        elif chosenauth[1] == 0x02:
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall(b"\x01" + _pascal_encode(proxy.username) + _pascal_encode(proxy.password))
            authstat = self.__recvall(2)
            if authstat[0] != 0x01:
                # Bad response
                self.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1] != 0x00:
                # Authentication failed
                self.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
            # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenauth[1] == 0xFF:
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        # Now we can request the actual connection
        req = struct.pack('BBB', 0x05, 0x01, 0x00)
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + b"\x01" + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if proxy.remote_dns:
                # Resolve remotely
                ipaddr = None
                req = req + (b"\x03" + _pascal_encode(destaddr))
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + b"\x01" + ipaddr
        # network endian
        req = req + struct.pack("!H", destport)
        self.sendall(req)
        # Get the response
        resp = self.__recvall(4)
        if resp[0] != 0x05:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1] != 0x00:
            # Connection failed
            self.close()
            if ord(resp[1:2]) <= 8:
                raise Socks5Error((ord(resp[1:2]),
                                   _socks5errors[ord(resp[1:2])]))
            else:
                raise Socks5Error((9, _socks5errors[9]))
        # Get the bound address/port
        elif resp[3] == 0x01:
            boundaddr = self.__recvall(4)
        elif resp[3] == 0x03:
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(resp[4])
        else:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        boundport = struct.unpack("!H", self.__recvall(2))[0]
        self.__proxysockname = (boundaddr, boundport)
        if ipaddr != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def getproxysockname(self):
        """getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self.__proxysockname

    def getproxypeername(self):
        """getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        """
        return _orgsocket.getpeername(self)

    def getpeername(self):
        """getpeername() -> address info
        Returns the IP address and port number of the destination
        machine (note: getproxypeername returns the proxy)
        """
        return self.__proxypeername

    def __negotiatesocks4(self, destaddr: str, destport: int, proxy: Proxy):
        """__negotiatesocks4(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if proxy.remote_dns:
                ipaddr = struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01)
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        # Construct the request packet
        req = struct.pack("!BBH", 0x04, 0x01, destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if proxy.username is not None:
            req = req + proxy.username.encode("utf-8")
        req = req + b"\x00"
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv:
            req = req + destaddr.encode("utf-8") + b"\x00"
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvall(8)
        if resp[0] != 0x00:
            # Bad data
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if resp[1] != 0x5A:
            # Server returned an error
            self.close()
            if resp[1] in (91, 92, 93):
                self.close()
                raise Socks4Error((resp[1], _socks4errors[resp[1] - 90]))
            else:
                raise Socks4Error((94, _socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (socket.inet_ntoa(resp[4:]),
                                struct.unpack("!H", resp[2:4])[0])

        # FIXME: not sure what is going on here. was he trying to check against false?
        if rmtrslv != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def __getproxyauthheader(self, proxy: Proxy) -> str:
        if proxy.username is not None and proxy.password is not None:
            auth = proxy.username + ":" + proxy.password
            return "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(auth.encode("utf-8")).decode("utf-8")
        else:
            return ""

    # TODO: type annotate
    def __stop_http_negotiation(self):
        buf = self.__buffer
        host, port, proxy = self.__negotiating
        self.__buffer = b''
        self.__negotiating = False
        self.__override.remove('send')
        self.__override.remove('sendall')
        return (buf, host, port, proxy)

    def recv(self, count:int, flags=0) -> bytes:
        if self.__negotiating:
            # If the calling code tries to read before negotiating is done,
            # assume this is not HTTP, bail and attempt HTTP CONNECT.
            if ENABLE_DEBUG: DEBUG("*** Not HTTP, failing back to HTTP CONNECT.")
            buf, host, port, proxy = self.__stop_http_negotiation()
            self.__negotiatehttpconnect(host, port, proxy)
            self.__sock.sendall(buf)
        while True:
            try:
                return self.__sock.recv(count, flags)
            except ssl.SSLError:
                pass

    # TODO: type annotate buffer?
    def recv_into(self, buf, nbytes=0, flags=0) -> int:
        if self.__negotiating:
            # If the calling code tries to read before negotiating is done,
            # assume this is not HTTP, bail and attempt HTTP CONNECT.
            if ENABLE_DEBUG: DEBUG("*** Not HTTP, failing back to HTTP CONNECT.")
            buf, host, port, proxy = self.__stop_http_negotiation()
            self.__negotiatehttpconnect(host, port, proxy)
            self.__sock.sendall(buf)
        while True:
            try:
                return self.__sock.recv_into(buf, nbytes, flags)
            except ssl.SSLError:
                pass

    # TODO: type annotate args to ReadableBuffer (can you even have that type?)
    def send(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.send(*args, **kwargs)
    # TODO: same as above
    def sendall(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.sendall(*args, **kwargs)

    def __negotiatehttp(self, destaddr: str, destport: int, proxy: Proxy):
        """__negotiatehttpproxy(self, destaddr, destport, proxy)
        Negotiates a connection through an HTTP proxy server.
        """
        if destport in (21, 22, 23, 25, 109, 110, 143, 220, 443, 993, 995):
            # Go straight to HTTP CONNECT for anything related to e-mail,
            # SSH, telnet, FTP, SSL, ...
            self.__negotiatehttpconnect(destaddr, destport, proxy)
        else:
            if ENABLE_DEBUG: DEBUG('*** Transparent HTTP proxy mode...')
            self.__negotiating = (destaddr, destport, proxy)
            self.__override.extend(['send', 'sendall'])

    def __negotiatehttpproxy(self):
        """__negotiatehttp(self, destaddr, destport, proxy)
        Negotiates an HTTP request through an HTTP proxy server.
        """
        buf = self.__buffer
        host, port, proxy = self.__negotiating

        # If our buffer is tiny, wait for data.
        if len(buf) <= 3: return

        # If not HTTP, fall back to HTTP CONNECT.
        # TODO: this doesn't seem like a good check. unknown "pro" method
        if buf[0:3].decode("utf-8").lower() not in ('get', 'pos', 'hea',
                                                    'put', 'del', 'opt', 'pro', 'pat', 'tra'):
            if ENABLE_DEBUG: DEBUG("*** Not HTTP, failing back to HTTP CONNECT.")
            self.__stop_http_negotiation()
            self.__negotiatehttpconnect(host, port, proxy)
            self.__sock.sendall(buf)
            return

        # Have we got the end of the headers?
        if buf.find(b'\r\n\r\n') != -1:
            CRLF = b'\r\n'
        elif buf.find(b'\n\n') != -1:
            CRLF = b'\n'
        else:
            # Nope
            return

        # Remove our send/sendall hooks.
        self.__stop_http_negotiation()

        # Format the proxy request.
        # TODO: fixme?
        host += ':%d' % port
        headers = buf.split(CRLF)
        for hdr in headers:
            if hdr.lower().startswith(b'host: '):
                host = hdr[6:].decode("utf-8")
        req = headers[0].split(b' ', 1)
        # headers[0] = '%s http://%s%s' % (req[0], host, req[1])
        headers[0] = b'%s %s' % (req[0], req[1])
        headers[1] = self.__getproxyauthheader(proxy).encode("utf-8") + headers[1]

        # Send it!
        if ENABLE_DEBUG: DEBUG("*** Proxy request:\n%s***" % CRLF.join(headers))
        self.__sock.sendall(CRLF.join(headers))

    def __negotiatehttpconnect(self, destaddr: str, destport: int, proxy: Proxy):
        """__negotiatehttp(self, destaddr, destport, proxy)
        Negotiates an HTTP CONNECT through an HTTP proxy server.
        """
        # If we need to resolve locally, we do this now
        if not proxy.remote_dns:
            addr = socket.gethostbyname(destaddr)
        else:
            addr = destaddr
        ss = ("CONNECT "
              + addr + ":" + str(destport) + " HTTP/1.1\r\n"
              + self.__getproxyauthheader(proxy)
              + "Host: " + destaddr + "\r\n\r\n"
              ).encode()
        self.__sock.sendall(ss)
        # We read the response until we get "\r\n\r\n" or "\n\n"
        resp = self.__recvall(1)
        while (resp.find("\r\n\r\n".encode()) == -1 and
               resp.find("\n\n".encode()) == -1):
            resp = resp + self.__recvall(1)
        # We just need the first line to check if the connection
        # was successful
        statusline = resp.splitlines()[0].split(" ".encode(), 2)
        if statusline[0] not in ("HTTP/1.0".encode(), "HTTP/1.1".encode()):
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        try:
            statuscode = int(statusline[1])
        except ValueError:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if statuscode != 200:
            self.close()
            raise HTTPError((statuscode, statusline[2]))
        self.__proxysockname = ("0.0.0.0", 0)
        self.__proxypeername = (addr, destport)

    def __negotiatessl(self, destaddr: str, destport: int, proxy: Proxy,
                       weak=False, anonymous=False):
        """__negotiatessl(self, destaddr, destport, proxy)
        Negotiates an SSL session.
        """
        want_hosts = proxy.host

        try:
            context = ssl.create_default_context()
            # ssl.wrap_socket moves socket into a new object, and returns to us a proxy object,
            #  leaving the underlying socket the same.
            #  This prevents us from wrapping the same socket twice with ssl.
            # use wrap_bio instead:
            # https://github.com/python/cpython/blob/c84e6f32df989908685ea8b6cd49ddde9f428524/Lib/test/test_ssl.py#L2106-L2121
            # self.__sock = context.wrap_socket(self.__sock, server_hostname=want_hosts)

            # Thanks urllib for this very specific class, that utilizes wrap_bio instead of wrap_socket
            self.__sock = SSLTransport(self.__sock, context, server_hostname=want_hosts)
        except:
            if ENABLE_DEBUG: DEBUG('*** SSL problem: %s/%s/%s' % (sys.exc_info(),
                                                           self.__sock,
                                                           want_hosts))
            raise

        self.__encrypted = True
        if ENABLE_DEBUG: DEBUG('*** Wrapped %s:%s in %s' % (destaddr, destport,
                                                     self.__sock))
    # TODO: type annotate return value
    def __default_route(self, dest: str):
        route = _proxyroutes.get(str(dest).lower(), [])[:]
        if not route or route[0].type == ProxyType.DEFAULT:
            route[0:1] = _proxyroutes.get(DEFAULT_ROUTE, [])
        while route and route[0].type == ProxyType.DEFAULT:
            route.pop(0)
        return route

    # TODO: type annotate
    def __do_connect(self, addrspec):
        if ':' in addrspec[0]:
            self.__sock = _orgsocket(socket.AF_INET6, self.__type, self.__proto,
                                     *self.__args, **self.__kwargs)
            return self.__sock.connect(addrspec)
        else:
            try:
                self.__sock = _orgsocket(socket.AF_INET, self.__type, self.__proto,
                                         *self.__args, **self.__kwargs)
                return self.__sock.connect(addrspec)
            except socket.gaierror:
                self.__sock = _orgsocket(socket.AF_INET6, self.__type, self.__proto,
                                         *self.__args, **self.__kwargs)
                return self.__sock.connect(addrspec)

    # TODO: type annotate
    def connect(self, destpair):
        """connect(self, despair)
        Connects to the specified destination through a chain of proxies.
        destpar - A tuple of the IP/DNS address and the port number.
        (identical to socket's connect).
        To select the proxy servers use setproxy() and chainproxy().
        """
        if ENABLE_DEBUG: DEBUG('*** Connect: %s / %s' % (destpair, self.__proxy))
        destpair = getattr(_thread_locals, 'create_conn', destpair)

        # Do a minimal input check first
        if ((not type(destpair) in (list, tuple)) or
                (len(destpair) < 2) or (type(destpair[0]) != type('')) or
                (type(destpair[1]) != int)):
            raise GeneralProxyError((5, _generalerrors[5]))

        if self.__proxy:
            proxy_chain = self.__proxy
            default_dest = destpair[0]
        else:
            proxy_chain = self.__default_route(destpair[0])
            default_dest = DEFAULT_ROUTE

        for proxy in proxy_chain:
            # TODO: is it even possible to end up here?
            if (proxy.type or ProxyType.NONE) not in PROXY_DEFAULT_PORT:
                raise GeneralProxyError((4, _generalerrors[4]))

        chain = proxy_chain[:]
        chain.append(Proxy(ProxyType.NONE, destpair[0], destpair[1]))
        if ENABLE_DEBUG: DEBUG('*** Chain: %s' % (chain,))

        first = True
        result = None
        while chain:
            proxy = chain.pop(0)

            if proxy.type == ProxyType.DEFAULT:
                chain[0:0] = self.__default_route(default_dest)
                if ENABLE_DEBUG: DEBUG('*** Chain: %s' % chain)
                continue

            if proxy.port != 0:
                portnum = proxy.port
            else:
                portnum = PROXY_DEFAULT_PORT[proxy.type or ProxyType.NONE]

            if first and proxy.host:
                if ENABLE_DEBUG: DEBUG('*** Connect: %s:%s' % (proxy.host, portnum))
                result = self.__do_connect((proxy.host, portnum))

            if chain:
                nexthop = (chain[0].host or '', int(chain[0].port or 0))

                if proxy.type in PROXY_SSL_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** TLS/SSL Setup: %s' % (nexthop,))
                    self.__negotiatessl(nexthop[0], nexthop[1], proxy,
                                        weak=(proxy.type == ProxyType.SSL_WEAK),
                                        anonymous=(proxy.type == ProxyType.SSL_ANON))

                if proxy.type in PROXY_HTTPC_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop,))
                    self.__negotiatehttpconnect(nexthop[0], nexthop[1], proxy)

                elif proxy.type in PROXY_HTTP_TYPES:
                    if len(chain) > 1:
                        # Chaining requires HTTP CONNECT.
                        if ENABLE_DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop,))
                        self.__negotiatehttpconnect(nexthop[0], nexthop[1],
                                                    proxy)
                    else:
                        # If we are last in the chain, do transparent magic.
                        if ENABLE_DEBUG: DEBUG('*** HTTP PROXY: %s' % (nexthop,))
                        self.__negotiatehttp(nexthop[0], nexthop[1], proxy)

                if proxy.type in PROXY_SOCKS5_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** SOCKS5: %s' % (nexthop,))
                    self.__negotiatesocks5(nexthop[0], nexthop[1], proxy)

                elif proxy.type == ProxyType.SOCKS4:
                    if ENABLE_DEBUG: DEBUG('*** SOCKS4: %s' % (nexthop,))
                    self.__negotiatesocks4(nexthop[0], nexthop[1], proxy)

                elif proxy.type == ProxyType.NONE:
                    if first and nexthop[0] and nexthop[1]:
                        if ENABLE_DEBUG: DEBUG('*** Connect: %s:%s' % nexthop)
                        result = self.__do_connect(nexthop)
                    else:
                        raise GeneralProxyError((4, _generalerrors[4]))

            first = False

        if ENABLE_DEBUG: DEBUG('*** Connected! (%s)' % result)
        return result


def wrapmodule(module):
    """wrapmodule(module)
    Attempts to replace a module's socket library with a SOCKS socket.
    This will only work on modules that import socket directly into the
    namespace.
    """
    module.socket.socket = socksocket
    module.socket.create_connection = sockcreateconn
    if ENABLE_DEBUG: DEBUG('Wrapped: %s' % module.__name__)
