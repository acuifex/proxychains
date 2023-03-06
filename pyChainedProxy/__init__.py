import base64, socket, sys, struct, threading, ssl
from enum import IntEnum, auto

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


PROXY_SSL_TYPES = (ProxyType.SSL, ProxyType.SSL_WEAK,
                   ProxyType.SSL_ANON, ProxyType.HTTPS,
                   ProxyType.HTTPS_CONNECT)
PROXY_HTTP_TYPES = (ProxyType.HTTP, ProxyType.HTTPS)
PROXY_HTTPC_TYPES = (ProxyType.HTTP_CONNECT, ProxyType.HTTPS_CONNECT)
PROXY_SOCKS5_TYPES = (ProxyType.SOCKS5, ProxyType.TOR)
PROXY_DEFAULTS = {
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
PROXY_TYPES = {
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

P_TYPE = 0
P_HOST = 1
P_PORT = 2
P_RDNS = 3
P_USER = 4
P_PASS = 5
P_CERTS = 6

DEFAULT_ROUTE = '*'
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


def parseproxy(arg):
    # This silly function will do a quick-and-dirty parse of our argument
    # into a proxy specification array. It lets people omit stuff.
    if '!' in arg:
        # Prefer ! to :, because it works with IPv6 addresses.
        args = arg.split('!')
    else:
        # This is a bit messier to accept common URL syntax
        if arg.endswith('/'):
            arg = arg[:-1]
        args = arg.replace('://', ':').replace('/:', ':').split(':')
    args[0] = PROXY_TYPES[args[0] or 'http']

    if (len(args) in (3, 4, 5)) and ('@' in args[2]):
        # Re-order http://user:pass@host:port/ => http:host:port:user:pass
        pwd, host = args[2].split('@')
        user = args[1]
        args[1:3] = [host]
        if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
        if len(args) == 3: args.append(False)
        args.extend([user, pwd])
    elif (len(args) in (2, 3, 4)) and ('@' in args[1]):
        user, host = args[1].split('@')
        args[1] = host
        if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
        if len(args) == 3: args.append(False)
        args.append(user)

    if len(args) == 2: args.append(PROXY_DEFAULTS[args[0]])
    if len(args) > 2: args[2] = int(args[2])

    if args[P_TYPE] in PROXY_SSL_TYPES:
        names = (args[P_HOST] or '').split(',')
        args[P_HOST] = names[0]
        while len(args) <= P_CERTS:
            args.append((len(args) == P_RDNS) and True or None)
        args[P_CERTS] = (len(names) > 1) and names[1:] or names

    return args


def addproxy(dest, proxytype=None, addr=None, port=None, rdns=True,
             username=None, password=None, certnames=None):
    global _proxyroutes
    route = _proxyroutes.get(dest.lower(), None)
    proxy = (proxytype, addr, port, rdns, username, password, certnames)
    if route is None:
        route = _proxyroutes.get(DEFAULT_ROUTE, [])[:]
    route.append(proxy)
    _proxyroutes[dest.lower()] = route
    if ENABLE_DEBUG: DEBUG('Routes are: %s' % (_proxyroutes,))


def setproxy(dest, *args, **kwargs):
    global _proxyroutes
    dest = dest.lower()
    if args:
        _proxyroutes[dest] = []
        return addproxy(dest, *args, **kwargs)
    else:
        if dest in _proxyroutes:
            del _proxyroutes[dest.lower()]


def setdefaultproxy(*args, **kwargs):
    """setdefaultproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed.
    """
    if args and args[P_TYPE] == ProxyType.DEFAULT:
        raise ValueError("Circular reference to default proxy.")
    return setproxy(DEFAULT_ROUTE, *args, **kwargs)


def adddefaultproxy(*args, **kwargs):
    if args and args[P_TYPE] == ProxyType.DEFAULT:
        raise ValueError("Circular reference to default proxy.")
    return addproxy(DEFAULT_ROUTE, *args, **kwargs)


def usesystemdefaults():
    import os

    no_proxy = ['localhost', 'localhost.localdomain', '127.0.0.1']
    no_proxy.extend(os.environ.get('NO_PROXY',
                                   os.environ.get('NO_PROXY',
                                                  '')).split(','))
    for host in no_proxy:
        setproxy(host, ProxyType.NONE)

    for var in ('ALL_PROXY', 'HTTPS_PROXY', 'http_proxy'):
        val = os.environ.get(var.lower(), os.environ.get(var, None))
        if val:
            setdefaultproxy(*parseproxy(val))
            os.environ[var] = ''
            return


def sockcreateconn(*args, **kwargs):
    _thread_locals.create_conn = args[0]
    try:
        rv = _orgcreateconn(*args, **kwargs)
        return rv
    finally:
        del (_thread_locals.create_conn)


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

    def __recvall(self, count):
        """__recvall(count) -> data
        Receive EXACTLY the number of bytes requested from the socket.
        Blocks until the required number of bytes have been received or a
        timeout occurs.
        """
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

    def addproxy(self, proxytype=None, addr=None, port=None, rdns=True, username=None, password=None, certnames=None):
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
        proxy = (proxytype, addr, port, rdns, username, password, certnames)
        if not self.__proxy: self.__proxy = []
        self.__proxy.append(proxy)

    def setproxy(self, *args, **kwargs):
        """setproxy(proxytype, addr[, port[, rdns[, username[, password[, certnames]]]]])
           (see addproxy)
        """
        self.__proxy = []
        self.addproxy(*args, **kwargs)

    def __negotiatesocks5(self, destaddr, destport, proxy):
        """__negotiatesocks5(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS5 server.
        """
        # First we'll send the authentication packages we support.
        if (proxy[P_USER] != None) and (proxy[P_PASS] != None):
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
        if chosenauth[0:1] != chr(0x05).encode():
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        # Check the chosen authentication method
        if chosenauth[1:2] == chr(0x00).encode():
            # No authentication is required
            pass
        elif chosenauth[1:2] == chr(0x02).encode():
            # Okay, we need to perform a basic username/password
            # authentication.
            self.sendall(chr(0x01).encode() +
                         chr(len(proxy[P_USER])) + proxy[P_USER] +
                         chr(len(proxy[P_PASS])) + proxy[P_PASS])
            authstat = self.__recvall(2)
            if authstat[0:1] != chr(0x01).encode():
                # Bad response
                self.close()
                raise GeneralProxyError((1, _generalerrors[1]))
            if authstat[1:2] != chr(0x00).encode():
                # Authentication failed
                self.close()
                raise Socks5AuthError((3, _socks5autherrors[3]))
            # Authentication succeeded
        else:
            # Reaching here is always bad
            self.close()
            if chosenauth[1] == chr(0xFF).encode():
                raise Socks5AuthError((2, _socks5autherrors[2]))
            else:
                raise GeneralProxyError((1, _generalerrors[1]))
        # Now we can request the actual connection
        req = struct.pack('BBB', 0x05, 0x01, 0x00)
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(destaddr)
            req = req + chr(0x01).encode() + ipaddr
        except socket.error:
            # Well it's not an IP number,  so it's probably a DNS name.
            if proxy[P_RDNS]:
                # Resolve remotely
                ipaddr = None
                req = req + (chr(0x03).encode() +
                             chr(len(destaddr)).encode() + destaddr.encode("latin-1"))
            else:
                # Resolve locally
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
                req = req + chr(0x01).encode() + ipaddr
        req = req + struct.pack(">H", destport)
        self.sendall(req)
        # Get the response
        resp = self.__recvall(4)
        if resp[0:1] != chr(0x05).encode():
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        elif resp[1:2] != chr(0x00).encode():
            # Connection failed
            self.close()
            if ord(resp[1:2]) <= 8:
                raise Socks5Error((ord(resp[1:2]),
                                   _socks5errors[ord(resp[1:2])]))
            else:
                raise Socks5Error((9, _socks5errors[9]))
        # Get the bound address/port
        elif resp[3:4] == chr(0x01).encode():
            boundaddr = self.__recvall(4)
        elif resp[3:4] == chr(0x03).encode():
            resp = resp + self.recv(1)
            boundaddr = self.__recvall(ord(resp[4:5]))
        else:
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        boundport = struct.unpack(">H", self.__recvall(2))[0]
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

    def __negotiatesocks4(self, destaddr, destport, proxy):
        """__negotiatesocks4(self, destaddr, destport, proxy)
        Negotiates a connection through a SOCKS4 server.
        """
        # Check if the destination address provided is an IP address
        rmtrslv = False
        try:
            ipaddr = socket.inet_aton(destaddr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if proxy[P_RDNS]:
                ipaddr = struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01)
                rmtrslv = True
            else:
                ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
        # Construct the request packet
        req = struct.pack(">BBH", 0x04, 0x01, destport) + ipaddr
        # The username parameter is considered userid for SOCKS4
        if proxy[P_USER] != None:
            req = req + proxy[P_USER]
        req = req + chr(0x00).encode()
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if rmtrslv:
            req = req + destaddr + chr(0x00).encode()
        self.sendall(req)
        # Get the response from the server
        resp = self.__recvall(8)
        if resp[0:1] != chr(0x00).encode():
            # Bad data
            self.close()
            raise GeneralProxyError((1, _generalerrors[1]))
        if resp[1:2] != chr(0x5A).encode():
            # Server returned an error
            self.close()
            if ord(resp[1:2]) in (91, 92, 93):
                self.close()
                raise Socks4Error((ord(resp[1:2]), _socks4errors[ord(resp[1:2]) - 90]))
            else:
                raise Socks4Error((94, _socks4errors[4]))
        # Get the bound address/port
        self.__proxysockname = (socket.inet_ntoa(resp[4:]),
                                struct.unpack(">H", resp[2:4])[0])
        if rmtrslv != None:
            self.__proxypeername = (socket.inet_ntoa(ipaddr), destport)
        else:
            self.__proxypeername = (destaddr, destport)

    def __getproxyauthheader(self, proxy):
        if proxy[P_USER] and proxy[P_PASS]:
            auth = proxy[P_USER] + ":" + proxy[P_PASS]
            return "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(auth.encode("utf-8")).decode("utf-8")
        else:
            return ""

    def __stop_http_negotiation(self):
        buf = self.__buffer
        host, port, proxy = self.__negotiating
        self.__buffer = b''
        self.__negotiating = False
        self.__override.remove('send')
        self.__override.remove('sendall')
        return (buf, host, port, proxy)

    def recv(self, count, flags=0):
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

    def recv_into(self, buf, nbytes=0, flags=0):
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

    def send(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.send(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        if self.__negotiating:
            self.__buffer += args[0]
            self.__negotiatehttpproxy()
        else:
            return self.__sock.sendall(*args, **kwargs)

    def __negotiatehttp(self, destaddr, destport, proxy):
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
        # buf = buf.replace("b'", "").replace("\\r","\r").replace("\\n","\n")
        host, port, proxy = self.__negotiating

        # If our buffer is tiny, wait for data.
        if len(buf) <= 3: return

        # If not HTTP, fall back to HTTP CONNECT.
        if buf[0:3].decode("utf-8").lower() not in ('get', 'pos', 'hea',
                                                    'put', 'del', 'opt', 'pro'):
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

    def __negotiatehttpconnect(self, destaddr, destport, proxy):
        """__negotiatehttp(self, destaddr, destport, proxy)
        Negotiates an HTTP CONNECT through an HTTP proxy server.
        """
        # If we need to resolve locally, we do this now
        if not proxy[P_RDNS]:
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

    def __negotiatessl(self, destaddr, destport, proxy,
                       weak=False, anonymous=False):
        """__negotiatessl(self, destaddr, destport, proxy)
        Negotiates an SSL session.
        """
        want_hosts = proxy[P_HOST]

        try:
            context = ssl.create_default_context()
            self.__sock = context.wrap_socket(self.__sock, server_hostname=want_hosts)
        except:
            if ENABLE_DEBUG: DEBUG('*** SSL problem: %s/%s/%s' % (sys.exc_info(),
                                                           self.__sock,
                                                           want_hosts))
            raise

        self.__encrypted = True
        if ENABLE_DEBUG: DEBUG('*** Wrapped %s:%s in %s' % (destaddr, destport,
                                                     self.__sock))

    def __default_route(self, dest):
        route = _proxyroutes.get(str(dest).lower(), [])[:]
        if not route or route[0][P_TYPE] == ProxyType.DEFAULT:
            route[0:1] = _proxyroutes.get(DEFAULT_ROUTE, [])
        while route and route[0][P_TYPE] == ProxyType.DEFAULT:
            route.pop(0)
        return route

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
            if (proxy[P_TYPE] or ProxyType.NONE) not in PROXY_DEFAULTS:
                raise GeneralProxyError((4, _generalerrors[4]))

        chain = proxy_chain[:]
        chain.append([ProxyType.NONE, destpair[0], destpair[1]])
        if ENABLE_DEBUG: DEBUG('*** Chain: %s' % (chain,))

        first = True
        result = None
        while chain:
            proxy = chain.pop(0)

            if proxy[P_TYPE] == ProxyType.DEFAULT:
                chain[0:0] = self.__default_route(default_dest)
                if ENABLE_DEBUG: DEBUG('*** Chain: %s' % chain)
                continue

            if proxy[P_PORT] != None:
                portnum = proxy[P_PORT]
            else:
                portnum = PROXY_DEFAULTS[proxy[P_TYPE] or ProxyType.NONE]

            if first and proxy[P_HOST]:
                if ENABLE_DEBUG: DEBUG('*** Connect: %s:%s' % (proxy[P_HOST], portnum))
                result = self.__do_connect((proxy[P_HOST], portnum))

            if chain:
                nexthop = (chain[0][P_HOST] or '', int(chain[0][P_PORT] or 0))

                if proxy[P_TYPE] in PROXY_SSL_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** TLS/SSL Setup: %s' % (nexthop,))
                    self.__negotiatessl(nexthop[0], nexthop[1], proxy,
                                        weak=(proxy[P_TYPE] == ProxyType.SSL_WEAK),
                                        anonymous=(proxy[P_TYPE] == ProxyType.SSL_ANON))

                if proxy[P_TYPE] in PROXY_HTTPC_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop,))
                    self.__negotiatehttpconnect(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] in PROXY_HTTP_TYPES:
                    if len(chain) > 1:
                        # Chaining requires HTTP CONNECT.
                        if ENABLE_DEBUG: DEBUG('*** HTTP CONNECT: %s' % (nexthop,))
                        self.__negotiatehttpconnect(nexthop[0], nexthop[1],
                                                    proxy)
                    else:
                        # If we are last in the chain, do transparent magic.
                        if ENABLE_DEBUG: DEBUG('*** HTTP PROXY: %s' % (nexthop,))
                        self.__negotiatehttp(nexthop[0], nexthop[1], proxy)

                if proxy[P_TYPE] in PROXY_SOCKS5_TYPES:
                    if ENABLE_DEBUG: DEBUG('*** SOCKS5: %s' % (nexthop,))
                    self.__negotiatesocks5(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] == ProxyType.SOCKS4:
                    if ENABLE_DEBUG: DEBUG('*** SOCKS4: %s' % (nexthop,))
                    self.__negotiatesocks4(nexthop[0], nexthop[1], proxy)

                elif proxy[P_TYPE] == ProxyType.NONE:
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
