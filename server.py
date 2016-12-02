# -*- coding: utf-8 -*-

import argparse
import logging
import threading
import datetime
import socket
import ssl
import select
import sys
import time
import CA
import zlib

PY3 = sys.version_info[0] == 3

if PY3:
    from urllib import parse as urlparse
    import queue
else:
    import urlparse
    import Queue as queue

logger = logging.getLogger(__name__)

CRLF, COLON, SP = b"\r\n", b':', b' '

HTTP_REQUEST_PARSER = 1
HTTP_RESPONSE_PARSER = 2

HTTP_PARSER_STATE_INITIALIZED = 1
HTTP_PARSER_STATE_LINE_RCVD = 2
HTTP_PARSER_STATE_RCVING_HEADERS = 3
HTTP_PARSER_STATE_HEADERS_COMPLETE = 4
HTTP_PARSER_STATE_RCVING_BODY = 5
HTTP_PARSER_STATE_COMPLETE = 6

CHUNK_PARSER_STATE_WAITING_FOR_SIZE = 1
CHUNK_PARSER_STATE_WAITING_FOR_DATA = 2
CHUNK_PARSER_STATE_COMPLETE = 3


class DataType:
    DOMAIN = '01'
    DELAY = '02'
    STATUS = '03'
    SERVER = '04'
    CONSTRUCTION = '05'
    CONNECTION = '06'
    
class ConnectionType:
    SUCCESS = '01'
    CONNECTED = '02'
    FAIL = '03'


class ChunkParser(object):
    """HTTP chunked encoding response parser."""
    
    def __init__(self):
        self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
        self.body = b''
        self.chunk = b''
        self.size = None
    
    def parse(self, data):
        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)
    
    def process(self, data):
        if self.state == CHUNK_PARSER_STATE_WAITING_FOR_SIZE:
            line, data = HTTPParser.split(data)
            if line:
                self.size = int(line, 16)
            else:
                # self.size = 0
                return False, data
            self.state = CHUNK_PARSER_STATE_WAITING_FOR_DATA
        elif self.state == CHUNK_PARSER_STATE_WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = CHUNK_PARSER_STATE_COMPLETE
                else:
                    self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(data) > 0, data

class HTTPParser(object):
    """HTTP request/response parser."""
    
    def __init__(self, type=None):
        self.type = type if type else HTTP_REQUEST_PARSER
        self.hostname = ""
        self.initAll()

    def initAll(self):
        self.state = HTTP_PARSER_STATE_INITIALIZED
        
        self.raw = b''
        self.buffer = b''
        
        self.headers = dict()
        self.body = None
        
        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None
        
        self.chunker = None
    
    def parse(self, data):
        if self.state == HTTP_PARSER_STATE_COMPLETE and self.type == HTTP_REQUEST_PARSER:
            self.initAll()
        self.raw += data
        data = self.buffer + data
        self.buffer = b''
        
        more = True if len(data) > 0 else False
        while more: 
            more, data = self.process(data)
        self.buffer = data
    
    def process(self, data):
        if self.state >= HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        (self.method == b"POST" or self.type == HTTP_RESPONSE_PARSER):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HTTP_PARSER_STATE_RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HTTP_PARSER_STATE_COMPLETE
            elif b'transfer-encoding' in self.headers and self.headers[b'transfer-encoding'][1].lower() == b'chunked':
                if not self.chunker:
                    self.chunker = ChunkParser()
                self.chunker.parse(data)
                if self.chunker.state == CHUNK_PARSER_STATE_COMPLETE:
                    self.body = self.chunker.body
                    self.state = HTTP_PARSER_STATE_COMPLETE
            
            return False, b''
        
        line, data = HTTPParser.split(data)
        if line == False: return line, data
        
        if len(line) == 0 and len(data) == 0 and self.method == b"CONNECT" and self.type == HTTP_REQUEST_PARSER:
            self.state = HTTP_PARSER_STATE_RCVING_HEADERS #fix bug???  b'CONNECT www.baidu.com:443 HTTP/1.0\r\n\r\n'  could not complete

        if self.state < HTTP_PARSER_STATE_LINE_RCVD:
            self.process_line(line)
        elif self.state < HTTP_PARSER_STATE_HEADERS_COMPLETE:
            self.process_header(line)
        
        if self.state == HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        self.type == HTTP_REQUEST_PARSER and \
        not self.method == b"POST" and \
        self.raw.endswith(CRLF*2):
            self.state = HTTP_PARSER_STATE_COMPLETE
        
        return len(data) > 0, data
    
    def process_line(self, data):
        line = data.split(SP)
        if self.type == HTTP_REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self.state = HTTP_PARSER_STATE_LINE_RCVD
    
    def process_header(self, data):
        if len(data) == 0:
            if self.state == HTTP_PARSER_STATE_RCVING_HEADERS:
                self.state = HTTP_PARSER_STATE_HEADERS_COMPLETE
            elif self.state == HTTP_PARSER_STATE_LINE_RCVD:
                self.state = HTTP_PARSER_STATE_RCVING_HEADERS
        else:
            self.state = HTTP_PARSER_STATE_RCVING_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)
    
    def build_url(self):
        if not self.url:
            return b'/None'
        
        url = self.url.path
        if url == b'': url = b'/'
        if not self.url.query == b'': url += b'?' + self.url.query
        if not self.url.fragment == b'': url += b'#' + self.url.fragment
        return url
    
    def build_header(self, k, v):
        return k + b": " + v + CRLF
    
    def build(self, del_headers=None, add_headers=None):
        req = b" ".join([self.method, self.build_url(), self.version])
        req += CRLF
        
        if not del_headers: del_headers = []
        for k in self.headers:
            if not k in del_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1])
        
        if not add_headers: add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1])
        
        req += CRLF
        if self.body:
            req += self.body
        
        return req
    
    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1: return False, data
        line = data[:pos]
        data = data[pos+len(CRLF):]
        return line, data



class TargetConnectionFailed(Exception):
    
    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason
    
    def __str__(self):
        return '<TargetConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)


class Proxy(threading.Thread):
    """docstring for Proxy"""
    def __init__(self, client, monitor, ca):
        super(Proxy, self).__init__()
        self.client = client
        self.monitor = monitor
        self.server = None

        self.startTime = self._now()
        self.lastActivity = self.startTime

        self.request = HTTPParser()
        self.response = HTTPParser(HTTP_RESPONSE_PARSER)

        self.connection_established_pkt = CRLF.join([
            b"HTTP/1.1 200 Connection established",
            b"Proxy-agent: proxy",
            CRLF
        ])

        self.hasSentToMonitor = False

        self.ca = ca
        

    def _now(self):
        return datetime.datetime.utcnow()


    def _isInactive(self):
        return (self._now() - self.lastActivity).seconds > 10


    def _getCACert(self):
        caCertStr = self.ca.getCACert()
        return CRLF.join([
            b"HTTP/1.1 200 OK",
            b"Content-Type:application/x-x509-ca-cert",
            b"Content-Length:" + str(len(caCertStr)).encode(),
            b"Connection:close",
            CRLF
        ]) + caCertStr


    def _gzipDecoder(self, data):
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)

    def _deflateDecoder(self, data):
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except zlib.error as e:
            return zlib.decompress(data)

    def _generateMessage(self, url, code=-1, contentLen=-1):
        if len(url) == 0:
            return {DataType.CONNECTION : {ConnectionType.FAIL : ''}}
        if code == -1 and contentLen == -1:
            return {DataType.CONNECTION : {ConnectionType.CONNECTED : url}}
        return {DataType.CONNECTION : {ConnectionType.SUCCESS : [url, code, contentLen]}}

    def _getResCode(self):
        return int(self.response.code.decode()) if self.response.code else -1

    def _getRequestUrl(self):
        try:
            url = self.request.url.geturl()
            if not url.startswith(b"http"):
                if b'host' in self.request.headers:
                    hostname = self.request.headers[b'host'][1]
                else:
                    hostname = self.request.hostname
                if hostname == url or hostname + b'/'== url:
                    url = b''
                url = b"https://" + hostname + url
        except Exception as e:
            return ''

        return url.decode()

    def _sendMessToMonitor(self):

        isUseChunkLen = True

        if self.response.state < HTTP_PARSER_STATE_HEADERS_COMPLETE \
            or self.hasSentToMonitor \
            or not self.request.url:
            return

        contentLen = -1
        if b'content-length' in self.response.headers:
            contentLen = int(self.response.headers[b'content-length'][1])
        elif isUseChunkLen:
            if self.response.state == HTTP_PARSER_STATE_COMPLETE and b"content-encoding" in self.response.headers:
                if self.response.headers[b"content-encoding"][1] == b"gzip":
                    try:
                        page_content = self._gzipDecoder(self.response.body)
                        contentLen = len(page_content)
                    except Exception as e:
                        logger.exception("Exception when gzipdecoder: %r" % ziperror)
                elif self.response.headers[b"content-encoding"][1] == b"deflate":
                    try:
                        page_content = self._deflateDecoder(self.response.body)
                        contentLen = len(page_content)
                    except Exception as e:
                        logger.exception("Exception when deflatedecoder: %r" % ziperror)
            else:
                return


        url = self._getRequestUrl()
        code = self._getResCode()

        message = self._generateMessage(url, code, contentLen)

        self._putMessDictToMonitor(message)

    def _putMessDictToMonitor(self, message):
        self.monitor.put(str(message).encode())
        self.hasSentToMonitor = True
        logger.info(str(message))


    def _processRequest(self, data): 
        self.request.parse(data)

        if self.server and not self.server.isClosed:
            self.server.queue(data)
            return

        if self.request.url and self.request.url.geturl() == b"http://proxy.ca/":
            self.client.queue(self._getCACert())
            return

        if self.request.state == HTTP_PARSER_STATE_COMPLETE:
            if self.request.method == b"CONNECT":
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80

            self.request.hostname = host

            try:
                self.server = Server(host, port)
                if self.request.method == b"CONNECT":
                    self.server.wrapToSSL()
                self.server.connect()
            except Exception as e:
                raise TargetConnectionFailed(host, port, repr(e))

            if self.request.method == b"CONNECT":
                self.client.send(self.connection_established_pkt)
                self.client.wrapToSSL(self.ca.getCert(host.decode()))
            else:
                self.server.queue(self.request.build(
                    del_headers=[b'proxy-connection', b'connection', b'keep-alive'], 
                    add_headers=[(b'Connection', b'Close')]                    
                ))

    def _processResponse(self, data):
        # if not self.request.method == b"CONNECT":
        #     self.response.parse(data)       #cpu cost a lot?
        self.response.parse(data)
        
        self._sendMessToMonitor()

        self.client.queue(data)

    def _process_rlist(self, r):
        if self.client.conn in r:
            data = self.client.recv()

            self.lastActivity = self._now()

            if not data:
                return True

            try:
                self._processRequest(data)
            except Exception as e:
                logger.exception(e)
                if isinstance(e, TargetConnectionFailed):
                    self._putMessDictToMonitor(self._generateMessage(""))
                else:
                    self._putMessDictToMonitor(self._generateMessage(self._getRequestUrl()))

                self.client.queue(CRLF.join([
                    b"HTTP/1.1 502 Bad Gateway",
                    b"Proxy-agent: proxy",
                    b"Content-Length: 11",
                    b"Connection: close",
                    CRLF
                ]) + b"Bad Gateway")

                self.client.flush()
                return True

        if self.server and not self.server.isClosed and self.server.conn in r:
            data = self.server.recv()
            self.lastActivity = self._now()
            if not data:
                self.server.close()
            else:
                self._processResponse(data)
        return False


    def _process_wlist(self, w):
        if self.client.conn in w:
            self.client.flush()

        if self.server and not self.server.isClosed and self.server.conn in w:
            self.server.flush()


    def _getLists(self):
        rlist, wlist, xlist = [], [], []
        if self.client.conn.fileno() > 0:
            rlist.append(self.client.conn)
            if self.client.hasBuffer():
                wlist.append(self.client.conn)

        if self.server and not self.server.isClosed and self.server.conn.fileno() > 0:
            rlist.append(self.server.conn)

            if self.server.hasBuffer():
                wlist.append(self.server.conn)

        return rlist, wlist, xlist


    def _process(self):
        while True:
            rlist, wlist, xlist = self._getLists()

            # windows may not accept three empty
            if len(rlist) == 0 and len(wlist) == 0 and len(xlist) == 0:
                break

            r, w, x = select.select(rlist, wlist, xlist, 1)

            self._process_wlist(w)

            isClientNotSendData = self._process_rlist(r)

            if isClientNotSendData:
                break

            if self.client.getBufferSize() == 0:
                if self.response.state == HTTP_PARSER_STATE_COMPLETE or self._isInactive():
                    break


    def run(self):
        try:
            self._process()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception("Proxy Exception:%r " % (e))
        finally:
            self.client.close()
            logger.debug("Closing proxy for connection %r at address %r" % (self.client.conn, self.client.addr))


class Connection(object):
    """docstring for Connection"""
    def __init__(self, isClient=False):
        super(Connection, self).__init__()
        self.isClient = isClient
        self.buffer = b""
        self.isClosed = False


    def send(self, data):
        size = 0
        try:
            size = self.conn.send(data)
        except Exception as e:
            pass
        return size


    def recv(self, BUFFER_SIZE=8192):
        data = b''
        try:
            data = self.conn.recv(BUFFER_SIZE)
        except Exception as e:
            pass

        if len(data) == 0:
            return

        if isinstance(self.conn, ssl.SSLSocket):
            data_left = self.conn.pending()
            while data_left:
                data += self.conn.recv(data_left)
                data_left = self.conn.pending()
        return data


    def close(self):
        self.conn.close()
        self.isClosed = True


    def getBufferSize(self):
        return len(self.buffer)


    def hasBuffer(self):
        return self.getBufferSize() > 0


    def queue(self, data):
        self.buffer += data


    def flush(self):
        sendSize = self.send(self.buffer)
        self.buffer = self.buffer[sendSize:]


class Server(Connection):
    """docstring for Server"""
    def __init__(self, host, port):
        super(Server, self).__init__()
        self.addr = (host, int(port))

        # support ipv6?
        socketFamily= socket.getaddrinfo(self.addr[0], self.addr[1])[0][0]
        self.conn = socket.socket(socketFamily, socket.SOCK_STREAM)

    def connect(self):
        self.conn.connect(self.addr)

    def wrapToSSL(self):
        self.conn = ssl.wrap_socket(self.conn)
        

class Client(Connection):
    """docstring for Client"""
    def __init__(self, conn, addr):
        super(Client, self).__init__(isClient=True)
        self.conn = conn
        self.addr = addr

    def wrapToSSL(self, certfile):
        self.conn = ssl.wrap_socket(self.conn, certfile=certfile, server_side=True)
        

class Monitor(Server, threading.Thread):
    """docstring for Monitor"""
    def __init__(self, host, port):
        super(Monitor, self).__init__(host, port)
        self.queue_send = queue.Queue()
        self.daemon = True
        self.reconnectTime = 0
        self.WAITTIME = 5
        self.isConnected = False


    def connect(self):
        try:
            self.conn.connect(self.addr)
            return True
        except Exception as e:
            logger.warning("Exception when monitor connect to remote: %r" % e)

        return False

    def run(self):
        while True:
            self.isConnected = False
            if self.reconnectTime == 5:
                time.sleep(self.WAITTIME)
                self.reconnectTime = 0
            self.isConnected = self.connect()
            self.reconnectTime += 1

            if self.isConnected:
                self.reconnectTime = 0
                self._handle()

    def _handle(self):
        while True:
            data = self.queue_send.get()
            isSend = self.sendall(data)
            if not isSend:
                break
            res = self.recv()
            if not res:
                break

    def sendall(self, data):
        try:
            self.conn.sendall(data)
        except Exception as e:
            return False
        return True

    
    def put(self, data):
        self.queue_send.put(data)


class TCPListener(object):

    def __init__(self, serverAddr, serverPort, monitorAddr, monitorPort, backlog = 1024):
        self.serverAddr = serverAddr
        self.serverPort = serverPort
        self.monitor = Monitor(monitorAddr, monitorPort)
        self.backlog = backlog
        self.ca = CA.CertificateAuthority()


    def handleConnection(self, conn, addr):
        client = Client(conn, addr)
        proxy = Proxy(client, self.monitor, self.ca)
        proxy.daemon = True
        proxy.start()
        logger.debug("Started Proxy %r to handle connection %r" % (proxy, client.conn))
        

    def run(self):
        
        self.monitor.start()

        listener = None
        try:
            logger.info("Started server on addr %s:serverPort %d" % (self.serverAddr, self.serverPort))

            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind((self.serverAddr, self.serverPort))
            listener.listen(self.backlog)

            while True:
                try:
                    conn, addr = listener.accept()
                    logger.debug("Accepted connection %r:%r" % (conn, addr))
                    self.handleConnection(conn, addr)
                except Exception as e:
                    logger.exception("Exception when start proxy: %r" % e)

        except Exception as e:
            logger.exception("TCPListener Exception: %r" % e)

        finally:
            logger.debug("closing TCPListener...")
            if listener:
                listener.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--server_addr", default="0.0.0.0", help="Default: 0.0.0.0")
    parser.add_argument("--server_port", default="10042", help="Default: 10042")
    parser.add_argument("--monitor_addr", default="127.0.0.1", help="Default: 127.0.0.1")
    parser.add_argument("--monitor_port", default="10044", help="Default: 10044")
    parser.add_argument("--log_level", default="INFO", help="DEBUG, INFO, WARNING, ERROR, CRITICAL")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s -%(levelname)s - pid:%(process)d - %(message)s")
    logging.disable(logging.DEBUG)
    server_addr = args.server_addr
    server_port = int(args.server_port)
    monitor_addr = args.monitor_addr
    monitor_port = int(args.monitor_port)

    try:
        proxy = TCPListener(server_addr, server_port, monitor_addr, monitor_port)
        proxy.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()