# -*- coding: utf-8 -*-

import argparse
import logging
import threading
import datetime
import socket
import select
import sys
import queue
import time
PY3 = sys.version_info[0] == 3

if PY3:
    from urllib import parse as urlparse
else:
    import urlparse

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


class ChunkParser(object):
    """HTTP chunked encoding response parser."""
    
    def __init__(self):
        self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
        self.body = b''
        self.chunk = b''
        self.size = None
    
    def parse(self, data):
        more = True if len(data) > 0 else False
        while more: more, data = self.process(data)
    
    def process(self, data):
        if self.state == CHUNK_PARSER_STATE_WAITING_FOR_SIZE:
            line, data = HTTPParser.split(data)
            self.size = int(line, 16)
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
        self.state = HTTP_PARSER_STATE_INITIALIZED
        self.type = type if type else HTTP_REQUEST_PARSER
        
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



class ProxyConnectionFailed(Exception):
    
    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason
    
    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)


class Proxy(threading.Thread):
    """docstring for Proxy"""
    def __init__(self, client, monitor):
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
        

    def _now(self):
        return datetime.datetime.utcnow()


    def _isInactive(self):
        return (self._now() - self.lastActivity).seconds > 30


    def _sendMessToMonitor(self):
        if self.response.state < HTTP_PARSER_STATE_HEADERS_COMPLETE or self.hasSentToMonitor:
            return

        url = self.request.url.geturl().decode()
        code = self.response.code.decode() if self.response.code else "None"
        if b'content-length' in self.response.headers:
            contentLen = str(int(self.response.headers[b'content-length'][1]))
        else:
            contentLen = "None"

        message = "%s\r\n%s\r\n%s" % (url, code, contentLen)
        print("\nthreadName:%s\nurl: %s\ncode: %s\ncontent-length: %s" % (self.name, url, code, contentLen))
        self.monitor.put(message.encode())
        self.hasSentToMonitor = True


    def _processRequest(self, data): 

        if self.server and not self.server.isClosed:
            self.server.queue(data)
            return

        self.request.parse(data)

        if self.request.state == HTTP_PARSER_STATE_COMPLETE:
            if self.request.method == b"CONNECT":
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80

            self.server = Server(host, port)

            try:
                self.server.connect()
            except Exception as e:
                self.server.isClosed = True
                raise ProxyConnectionFailed(host, port, repr(e))

            if self.request.method == b"CONNECT":
                self.client.queue(self.connection_established_pkt)
            else:
                self.server.queue(self.request.build(
                    del_headers=[b'proxy-connection', b'connection', b'keep-alive'], 
                    add_headers=[(b'Connection', b'Close')]                    
                ))

    def _processResponse(self, data):

        if not self.request.method == b"CONNECT":
            self.response.parse(data)       #cpu cost a lot?
        
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
        rlist, wlist, xlist = [self.client.conn], [], []

        if self.client.hasBuffer():
            wlist.append(self.client.conn)

        if self.server and not self.server.isClosed:
            rlist.append(self.server.conn)

            if self.server.hasBuffer():
                wlist.append(self.server.conn)

        return rlist, wlist, xlist


    def _process(self):
        while True:
            rlist, wlist, xlist = self._getLists()
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
        return self.conn.send(data)


    def recv(self, BUFFER_SIZE=8192):
        try:
            data = self.conn.recv(BUFFER_SIZE)
            if len(data) == 0:
                return
            return data
        except Exception as e:
            # logger.exception("Exception when receiving from %r: %r" % (self.conn, e))
            return

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


class Monitor(Connection, threading.Thread):
    """docstring for Monitor"""
    def __init__(self, host, port):
        super(Monitor, self).__init__()
        self.addr = (host, int(port))
        self.queue_send = queue.Queue()
        self.daemon = True
        self.reconnectTime = 0
        self.WAITTIME = 5
        self.isConnected = False

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

    def connect(self):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect(self.addr)
        except Exception as e:
            logger.warning("Exception when connect to remote monitor: %r" % e)
            return False

        return True
    
    def put(self, data):
        self.queue_send.put(data)


class Server(Connection):
    """docstring for Server"""
    def __init__(self, host, port):
        super(Server, self).__init__()
        self.addr = (host, int(port))


    def connect(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.addr[0], self.addr[1]))
        

class Client(Connection):
    """docstring for Client"""
    def __init__(self, conn, addr):
        super(Client, self).__init__(isClient=True)
        self.conn = conn
        self.addr = addr
        

class TCPListener(object):

    def __init__(self, serverAddr, serverPort, monitorAddr, monitorPort, backlog = 1024):
        self.serverAddr = serverAddr
        self.serverPort = serverPort
        self.monitor = Monitor(monitorAddr, monitorPort)
        self.backlog = backlog


    def handleConnection(self, conn, addr):
        client = Client(conn, addr)
        proxy = Proxy(client, self.monitor)
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
                conn, addr = listener.accept()
                logger.info("Accepted connection %r:%r" % (conn, addr))
                self.handleConnection(conn, addr)

        except Exception as e:
            logger.exception("TCPListener Exception: %r" % e)

        finally:
            logger.info("closing TCPListener...")
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
    logging.disable(logging.INFO)
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