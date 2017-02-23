# -*- coding: utf-8 -*-

import socket
import threading
import time
import datetime
import logging
import argparse
import select
from server import Connection as AbstractConnection

logger = logging.getLogger(__name__)

BUFF_SIZE = 8192


class Connection(AbstractConnection):
    """docstring for Connection"""
    def __init__(self, conn, addr):
        super(Connection, self).__init__()
        self.conn = conn
        self.addr = addr
        

class Proxy(threading.Thread):
    """docstring for Proxy"""
    def __init__(self, client, server):
        super(Proxy, self).__init__()
        self.client = client
        self.server = server
        self.lastActivity = datetime.datetime.utcnow()

    def _now(self):
        return datetime.datetime.utcnow()

    def _isInactive(self):
        return (self._now() - self.lastActivity).seconds > 10

    def _process_rlist(self, r):
        if self.client.conn in r:
            data = self.client.recv()

            self.lastActivity = self._now()

            if not data:
                return True

            self.server.queue(data)

        if self.server and not self.server.isClosed and self.server.conn in r:
            data = self.server.recv()
            self.lastActivity = self._now()
            if not data:
                self.server.close()
            else:
                self.client.queue(data)
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

            if self.client.getBufferSize() == 0 and self._isInactive():
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
            self.server.close()
            logger.debug("Closing proxy for connection %r at address %r" % (self.client.conn, self.client.addr))

class TCPListener(object):
    """docstring for TCPServer"""

    def __init__(self, localIP, localPort):
        super(TCPListener, self).__init__()
        self.localIP = localIP
        self.localPort = localPort
        
        self.localServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.localServer.bind((localIP, localPort))
        self.localServer.listen(1024)

        
    def run(self):
        logger.info("Start service on  %s:%d  ..." % (self.localIP, self.localPort))

        while True:
            try:
                localConn, localAddr = self.localServer.accept()
                self._handleConn(localConn, localAddr)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt! Quit...")
                break
            except Exception as e:
                logger.exception("Exception when listen: %r" % e)
                break

            
            logger.info("Request from %s:%d" % localAddr)

        self.localServer.close()



    def _handleConn(self, localConn, localAddr):
        
        remoteAddr = self._getRemoteServer()
        remoteConn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remoteConn.connect(remoteAddr)
        except Exception as e:
            localConn.close()
            logger.exception("Exception when handleConn: %r" % e)
            return
        client = Connection(localConn, localAddr)
        server = Connection(remoteConn, remoteAddr)
        Proxy(client, server).start()


    def _getRemoteServer(self):
        remoteIP = "127.0.0.1"
        remotePort = 10042
        return (remoteIP, remotePort)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--local-addr", default="127.0.0.1", help="Default: 127.0.0.1")
    parser.add_argument("--local-port", default="10024", help="Default: 10024")
    parser.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR, CRITICAL")

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s - %(levelname)s - threadid:%(thread)d - %(message)s")

    local_addr = args.local_addr
    local_port = int(args.local_port)

    try:
        proxy = TCPListener(local_addr, local_port)
        proxy.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()