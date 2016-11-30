# -*- coding: utf-8 -*-

import socket
import threading
import time
import logging
import argparse

logger = logging.getLogger(__name__)

BUFF_SIZE = 8192


class ConnAlgorithm(threading.Thread):
    """docstring for ConnAlgorithm"""
    def __init__(self):
        super(ConnAlgorithm, self).__init__()
        self.daemon = True

        alIP = "127.0.0.1"
        alPort = 10027
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiver.connect((alIP, alPort))
        self.ipPortList = []

    def run(self):
        while True:
            try:
                data = self.receiver.recv(8192)
                self._update(data)
            except Exception as e:
                logger.exception("Exception in ConnAlgorithm: %r" % e)
                time.sleep(1)
            

    def _update(self, data):
        logger.info("update ip:port list: %s" % data.decode())
        self.ipPortList = data.decode().split(" ")
                
        


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

        # self.connAlgorithm = ConnAlgorithm()
        # self.connAlgorithm.start()

        while True:
            try:
                (localConn, localAddr) = self.localServer.accept()
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt! Quit...")
                break
            except Exception as e:
                logger.exception("Exception when listen: %r" % e)
                break

            threading.Thread(target = self._handleConn, args=(localConn, localAddr), daemon=True).start()
            logger.info("Request from %s:%d" % localAddr)



    def _handleConn(self, localConn, localAddr):
        
        remoteIP, remotePort = self._getRemoteServer()

        remoteConn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remoteConn.connect((remoteIP, remotePort))
        except Exception as e:
            localConn.close()
            logger.exception("Exception when handleConn: %r" % e)
            return

        threading.Thread(target=self._dataTrans, args=(localConn, remoteConn), daemon=True).start()
        threading.Thread(target=self._dataTrans, args=(remoteConn, localConn), daemon=True).start()


    def _dataTrans(self, receiver, sender,l=False):
        while True:
            try:
                data = receiver.recv(BUFF_SIZE)
            except Exception as e:
                break
            if not data:
                break

            try:
                sender.sendall(data)
            except Exception as e:
                break
        
        logger.info("close connections...")

        receiver.close()
        sender.close()


    def _getRemoteServer(self):
        remoteIP = "127.0.0.1"
        remotePort = 10042
        return remoteIP, remotePort

        # while len(self.connAlgorithm.ipPortList) == 0:
        #     logger.info("No proxy server...")
        #     time.sleep(1)
        # addr = self.connAlgorithm.ipPortList[0].split(":")
        # return addr[0], int(addr[1])



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