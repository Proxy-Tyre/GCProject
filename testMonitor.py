
import socket
import random
import time
import threading
import IOfunc

ip = "127.0.0.1"
port = 10044

testSet = set()

class Handler(threading.Thread):
	"""docstring for Handler"""
	def __init__(self, conn, addr):
		super(Handler, self).__init__()
		self.conn = conn
		self.addr = addr

	def run(self):
		while True:
			data = self.conn.recv(8192)
			if not data:
				break
			self.conn.send(b"OK")


			
			# if data not in testSet:
			# 	testSet.add(data)
			# else:
			print(IOfunc.getData(data))
			# time.sleep(1)


def main():
	listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listener.bind((ip, port))
	listener.listen(100)

	print("start at %s:%d" % (ip, port))

	while True:
		try:
			conn, addr = listener.accept()
			print("connect from %s:%d" % addr)
			Handler(conn, addr).start()
		except KeyboardInterrupt:
			break
		except Exception as e:
			print(e)



if __name__ == '__main__':
	main()