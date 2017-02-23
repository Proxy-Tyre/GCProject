import socket
import subprocess
import threading
import re
import time
import json
import argparse
from IOfunc import *



BUFSIZE=1024

TIMEOUT = 3000

def get_domain(url):
	pattern = re.compile('https?://(.+?)/')
	try:
		return pattern.match(url+'/').group(1)
	except:
		return

class Client(object):
	"""docstring for Client"""
	def __init__(self,interval_time=10):
		super(Client, self).__init__()
		self.server_delay={}
		self.domain_delay={}
		self.server_status={}
		# self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		
		self.set_host_port()
		threading.Thread(target=self.debug).start()
		threading.Thread(target=self.update_server_status,args=(interval_time,)).start()

	def set_host_port(self):
		parser = argparse.ArgumentParser()
		parser.add_argument("--host_addr", default="127.0.0.1", help="Default: 127.0.0.1")
		parser.add_argument("--host_port", default="1888", help="Default: 1888")
		args = parser.parse_args()
		self.HOST=args.host_addr
		self.PORT=(int)(args.host_port)

	def debug(self):
		while True:
			print_all('Client_monitor',{'server_delay':self.server_delay,
				'domain_delay':self.domain_delay,
				'server_status':self.server_status})
			time.sleep(5)

	def add_domain(self,domain):
		sock = self.connect()

		domain_data = {domain:TIMEOUT}
		data = {DataType.CONSTRUCTION:RECV,DataType.DOMAIN:domain_data}
		sock.send(packData(data))
		self.domain_delay[domain] = TIMEOUT
		print('add dommain ',domain)
		sock.close()


	def add_url(self,url):
		self.domain_delay[get_domain(url)] = TIMEOUT

	def connect(self,host=None,port=None):
		sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		if host == None:
			host = self.HOST
		if port == None:
			port = self.PORT
		while True:
			try:
				# print('tring connect to server')
				sock.connect((host,port))
				# print('connect success')
				return sock
			except:
				continue

		
	def update_server_status(self,interval_time):
		while True:
			threading.Thread(target=self.update_server_delay).start()
			# print('start connentc')
			sock = self.connect()
			# print("connect success")
			# sock.settimeout(5)
			data = {DataType.CONSTRUCTION:SEND}
			send_data(sock,data)
			data_dict = recv_data(sock,BUFSIZE)

			# print(data_dict)

			for datatype in data_dict:
				if datatype == DataType.DELAY:
					self.domain_delay = data_dict[datatype]
					continue
				if datatype == DataType.STATUS:
					self.server_status = data_dict[datatype]
					continue
				if datatype == DataType.SERVER:
					for server in data_dict[datatype]:
						if server not in self.server_delay:
							self.server_delay.update(data_dict[datatype])

			sock.close()
			
			time.sleep(interval_time)


	# under are self things

	def clear_server_delay(self):
		for server in self.server_delay:
			self.server_delay[server] = TIMEOUT


	def ping(self,host):
		result = ping(host)
		if result:
			sum_dalay=0
			for delay in result:
				sum_dalay+=delay
			self.server_delay[host]=int(sum_dalay/len(result))
		else:
			self.server_delay[host] = TIMEOUT

		# check all the delay of agency
	def update_server_delay(self):
		# print('update_server_delay')
		# self.clear_server_delay()
		thread_pool=[]
		for server in self.server_delay:
			t = threading.Thread(target=self.ping,args=(server,))
			t.start()
			thread_pool.append(t)
		for thread in thread_pool:
			thread.join()
		# print(self.server_delay)


if __name__ == '__main__':
	s=Client(10)
	# s.connect()
	s.add_domain('bing.com')
	s.add_domain('baidu.com')
	# s.set_host_port(host,port)
	# s.update_server_status(10)
