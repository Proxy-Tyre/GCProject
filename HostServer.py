import socket
import threading
import re
import subprocess
import multiprocessing
import json
import time
from urllib import request
from IOfunc import *

# HOST=''
# MASTER_HOST='192.168.74.1'

# PORT_SERVER=2888

BUFSIZE=1024

STATUS_OK = 1
STATUS_NO = 0

PRECISION = 50


TIMEOUT = 3000



class Server(object):
	"""docstring for Server"""
	def __init__(self):
		super(Server, self).__init__()

		self.HOST = ''
		self.PORT_CLIENT=1888
		self.PORT_SERVER=2888

		self.online_server = {}

		self.clawer_domain = {}

		self.global_domain_delay={}
		self.global_domain_status={}

		threading.Thread(target=self.debug).start()

		threading.Thread(target=self.listen_client).start()
		threading.Thread(target=self.listen_server).start()
		

	def set_client_port(self,port):
		self.PORT_CLIENT = port

	def set_server_port(self,port):
		self.PORT_SERVER = port

	def debug(self):
		while True:
			print_all('Host_server',{'online_server':self.online_server,
				'clawer_domain':self.clawer_domain,
				'global_domain_delay':self.global_domain_delay,
				'global_domain_status':self.global_domain_status})
			time.sleep(5)


	def listen_client(self):
		print('start listen for client...')
		
		self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.socket.bind((self.HOST,self.PORT_CLIENT))
		self.socket.listen(5)
		while 1:
			conn,addr = self.socket.accept()
			print("connected client by ",addr)
			threading.Thread(target=self.client_thread,args=(conn,addr)).start()
		self.socket.close()

	def listen_server(self):
		print('start listen for server...')

		self.socket_s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.socket_s.bind((self.HOST,self.PORT_SERVER))
		self.socket_s.listen(5)
		while 1:
			conn,addr = self.socket_s.accept()
			print('connected server by ',addr)
			self.online_server[addr[0]] = TIMEOUT
			threading.Thread(target=self.server_thread,args=(conn,addr)).start()
		self.socket.close()

	def server_thread(self,conn,addr):
		data = recv_data(conn,BUFSIZE)

		for datatype in data:
			if datatype == DataType.DELAY:
				self.update_domain_delay(addr,data[datatype])
				continue
			if datatype == DataType.STATUS:
				self.merge_status_table(addr,data[datatype])

		
		data = {DataType.DOMAIN:self.clawer_domain}
		send_data(conn,data)

		# print(self.global_domain_status)
		conn.close()

	def client_thread(self,conn,addr):
		data_from_client = recv_data(conn,BUFSIZE)
		# print(data_from_client)

		for datatype in data_from_client:
			if datatype == DataType.CONSTRUCTION:
				construction = data_from_client[datatype]
			if datatype == DataType.DOMAIN:
				self.add_domain(data_from_client[datatype])

		data = {DataType.SERVER:self.online_server,DataType.DELAY:self.global_domain_delay,
								DataType.STATUS:self.global_domain_status}
		# print(data)
		send_data(conn,data)
		# print('send finish')

		conn.close()

	def add_domain(self,domain):
		# print(domain)
		if isinstance(domain,str):
			self.clawer_domain[domain] = TIMEOUT
		if isinstance(domain,dict):
			for domain_item in domain:
				if domain_item not in self.clawer_domain:
					self.add_domain(domain_item)

	def update_domain_delay(self,addr,delay_list):
		addr = addr[0]
		for domain in delay_list:
			if domain not in self.global_domain_delay:
				self.global_domain_delay[domain] = {addr:delay_list[domain]}
			else:
				self.global_domain_delay[domain].update({addr:delay_list[domain]})

	# def merge_speed_table(self,addr,block):
	# 	for item in block:
	# 		if item in self.global_domain_delay:
	# 			if len(self.global_domain_delay[item][addr[0]]) > 4 :
	# 				self.global_domain_delay[item][addr[0]].pop(0)
	# 			self.global_domain_delay[item][addr[0]].append(block[item])
	# 		else:
	# 			self.global_domain_delay[item]={addr[0]:[block[item]]}

	def merge_status_table(self,addr,block):
		for domain in block:
			if domain in self.global_domain_status:
				self.global_domain_status[domain].update({addr[0]:block[domain]})
			else:
				self.global_domain_status[domain]={addr[0]:block[domain]}
				

		# when this is the host server, sort all the server-website speed list and return a suggest list 
	def sort(self):
		temp={}
		for domain in self.global_domain_delay:
			temp[domain]=[]
			for addr in self.global_domain_delay[domain]:
				if self.global_domain_delay[domain][addr][-1] != TIMEOUT:
					length = len(self.global_domain_delay[domain][addr])
					length-=1
					delay_avrg = 1/(1<<(length))*self.global_domain_delay[domain][addr][-1]
					for delay in self.global_domain_delay[domain][addr][:-1]:
						delay_avrg+=1/(1<<(length))*delay
						length-=1
					temp[domain].append((addr,delay_avrg))
				else:
					temp[domain].append((addr,TIMEOUT))
				
			temp[domain]=sorted(temp[domain],key=lambda tup:tup[1])
		return temp



if __name__ == '__main__':
	r=Server()
	# r.add_domain('www.bing.com')
	# r.basic_speed_evaluation()
	# print(get_domain('https://www.cnblogs.com'))

	
