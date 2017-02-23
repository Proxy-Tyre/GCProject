import socket
import threading
import re
import subprocess
import multiprocessing
import json
import time
import argparse
from urllib import request
from IOfunc import *

# HOST=''
# MASTER_HOST='127.0.0.1'
# PORT_CLIENT=1888
# PORT_SERVER=2888

BUFSIZE=1024

STATUS_OK = 1
STATUS_NO = 0

PRECISION = 50


TIMEOUT = 3000

class Server(object):
	"""docstring for Server"""
	def __init__(self,interval_time=10,record_stick_time=300):
		super(Server, self).__init__()
		self.RECORD_STICK_TIME = record_stick_time
		self.INTERVAL_TIME = interval_time  

		self.domain_delay={}      
		self.domain_status={}             # {domain:[status,access_count,stick_time,start_time]}
		self.domain_status_judge_table={}       # {domain:[(success_url,200,length),(second_last_url,httpcode,length),(last_url,httpcode,length)]}
		
		self.set_addr_port()


		threading.Thread(target=self.debug).start()

		threading.Thread(target=self.report,args=(interval_time,)).start()

	def set_addr_port(self):
		parser = argparse.ArgumentParser()
		parser.add_argument("--host_addr", default="127.0.0.1", help="Default: 127.0.0.1")
		parser.add_argument("--host_port", default="2888", help="Default: 2888")
		parser.add_argument("--mesg_addr", default="127.0.0.1", help="Default: 127.0.0.1")
		parser.add_argument("--mesg_port", default="10044", help="Default: 10044")
		args = parser.parse_args()
		self.host_addr = args.host_addr
		self.host_port = args.host_port
		self.mesg_port = args.mesg_port
		self.mesg_addr = args.mesg_addr
		print('log: host addr ',self.host_addr)
		print('log: host port ',self.host_port)

	def connect(self):
		while True:
			try:
				sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				sock.connect((self.host_addr,self.host_port))
				return sock
			except:
				continue
		

	def debug(self):
		while True:
			print_all('Slave_server' , {'domain_delay':self.domain_delay,
				'domain_status':self.domain_status,
				'domain_status_judge_table':self.domain_status_judge_table})
			time.sleep(5)

	def add_domain(self,domain):
		if isinstance(domain,str):
			self.domain_delay[domain] = TIMEOUT
		if isinstance(domain,dict):
			for domain_item in domain:
				if domain_item not in self.domain_delay:
					self.add_domain(domain_item)


	def report(self,interval_time):
		threading.Thread(target=self.recv_access_message).start()
		while True:
			t = threading.Thread(target=self.update_domain_delay)
			t.start()
			while True:
				try:
					print('slave try to connect host server')
					sock = self.connect()
					break
				except:
					continue
			t.join()

			data_dict = {DataType.DELAY:self.domain_delay,
							DataType.STATUS:self.domain_status}
			send_data(sock,data_dict)

			data_list = recv_data(sock,BUFSIZE)

			sock.close()

			for datatype in data_list:
				if datatype == DataType.DOMAIN:
					self.add_domain(data_list[datatype])
			
			time.sleep(interval_time)

	def ping(self,host): 
		cmd_status,cmd_result = subprocess.getstatusoutput('ping '+host)
		if not cmd_status:
			p = re.compile('时间.(\d+?)ms')
			result = p.findall(cmd_result)
			sum_delay=0
			for delay in result:
				sum_delay+=int(delay)
			if result:
				return sum_delay/len(result)
			
	# below are used to update the doamin_dalay
	def evaluate(self,host):
		t = self.ping(host)
		if t:
			self.domain_delay[host] = int(t)
		else:
			self.domain_delay[host] = TIMEOUT

		
	def update_domain_delay(self):
		thread_pool=[]
		for test in self.domain_delay:
			t = threading.Thread(target=self.evaluate,args=(test,))
			t.start()
			thread_pool.append(t)
		for thread in thread_pool:
			thread.join()


	# below are used to receive the message
	def recv_access_message(self):
		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.bind((self.mesg_addr, int(self.mesg_port)))
		listener.listen(100)
		print('log: message addr ',self.mesg_addr)
		print('log: message port ',self.mesg_port)

		while True:
			try:
				conn, addr = listener.accept()
				print("connect from %s:%d" % addr)
				
				while True:
					data = conn.recv(8192)
					if not data:
						break
					conn.send(b"OK")
					try:
						data = data.decode()
						url, code, contentLen = data.split("\r\n")
						if code:
							code = int(code)
						else:
							code = 0
						if contentLen:
							contentLen = int(contentLen)
						else:
							contentLen = 0
						threading.Thread(target=self.handle_access_message,args=(url,code,contentLen)).start()
					except Exception as e:
						pass
			except KeyboardInterrupt:
				break
			except Exception as e:
				print(e)


	def handle_access_message(self,url,code,contentLen):
		if contentLen == None:
			contentLen = 0
		domain = get_domain(url)
		if domain:
			if domain in self.domain_status:
				if not self.recode_is_timeout(self.domain_status[domain]):
					status_list = self.domain_status[domain]
					# update_domain_status_judge_table(data_list[0],data_list[1],data_list[2])
					status_list[1]+=1
					status_list[2] = round(time.time())-status_list[3]
				else:
					self.domain_status[domain]=[]
					self.domain_status[domain].append(STATUS_OK)
					self.domain_status[domain].append(1)
					self.domain_status[domain].append(0)
					self.domain_status[domain].append(round(time.time()))					
			else:
				self.domain_status[domain]=[]
				self.domain_status[domain].append(STATUS_OK)
				self.domain_status[domain].append(1)
				self.domain_status[domain].append(0)
				self.domain_status[domain].append(round(time.time()))
			self.update_domain_status_judge_table(url,code,contentLen)		


	def recode_is_timeout(self,status_list):
		if status_list[2] + self.RECORD_STICK_TIME > round(time.time())-status_list[3]:
			return False
		return True

	def update_domain_status_judge_table(self,url,code,content_length):
		domain = get_domain(url)
		record = (url,code,content_length)

		if domain not in self.domain_status_judge_table:
			if code == 200:
				# threading.Thread(target = self.add_first_success_to_judge_table,args =(url,)).start()
				self.add_first_success_to_judge_table(url,code,content_length)
		else:
			if len(self.domain_status_judge_table[domain]) > 2:
				if self.check_at_this_access(url,code,content_length):
					self.domain_status_judge_table[domain][1]=self.domain_status_judge_table[domain][2]
					self.domain_status_judge_table[domain][2]=record
			else:
				self.domain_status_judge_table[domain].append(record)
		# print(self.domain_status_judge_table)

	def add_first_success_to_judge_table(self,url,code,content_length):
		if not content_length:
			for i in range(0,3):
				try:
					response = request.urlopen(url)
					record = (url,response.code,response.length)
					self.domain_status_judge_table[get_domain(url)] = []
					self.domain_status_judge_table[get_domain(url)].append(record)
					print('first success record: ',record)
					break
				except:
					continue
		else:
			record = (url,code,content_length)
			self.domain_status_judge_table[get_domain(url)] = []
			self.domain_status_judge_table[get_domain(url)].append(record)
			print('first success record: ',record)

	def check_at_this_access(self,url,code,content_length):
		domain=get_domain(url)
		if url != self.domain_status_judge_table[domain][2][0] and code == self.domain_status_judge_table[domain][2][1] and content_length < self.domain_status_judge_table[domain][2][2]+PRECISION and content_length > self.domain_status_judge_table[domain][2][2]-PRECISION:
			if url != self.domain_status_judge_table[domain][1][0] and code == self.domain_status_judge_table[domain][1][1] and content_length < self.domain_status_judge_table[domain][1][2]+PRECISION and content_length > self.domain_status_judge_table[domain][1][2]-PRECISION:
				if url != self.domain_status_judge_table[domain][0][0] and code == self.domain_status_judge_table[domain][0][1] and content_length < self.domain_status_judge_table[domain][0][2]+PRECISION and content_length > self.domain_status_judge_table[domain][0][2]-PRECISION:
					return False
				elif not self.check_the_same_with_success_url(domain,url,code,content_length):
					status = self.domain_status[domain]
					status[0] = STATUS_NO
					status[2] = time.time()-status[3]
					return False
		return True

	def check_the_same_with_success_url(self,domain,url,code,content_length):
		print('check_the_same_with_success_url')
		try:
			recode = self.domain_status_judge_table[domain][0]
			target_url = recode[0]
			target_code = recode[1]
			target_length = recode[2]
		except:
			return False
		
		for i in range(0,3):
			try:
				response = request.urlopen(target_url)
				if target_code == response.code and target_length < response.length+PRECISION and target_length > response.length-PRECISION:
					return True
				else:
					return False
			except:
				if i > 1:
					return False

if __name__ == '__main__':
	r=Server()
	# r.handle_access_message('https://www.baidu.com',200,11234)



