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
STATUS_NOT_SURE = 2

PRECISION = 50


TIMEOUT = 3000

class Server(object):
	"""docstring for Server"""
	def __init__(self):
		super(Server, self).__init__()
		# self.RECORD_STICK_TIME = record_stick_time
		# self.INTERVAL_TIME = interval_time  

		self.domain_delay={}      
		self.domain_status={}             # {domain:[status,access_count,stick_time,start_time]}
		self.domain_status_judge_table={}       # {domain:[(success_url,200,length),(second_last_url,httpcode,length),(last_url,httpcode,length)]}
		
		self.set_addr_port()

		self.recv_data_pool = []


		threading.Thread(target=self.debug).start()

		threading.Thread(target=self.handle_access_message).start()

		threading.Thread(target = self.clear_old_record).start()

		threading.Thread(target=self.report).start()



	def set_addr_port(self):
		parser = argparse.ArgumentParser()
		parser.add_argument("--host_addr", default="127.0.0.1", help="Default: 127.0.0.1")
		parser.add_argument("--host_port", default="2888", help="Default: 2888")
		parser.add_argument("--mesg_addr", default="0.0.0.0", help="Default: 0.0.0.0")
		parser.add_argument("--mesg_port", default="10044", help="Default: 10044")
		parser.add_argument("--hold_time", default="300", help="Default: 300")
		parser.add_argument("--report_freq", default="10", help="Default: 10")
		parser.add_argument("--clear_freq", default="14400", help="Default: 14400")
		args = parser.parse_args()
		self.host_addr = (str)(args.host_addr)
		self.host_port = (int)(args.host_port)
		self.mesg_port = (int)(args.mesg_port)
		self.mesg_addr = (str)(args.mesg_addr)
		self.RECORD_STICK_TIME = (int)(args.hold_time)
		self.INTERVAL_TIME = (int)(args.report_freq)
		self.clear_freq = (int)(args.clear_freq)

	def clear_old_record(self):
		time.sleep(self.clear_freq)
		for domain in self.domain_status:
			if self.recode_is_timeout(self.domain_status[domain]):
				self.domain_status.pop(domain)

	def connect(self):
		while True:
			try:
				sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				sock.connect((self.host_addr,self.host_port))
				print('success to connect the host_server: ',self.host_addr,self.host_port)
				return sock
			except Exception as e:
				# print(e)
				print('fail to connect the host_server: ',self.host_addr,self.host_port)
			time.sleep(5)
		

	def debug(self):
		while True:
			print_all('Slave_server' , {'domain_delay':self.domain_delay,
				'domain_status':self.domain_status,
				'recv_data_pool size':len(self.recv_data_pool)})
			# ,'domain_status_judge_table':self.domain_status_judge_table})
			time.sleep(5)

	def add_domain(self,domain):
		if isinstance(domain,str):
			self.domain_delay[domain] = TIMEOUT
		if isinstance(domain,dict):
			for domain_item in domain:
				if domain_item not in self.domain_delay:
					self.add_domain(domain_item)


	def report(self):
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
			
			time.sleep(self.INTERVAL_TIME)

	def ping_for_windows(self,host): 
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
		t = ping(host)
		if t:
			r = 0
			for d in t:
				r+=d
			self.domain_delay[host] = int(r/len(t))
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


	# below are used to receive the 
	def recv_access_message(self):
		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.bind((self.mesg_addr, int(self.mesg_port)))
		listener.listen(100)
		print('log: message addr ',self.mesg_addr)
		print('log: message port ',self.mesg_port)

		while True:
			try:
				print('.........waiting for message giver...........')
				conn, addr = listener.accept()
				print("connect from %s:%d" % addr)
				count = 5
				while True:
					try:
						data = recv_data(conn,BUFSIZE)

						if not data:
							if count > 0:
								count = count - 1
								continue
							else:
								print('connection maybe close')
								conn.close()
								break
						count = 5

						self.recv_data_pool.append(data)
						# for datatype in data:
						# 	if datatype == DataType.CONNECTION:
						# 		threading.Thread(target=self.handle_access_message,args=(data[datatype],)).start()
						# if not data:
						# 	print('recieved none data, conn close')
						# 	conn.close()
						# 	break
					except Exception as e:
						print(e)
						break

			except KeyboardInterrupt:
				break
			except Exception as e:
				print(e)

		print('not recieving message!!!!!')


	def handle_access_message(self):
		while True:
			while self.recv_data_pool:
				data = self.recv_data_pool.pop()
				print(data)
				if not data:
					continue
				try:
					for datatype in data:
						if datatype == DataType.CONNECTION:
							tempdata = data[datatype]
							for connectiontype in tempdata:
								if connectiontype == ConnectionType.SUCCESS:
									self._handle_success_connection_message(tempdata[connectiontype])
								if connectiontype == ConnectionType.CONNECTED:
									self._handle_connected_connection_message(tempdata[connectiontype])
				except Exception as e:
					print(e)
			time.sleep(1)
			
			
	def _add_count_to_record(self,domain):
		status_list = self.domain_status[domain]
		status_list[1]+=1
		status_list[2] = round(time.time())-status_list[3]


	def _refresh_domain_status(self,domain):
		self.domain_status[domain]=[]
		self.domain_status[domain].append(STATUS_NOT_SURE)
		self.domain_status[domain].append(1)
		self.domain_status[domain].append(0)
		self.domain_status[domain].append(round(time.time()))


	def _handle_success_connection_message(self,datalist):
		url = datalist[0]
		code = datalist[1]
		contentLen = datalist[2]
		domain = get_domain(url)
		if domain:
			if domain in self.domain_status and not self.recode_is_timeout(self.domain_status[domain]):
				self._add_count_to_record(domain)
			else:
				self._refresh_domain_status(domain)
			if not code:
				code = 0
			if not contentLen:
				contentLen = 0
			self.update_domain_status_judge_table(url,code,contentLen)



	def _handle_connected_connection_message(self,url):
		domain = get_domain(url)
		if domain:
			if domain in self.domain_status and not self.recode_is_timeout(self.domain_status[domain]):
				self._add_count_to_record(domain)
			else:
				self._refresh_domain_status(domain)
			



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
				self.domain_status[domain][0] = STATUS_OK
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
		if code == self.domain_status_judge_table[domain][2][1] and content_length < self.domain_status_judge_table[domain][2][2]+PRECISION and content_length > self.domain_status_judge_table[domain][2][2]-PRECISION:
			if code == self.domain_status_judge_table[domain][1][1] and content_length < self.domain_status_judge_table[domain][1][2]+PRECISION and content_length > self.domain_status_judge_table[domain][1][2]-PRECISION:
				if code == self.domain_status_judge_table[domain][0][1] and content_length < self.domain_status_judge_table[domain][0][2]+PRECISION and content_length > self.domain_status_judge_table[domain][0][2]-PRECISION:
					status = self.domain_status[domain]
					status[0] = STATUS_NO
					status[2] = time.time()-status[3]					
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

