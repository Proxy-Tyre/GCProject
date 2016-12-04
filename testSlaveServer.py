from urllib import request
import threading
import time
import SlaveServer
import random
import multiprocessing
import http
import urllib
from IOfunc import *

queue = multiprocessing.Queue()
global judge 
judge = True
def task():
	while True:
		try:
			url = 'https://search.yahoo.com/search?p='+random_str()
			# url = 'https://www.google.co.jp/search?site=&source=hp&btnG=Google+%E6%90%9C%E7%B4%A2&q='+random_str()
			req = request.Request(url)
			response = request.urlopen(req,timeout=8)
			# print(response)
			content = response.read()
			print((url,response.code,len(content)))
			queue.put((url,response.code,len(content)))
		except Exception as e:
			if isinstance(e,urllib.error.HTTPError):
				print(e.getcode(),e)
				queue.put((url,e.getcode(),0))
			else:
				print(type(e))
				print(e)
			# break

def random_str():
	s = ''
	for i in range(6):
		p = round(random.random()*100%26)+97
		s+=chr(p)
	return s

threadpool = []
for i in range(1):
	t = threading.Thread(target=task).start()
	threadpool.append(t)

slaveserver = SlaveServer.Server()
judge = True

while judge:
	item= queue.get()
	for key in slaveserver.domain_status:
		if slaveserver.domain_status[key][0]!=1:
			judge = False
	slaveserver.handle_access_message({ConnectionType.SUCCESS:[item[0],item[1],item[2]]} )

print('finish!lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll')
