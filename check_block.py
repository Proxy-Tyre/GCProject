from urllib import request
import requests
import threading
import time

global count
count = 0

def connect():
	while True:
		try:
			
			url1 = 'https://www.zhihu.com/search?type=content&q=qq'
			url2 = 'http://music.163.com/#/search/m/?s=%E5%96%9C%E6%AC%A2%E4%BD%A0&type=1'
			url3 = 'https://movie.douban.com/subject_search?search_text=%E6%8D%A2&cat=1002'
			url4 = 'http://s.hongxiu.com/searchresult.aspx?iftitle=1&query=%B6%B7%C6%C6%B2%D4%F1%B7'
			
			#request.urlopen(req,timeout=8)
			proxies = {
                                'https':'128.199.90.107:10042',
                                'http':'128.199.90.107'}
			requests.get(url4,proxies = proxies,verify = False)
			
			global count
			count = count + 1
			print(count)
		except Exception as e:
			print(e)
			continue

for i in range(12):
	threading.Thread(target=connect).start()
