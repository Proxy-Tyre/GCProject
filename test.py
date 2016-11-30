from urllib import request
import threading
import time

while(True):
	try:
		req = request.Request('https://www.baidu.com/')
		req.set_proxy(host='127.0.0.1:10024',type='https')

		request.urlopen(req,timeout=8)
		time.sleep(10)
	except:
		print('fail to connect ...')
		continue


# req = request.Request('http://www.scut.edu.cn/academic')
# req.set_proxy(host='127.0.0.1:10024',type='http')	

# request.urlopen(req)


# req = request.Request('http://www.scut.edu.cn/academic')
# req.set_proxy(host='127.0.0.1:10024',type='http')

# request.urlopen(req)

