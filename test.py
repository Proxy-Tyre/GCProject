from urllib import request
import threading
import time

while(True):
	try:
		req = request.Request('https://github.com/')
		req.set_proxy(host='128.199.90.107:10042',type='https')

		request.urlopen(req,timeout=8)
	except:
		print('fail to connect ...')
	time.sleep(1)


# req = request.Request('http://www.scut.edu.cn/academic')
# req.set_proxy(host='127.0.0.1:10024',type='http')	

# request.urlopen(req)


# req = request.Request('http://www.scut.edu.cn/academic')
# req.set_proxy(host='127.0.0.1:10024',type='http')

# request.urlopen(req)

