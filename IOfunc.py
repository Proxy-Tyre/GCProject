import json
import re

class DataType:
	DOMAIN = '01'
	DELAY  = '02'
	STATUS = '03'
	SERVER = '04'
	CONSTRUCTION = '05'

SEP = '\r\n'.encode()
RECV = 'RECV'
SEND = 'SEND'

def getkey(tup):
	return tup[1]

def get_domain(url):
	pattern = re.compile('https?://(.+?)/')
	try:
		return pattern.match(url+'/').group(1)
	except:
		return

def getData(data_bytes):
	data = {}
	data_list = data_bytes.split(SEP)[:-1]
	if len(data_list)%2 == 0:
		index = 0
		while index < len(data_list):
			data[data_list[index].decode()]=data_list[index+1].decode()
			index+=2
		_decode_data(data)
		return data
	else:
		print('warning: data not complete!!')

def packData(data_dict):
	# print(data_dict)
	data=b''
	for datatpye in data_dict:
		data += _encode_data(datatpye,data_dict[datatpye])
	return data


def _decode_data(data):
	for item in data:
		if item != DataType.CONSTRUCTION:
			data[item] = json.loads(data[item])
			continue


def _encode_data(datatype,data):
	if datatype != DataType.CONSTRUCTION:
		return  datatype.encode()+SEP+json.dumps(data).encode()+SEP
	return datatype.encode()+SEP+data.encode()+SEP

def recv_data(conn,buffer_size):
	raw_data = conn.recv(buffer_size)
	readable_data = getData(raw_data)
	return readable_data

def send_data(conn,data_dict):
	raw_data = packData(data_dict)
	conn.send(raw_data)

def print_all(kind,data_dict):
	print('\n*******************************')
	print(kind,'\n')
	for key in data_dict:
		print(key,' : ',data_dict[key])
	print('*******************************\n')


if __name__ == '__main__':
	data = packData({DataType.CONSTRUCTION:RECV})
	print(data)
	origindata = getData(data)
	print(origindata)
	# print_all({'data':{'1':2}})