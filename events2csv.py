#!/usr/bin/python3


import sys
import json
import base64
import ntpath
import socket
import sqlite3
import argparse 
import datetime


def filetime2datetime(filetime_timestamp):
	datetime_timestamp = (datetime.datetime(1601, 1, 1).replace(tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=int(filetime_timestamp) // 10))
	return datetime_timestamp


def datetime2filetime(datetime_timestamp):
	filetime_timestamp = int((datetime_timestamp - datetime.datetime(1601, 1, 1).replace(tzinfo=datetime.timezone.utc)).total_seconds() * 10000000)
	return filetime_timestamp

def datetime2string(datetime_timestamp):
	string_timestamp = datetime_timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
	return string_timestamp

def queryDB(input_file, date_filter):
	events_query = "SELECT timestamp,name,pid,ppath,username,int1,int2,int3,int4,str1,str2,str3,str4,data1,data2,event_id,flag1 FROM events LEFT JOIN event_types ON events.type_id = event_types.id"
	stats_query = "SELECT name, first_event, last_event, event_count FROM (SELECT type_id, MIN(timestamp) as first_event, MAX(timestamp) as last_event, count(timestamp) as event_count FROM events GROUP BY type_id) LEFT JOIN event_types ON type_id = event_types.id"
	if date_filter:
		try:
			start_datetime = datetime.datetime.strptime(date_filter.split("/")[0].strip(),"%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
			stop_datetime = datetime.datetime.strptime(date_filter.split("/")[1].strip(),"%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
		except:
			print("[-] Error - ",sys.exc_info())
			print("[-] Exiting ...")
			exit(1)	
		if stop_datetime > start_datetime:
			start_filetime = datetime2filetime(start_datetime)
			stop_filetime = datetime2filetime(stop_datetime)
			events_query += " WHERE timestamp >= " + str(start_filetime) + " AND timestamp <= " + str(stop_filetime)
		else:
			print("[-] Error - Filter end timestamp must be greater than start timestamp")
			print("[-] Exiting ...")
			exit(1)
	events_query += " ORDER BY timestamp,sequence_num ASC"
	print("[+] Querying DB ...")
	try:
		db_connection = sqlite3.connect("file:"+ input_file + "?mode=ro",uri=True)
		cursor = db_connection.execute(events_query)
		events_result = cursor.fetchall()
		cursor = db_connection.execute(stats_query)
		stats_result = cursor.fetchall()
	except:
		print("[-] Error - ",sys.exc_info())
		print("[-] Exiting ...")
		exit(1)
	db_connection.close()	
	return events_result, stats_result


def printStats(events_result,stats_result):
	print("[+] Extracted " + str(len(events_result)) + " records")
	print("[+] Events from " + datetime2string(filetime2datetime(events_result[0][0])) + " to " + datetime2string(filetime2datetime(events_result[-1][0])))
	for stat in stats_result:
		first_event_timestamp = datetime2string(filetime2datetime(stat[1]))
		last_event_timestamp = datetime2string(filetime2datetime(stat[2]))
		print("[+] " + str(stat[3]) + " " + stat[0] + " events, from " + first_event_timestamp + " to: " + last_event_timestamp)
	return


def getdnsLookupEventData(db_row):
	domain = str(db_row[9]) #str1
	message = "Process " + ntpath.basename(str(db_row[3])) + " query DNS for " + domain
	return domain, message


def getaddressNotificationEventData(db_row):
	if len(db_row[13]) == 4: 
		#IPv4
		ip_address = '.'.join(str(c) for c in db_row[13]) #data1
	else:
		#IPv6
		ip_address = ':'.join(db_row[13].hex()[i:i+4] for i in range(0, len(db_row[13].hex()), 4)) #data1
	message = "Change IP Address to " + ip_address
	return ip_address, message


def getimageLoadEventData(db_row):
	loaded_DLL = str(db_row[9]) #str1
	device_path = str(db_row[10]) #str2
	message = "Process " + ntpath.basename(str(db_row[3])) + " load DLL " + loaded_DLL
	return loaded_DLL, device_path, message
	
	
def getprocessEventData(db_row):
	process_status_dict = {1:"start", 2:"end", 3:"running"}
	parent_process = str(db_row[9]) #str1
	parent_pid = str(db_row[5]) #int1
	start_time = "" #int3
	if db_row[7]:
		start_time = datetime2string(filetime2datetime(db_row[7]))
	hash = "" #data1
	if db_row[13]:
		hash = db_row[13].hex()
	command_line = str(db_row[11]) #str3
	status = process_status_dict[db_row[6]] #int2
	message = "Process " + ntpath.basename(str(db_row[3])) + " " + status
	if status == "start":
		message += " by " + ntpath.basename(parent_process)
	return parent_process, parent_pid, start_time, hash, command_line, status, message


def protonameByNum(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return str(name[8:])
    return ""


def getipv4NetworkEventData(db_row):
	if len(db_row[14]) == 4:
		#IPv4
		source_ip = '.'.join(str(c) for c in db_row[14]) #data2
	else:
		#IPv6
		source_ip = ':'.join(db_row[14].hex()[i:i+4] for i in range(0, len(db_row[14].hex()), 4)) #data2
	if len(db_row[13]) == 4:
		#IPv4
		destination_ip = '.'.join(str(c) for c in db_row[13]) #data1
	else:
		#IPv6
		destination_ip = ':'.join(db_row[13].hex()[i:i+4] for i in range(0, len(db_row[13].hex()), 4)) #data1
	source_port = str(db_row[6]) #int2
	destination_port = str(db_row[5]) #int1
	protocol = protonameByNum(db_row[7]) #int3
	message = "Process " + ntpath.basename(str(db_row[3])) + " connection from " + source_ip + ":" + source_port + " to " + destination_ip + ":" + destination_port
	return source_ip, source_port, destination_ip, destination_port, protocol, message


def guessFileType(start_bytes,mime_type_json):
	if mime_type_json:
		bytes = base64.b64decode(start_bytes)
		stream = " ".join(['{:02X}'.format(byte) for byte in bytes])
		for element in mime_type_json:
			for signature in element["signature"]:
				offset = element["offset"] * 2 + element["offset"]
				if signature == stream[offset:len(signature) + offset]:
					return element["mime"], element["extension"]
	return "", ""
	

def getfileWriteEventData(db_row,magic_sign_json):
	parent_process = str(db_row[11]) #str3
	device_path = str(db_row[10]) #str2
	file_path = str(db_row[9]) #str1
	number_of_writes = "" #int1
	if db_row[5]:
		number_of_writes = str(db_row[5]) 
	file_size = "" #int2
	if db_row[6]:
		file_size = str(db_row[6]) 
	bytes_written = "" #int3
	if db_row[7]:	
		bytes_written = str(db_row[7]) 
	status = ""	#flag1
	if db_row[16] == 1:
		status = "Closed"
	hash = "" #data1
	if db_row[13]:
		hash = db_row[13].hex()
	data2 = json.loads(''.join(str(c) for c in db_row[14])) #data2
	parent_pid = "" #data2
	if "parentPid" in data2:
		parent_pid = str(data2["parentPid"])
	data = "" #data2
	mime_type = ""
	extension = ""
	if "data" in data2:
		data = data2["data"]
		mime_type, extension = guessFileType(data2["data"],magic_sign_json)
	open_time = "" #data2
	if "openTimeRaw" in data2:
		open_time = datetime2string(filetime2datetime(data2["openTimeRaw"]))
	event_reason = "" #data2
	if "eventReason" in data2:
		event_reason = str(data2["eventReason"])
	open_duration = "" #data2
	if "openDuration" in data2:
		open_duration = str(data2["openDuration"])
	message = "Process " + ntpath.basename(str(db_row[3])) + " write file " + ntpath.basename(file_path)
	return parent_process, device_path, file_path, number_of_writes, file_size, bytes_written, status, hash, parent_pid, data, mime_type, extension, open_time, event_reason, open_duration, message

	
def geturlMonitorEventData(db_row,encoding):
	if len(db_row[13]) == 4:
		#IPv4
		destination_ip = '.'.join(str(c) for c in db_row[13]) #data1
	else:
		#IPv6
		destination_ip = ':'.join(db_row[13].hex()[i:i+4] for i in range(0, len(db_row[13].hex()), 4)) #data1
	source_port = str(db_row[6]) #int2
	destination_port = str(db_row[5]) #int1
	http_method = str(db_row[9]) #str1
	http_request = db_row[10].decode(encoding).replace("\r\n"," | ")[0:-4] #str2
	host = destination_ip
	for header in db_row[10].decode(encoding).split("\r\n"):
		if "Host" in header or "host" in header:
			host = header.split(":")[1].strip()
			break
	message = "Process " + ntpath.basename(str(db_row[3])) + " HTTP " + http_method + " request to " + host + ":" + destination_port
	return source_port, destination_ip, destination_port, http_method, http_request, host, message


def getregKeyEventData(db_row,encoding):
	reg_modification_dict = {1:"change value", 2:"delete value", 3:"create key", 4:"delete key"} 
	value_type_dict = {1:"REG_SZ", 2:"REG_EXPAND_SZ", 3:"REG_BINARY", 4:"REG_DWORD", 5:"5 - Type not parsed", 6:"REG_LINK", 7:"REG_MULTI_SZ", 8:"8 - Type not parsed", 9:"9 - Type not parsed", 10:"10 - Type not parsed", 11:"REG_QWORD"} 
	modification_type = "" #int1
	if db_row[5]:
		modification_type = reg_modification_dict[db_row[5]] 
	value_type = "" #int2
	if db_row[6]:
		value_type = value_type_dict[db_row[6]] 
	path = str(db_row[9]) + "\\" + str(db_row[10]) #str1 + str2
	if db_row[12]:
		path += "\\" + str(db_row[12]) #+ str4
	value = "" #data1
	if db_row[13]:
		if db_row[6]:
			if db_row[6] == 1 or db_row[6] == 2 or db_row[6] == 6 or db_row[6] == 7: #REG_SZ - REG_EXPAND_SZ - REG_LINK - REG_MULTI_SZ
				value = db_row[13].decode(encoding)
			elif db_row[6] == 3: #REG_BINARY
				value = ""
			elif db_row[6] == 4 or db_row[6] == 11: #REG_DWORD - REG_QWORD
				value = "0x" + db_row[13].hex()
			else:
				value = "[" + ' '.join(db_row[13].hex()[i:i+2] for i in range(0, len(db_row[13].hex()), 2)) + "]" #Value not parsed, printing bytes
		else:
			value = "[" + ' '.join(db_row[13].hex()[i:i+2] for i in range(0, len(db_row[13].hex()), 2)) + "]" #Value type not present, printing bytes
	message = "Process " + ntpath.basename(str(db_row[3])) + " " + modification_type + " registry " + path
	return path, value, modification_type, value_type, message


def prepareData(events_result,magic_sign_json,encoding):
	print("[+] Preparing data ...")
	data_list = []
	for db_row in events_result:
		data_row = {}
		data_row["event_id"] = str(db_row[15])
		data_row["message"] = ""
		data_row["domain"] = ""
		data_row["ip_address"] = ""
		data_row["loaded_DLL"] = ""
		data_row["device_path"] = ""
		data_row["source_ip"] = ""
		data_row["source_port"] = ""
		data_row["destination_ip"] = ""
		data_row["destination_port"] = ""
		data_row["host"] = ""
		data_row["protocol"]= ""
		data_row["http_method"] = ""
		data_row["http_request"] = ""
		data_row["parent_process"] = ""
		data_row["parent_pid"] = ""
		data_row["start_time"] = "" 
		data_row["hash"] = ""
		data_row["command_line"] = ""
		data_row["status"] = ""
		data_row["file_path"] = ""
		data_row["number_of_writes"] = ""
		data_row["file_size"] = ""
		data_row["bytes_written"] = ""
		data_row["data"] = ""
		data_row["mime_type"] = ""
		data_row["extension"] = ""
		data_row["open_time"] = ""
		data_row["event_reason"] = ""
		data_row["open_duration"] = ""
		data_row["path"] = ""
		data_row["value"] = ""
		data_row["modification_type"] = ""
		data_row["value_type"] = ""
		try:
			data_row["timestamp"] = datetime2string(filetime2datetime(db_row[0]))
			data_row["event_type"] = str(db_row[1])
			data_row["pid"] = str(db_row[2])
			data_row["process"] = str(db_row[3])
			data_row["user"] = str(db_row[4])
			if db_row[1] == "dnsLookupEvent":
				data_row["domain"], data_row["message"] = getdnsLookupEventData(db_row)
			elif db_row[1] == "addressNotificationEvent":
				data_row["ip_address"], data_row["message"] = getaddressNotificationEventData(db_row)
			elif db_row[1] == "imageLoadEvent":
				data_row["loaded_DLL"], data_row["device_path"], data_row["message"] = getimageLoadEventData(db_row)
			elif db_row[1] == "processEvent":
				data_row["parent_process"], data_row["parent_pid"], data_row["start_time"], data_row["hash"], data_row["command_line"], data_row["status"], data_row["message"] = getprocessEventData(db_row)				
			elif db_row[1] == "ipv4NetworkEvent":
				data_row["source_ip"], data_row["source_port"], data_row["destination_ip"], data_row["destination_port"], data_row["protocol"], data_row["message"] = getipv4NetworkEventData(db_row)
			elif db_row[1] == "fileWriteEvent":
				data_row["parent_process"], data_row["device_path"], data_row["file_path"], data_row["number_of_writes"], data_row["file_size"], data_row["bytes_written"], data_row["status"], data_row["hash"], data_row["parent_pid"], data_row["data"], data_row["mime_type"], data_row["extension"], data_row["open_time"], data_row["event_reason"], data_row["open_duration"], data_row["message"] = getfileWriteEventData(db_row,magic_sign_json)
			elif db_row[1] == "urlMonitorEvent":
				data_row["source_port"], data_row["destination_ip"], data_row["destination_port"], data_row["http_method"], data_row["http_request"], data_row["host"], data_row["message"] = geturlMonitorEventData(db_row,encoding)
			elif db_row[1] == "regKeyEvent":
				data_row["path"], data_row["value"], data_row["modification_type"], data_row["value_type"], data_row["message"] = getregKeyEventData(db_row,encoding)
			else:
				data_row["message"] = "Event not parsed"
			data_list.append(data_row)
		except KeyboardInterrupt:
			print("[-] Error - Events parsing interrupted by user")
			print("[-] Exiting ...")
			exit(1)
		except:
			print("[-] Error - Parsing event id " + str(db_row[15]) + " fail - ",sys.exc_info())
			continue
	return data_list

def writeCSV(data_list, output_file,separator):
	print("[+] Writing CSV ...")
	try:
		with open(output_file, "w") as file_out:
			file_out.write("datetime"+separator+"timestamp_desc"+separator+"message"+separator+"domain"+separator+"ip_address"+separator+"loaded_DDL"+separator+"device_path"+separator+"source_ip"+separator+"source_port"+separator+"destination_ip"+separator+"destination_port"+separator+"host"+separator+"protocol"+separator+"http_method"+separator+"http_request"+separator+"parent_process"+separator+"parent_pid"+separator+"start_time"+separator+"hash"+separator+"command_line"+separator+"status"+separator+"file_path"+separator+"number_of_writes"+separator+"file_size"+separator+"bytes_written"+separator+"data"+separator+"mime_type"+separator+"extension"+separator+"open_time"+separator+"event_reason"+separator+"open_duration"+separator+"path"+separator+"value"+separator+"modification_type"+separator+"value_type"+separator+"pid"+separator+"process"+separator+"user"+separator+"event_id\n")
			for data_row in data_list:
				for key,value in data_row.items():
					data_row[key] = "\"" + data_row[key].replace("\n","").replace("\r","").replace("\"","\'").replace("None","") + "\""
				file_out.write(data_row["timestamp"]+separator+data_row["event_type"]+separator+data_row["message"]+separator+data_row["domain"]+separator+data_row["ip_address"]+separator+data_row["loaded_DLL"]+separator+data_row["device_path"]+separator+data_row["source_ip"]+separator+data_row["source_port"]+separator+data_row["destination_ip"]+separator+data_row["destination_port"]+separator+data_row["host"]+separator+data_row["protocol"]+separator+data_row["http_method"]+separator+data_row["http_request"]+separator+data_row["parent_process"]+separator+data_row["parent_pid"]+separator+data_row["start_time"]+separator+data_row["hash"]+separator+data_row["command_line"]+separator+data_row["status"]+separator+data_row["file_path"]+separator+data_row["number_of_writes"]+separator+data_row["file_size"]+separator+data_row["bytes_written"]+separator+data_row["data"]+separator+data_row["mime_type"]+separator+data_row["extension"]+separator+data_row["open_time"]+separator+data_row["event_reason"]+separator+data_row["open_duration"]+separator+data_row["path"]+separator+data_row["value"]+separator+data_row["modification_type"]+separator+data_row["value_type"]+separator+data_row["pid"]+separator+data_row["process"]+separator+data_row["user"]+separator+data_row["event_id"]+"\n")
	except KeyboardInterrupt:
			print("[-] Error - Events writing interrupted by user")
			print("[-] Exiting ...")
			exit(1)
	except:
		print("[-] Error - Writing event id " + data_row["event_id"] + " fail - ",sys.exc_info())
		exit(1)
	print("[+] Events writed on " + output_file)
	return


def loadMagicJson(magic_json_path):
	magic_sign_json = ""
	try:
		with open(magic_json_path) as file_magic_sig:
			magic_sign_json = json.loads(file_magic_sig.read())
	except:
		pass
	return magic_sign_json


def main():	
	argparser = argparse.ArgumentParser()
	argparser.add_argument('-i',metavar='',type=str,help='Events DB path, the DB must be un-encrypted ',required=True)
	argparser.add_argument('-o',metavar='',type=str,help='CSV output file',required=True)
	argparser.add_argument('-f',metavar='',type=str,help='Date filter "UTC ISO8601 start timestamp / UTC ISO8601 stop timestamp" eg. "2022-03-04 00:00:00 / 2022-05-15 23:34:59"',default="")
	argparser.add_argument('-s',metavar='',type=str,help='CSV column separator - default: ","',default=",")
	argparser.add_argument('-j',metavar='',type=str,help='Path to magic number json DB',default="")
	argparser.add_argument('-e',metavar='',type=str,help='Source system encoding - default iso8859-1',default="iso8859-1")
	inputArgs = argparser.parse_args()	
	print("[+] Starting ...")	
	events_result, stats_result = queryDB(inputArgs.i.strip(),inputArgs.f.strip())
	printStats(events_result,stats_result)
	magic_sign_json = loadMagicJson(inputArgs.j.strip())
	data_list = prepareData(events_result,magic_sign_json,inputArgs.e.strip())
	writeCSV(data_list,inputArgs.o.strip(),inputArgs.s.strip())
	return
	
	
if __name__ == "__main__":
    main()
    exit(0)
