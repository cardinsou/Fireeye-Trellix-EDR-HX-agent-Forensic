#!/usr/bin/python3


import sys
import sqlite3
import argparse 
import datetime


def unix2datetime(unix_timestamp):
	datetime_timestamp = datetime.datetime.utcfromtimestamp(unix_timestamp).replace(tzinfo=datetime.timezone.utc)
	return datetime_timestamp


def datetime2unix(datetime_timestamp):
	unix_timestamp = int(datetime_timestamp.timestamp())
	return unix_timestamp


def datetime2string(datetime_timestamp):
	string_timestamp = datetime_timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
	return string_timestamp


def querydb(input_file, date_filter):
	query = "SELECT time,pid,fn,process_name,msg,argc,arg1,arg2,arg3,arg4,arg5,arg6,_id FROM log"
	if date_filter:
		try:
			start_datetime = datetime.datetime.strptime(date_filter.split("/")[0].strip(),"%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
			stop_datetime = datetime.datetime.strptime(date_filter.split("/")[1].strip(),"%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
		except:
			print("[-] Error - ",sys.exc_info())
			print("[-] Exiting ...")
			exit(1)	
		if stop_datetime > start_datetime:
			query += " WHERE time >= " + str(datetime2unix(start_datetime)) + " AND time <= " + str(datetime2unix(stop_datetime))
		else:
			print("[-] Error - Filter end timestamp must be greater than start timestamp")
			print("[-] Exiting ...")
			exit(1)
	query += " ORDER BY time ASC"
	print("[+] Querying DB ...")
	try:
		db_connection = sqlite3.connect(input_file)
		cursor = db_connection.execute(query)
		events_result = cursor.fetchall()
	except:
		print("[-] Error - ",sys.exc_info())
		print("[-] Exiting ...")
		exit(1)
	db_connection.close()	
	return events_result


def printstats(events_result):
	print("[+] Extracted " + str(len(events_result)) + " records")
	print("[+] Events from " + datetime2string(unix2datetime(events_result[0][0])) + " to " + datetime2string(unix2datetime(events_result[-1][0])))
	return


def preparedata(events_result):
	print("[+] Preparing data ...")
	data_list = []
	for db_row in events_result:
		data_row = {}
		try:
			data_row["timestamp"] = datetime2string(unix2datetime(db_row[0]))
			data_row["process_name"] = str(db_row[3]) 
			data_row["pid"] = str(db_row[1])
			data_row["function"] = str(db_row[2])
			data_row["message"] = db_row[4]
			for i in range(6,6+db_row[5]):
				data_row["message"] = data_row["message"].replace("^"+str(i-5),db_row[i])
			data_row["event_id"] = str(db_row[12])
			data_list.append(data_row)
		except KeyboardInterrupt:
			print("[-] Error - Events parsing interrupted by user")
			print("[-] Exiting ...")
			exit(1)
		except:
			print("[-] Error - Parsing event id " + str(db_row[12]) + " fail - ",sys.exc_info()) ################
			continue
	return data_list


def writeCSV(data_list, output_file, separator):
	print("[+] Writing CSV ...")
	try:
		with open(output_file, "w") as file_out:
			file_out.write("datetime"+separator+"timestamp_desc"+separator+"message"+separator+"process_name"+separator+"pid\n")
			for data_row in data_list:
				for key,value in data_row.items():
					data_row[key] = "\"" + data_row[key].replace("\n","").replace("\r","").replace("\"","\'") + "\""
				file_out.write(data_row["timestamp"]+separator+data_row["function"]+separator+data_row["message"]+separator+data_row["process_name"]+separator+data_row["pid"]+"\n")
	except KeyboardInterrupt:
			print("[-] Error - Events parsing interrupted by user")
			print("[-] Exiting ...")
			exit(1)
	except:
		print("[-] Error - Writing event id " + data_row["event_id"] + " fail - ",sys.exc_info())
		print("[-] Exiting ...")
		exit(1)
	print("[+] Events writed on " + output_file)
	return


def main():	
	argparser = argparse.ArgumentParser()
	argparser.add_argument('-i',metavar='',type=str,help='Xlog DB path, the DB must be un-encrypted ',required=True)
	argparser.add_argument('-o',metavar='',type=str,help='CSV output file',required=True)
	argparser.add_argument('-f',metavar='',type=str,help='Date filter "UTC ISO8601 start timestamp / UTC ISO8601 stop timestamp" eg. "2022-03-04 00:00:00 / 2022-05-15 23:34:59"',default="")
	argparser.add_argument('-s',metavar='',type=str,help='CSV column separator default: ","',default=",")
	inputArgs = argparser.parse_args()	
	print("[+] Starting ...")	
	events_result = querydb(inputArgs.i.strip(),inputArgs.f.strip())
	printstats(events_result)
	data_list = preparedata(events_result)
	writeCSV(data_list,inputArgs.o.strip(),inputArgs.s.strip())
	return
	
	
if __name__ == "__main__":
    main()
    exit(0)
