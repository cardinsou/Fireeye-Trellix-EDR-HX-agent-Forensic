# Fireeye/Trellix EDR HX agent Forensic

During an assignment, we noticed that a couple of compromised machines didn't poll the EDR console for some time. Checking on the machines, the EDR agent was running (process xagt.exe), but it didn't send events or alarms to the main console, so we had a couple of compromised machines that recorded events but we weren't able to recover those events. We already DDed the compromised machine so we tried to find an alternative way to recover data.

On Fireeye HX agent documentation is mentioned that all the events are recorded in a "ring buffer" on the machine, this buffer is a SQLite DB in the following path:

**Windows agent:** C:\ProgramData\FireEye\xagt\

**Linux agent:** /var/lib/fireeye/xagt/

When a triage is requested, the agent on the client queries the ring buffer and send data to the main console. In the mentioned folder there are three SQLite DB:

- **main.db**, contains agent configuration, console IP, exclusion path, policy, certificate, etc...
- **xlog.db**, contains agent log, start, stop, etc... 
- **events.db**, contains all the events that the agent record

All the SQLite database are encrypted with [SQLCipher](https://www.zetetic.net/sqlcipher/) library and configured to use WAL (Write-Ahead Logging). This two configurations make the analysis a little bit more tricky:

- Every DB has its own encryption key
- WAL is used to speed up the interaction between agent process and the db, every modification isn't stored in real time on the DB but in WAL file and then, after few time, bulk synchronized with the DB. If a record is modified many times, and all changes are stored in WAL file, the final DB contains only the last one. So to analyze final data we need to export the DB and the WAL file, for example events.db and events.db-wal.

In the mentioned folder is also possible to find a file named like "events.db.1735.brk". This kind of file are created after a regeneration of the DB by the agent. The numeric code in the file name (eg. 1735) is the error code that cause the regenereation.

## Recovering encryption key

Encryption key format is:

```
x'd48938n06242853754f455s754565e7d5b391301770d133ad5674ce444fa9287f9hjjf3c7a32c087fs67ffe45s440z4g'
```

So if the agent was running we could find it in RAM memory acquisition with the following regex:

```
strings memory.raw | grep -P "^x\'[a-z,0-9]{96}?\'"
```

After executing the above command we retrieve three or more unique key, one for each mentioned DB. This method recover ONLY the key of the opened DB, not the key of backed up DB like the above mentioned "events.db.1735.brk".

## Open DB

You can use the following tools to open the databases:

- Sqlcipher on Linux 
- Sqlitebroswer on Windows (Sqlcipher version)

As previously mentioned, the path from wich you open the DB must contain the db file and the WAL file, mentioned software automatically do merge operations.

### Sqlcipher

You can install it from the repo (eg. ubuntu: apt-get install sqlcipher) and execute the following commands to save the DB in un-encrypted format:

```
user$ sqlcipher
sqlite> .open /home/user/events.db
sqlite> PRAGMA key = "x'd48938n06242853754f455s754565e7d5b391301770d133ad5674ce444fa9287f9hjjf3c7a32c087fs67ffe45s440z4g'";
sqlite> .save /home/user/events_no_pwd.db
sqlite> .exit
```

### Sqlitebrowser

You can open the DB with [Sqlitebrowser](https://sqlitebrowser.org/dl/). Setup operation install two version of Sqlitebrowser, standard and with SQLCipher support. You must use the one with Sqlcipher support and:

- Click "open database"
- Select "raw key" from the dropdown menu
- Format the key as:

    **0x**d48938n06242853754f455s754565e7d5b391301770d133ad5674ce444fa9287f9hjjf3c7a32c087fs67ffe45s440z4g

- Select "SQLCipher3" as encryption type 
- Click "OK".

## main.db

Composed by 4 tables, the intresting one is named "kv" and contains information about the installed agent. The most intresting key for our purposes is "mxa/config", the relative value contains the configuration pushed by the console to the agent. Following the most useful parameters:

- **Process information:**

    ```
    "process": {
        "cpu_limit": 50,
        ......
        "uninstall_password": "XXXXXXXXXXX"
    }
    ```
    - **cpu_limit**, max % of CPU that the agent can use
    - **uninstall_password**, encrypted password that the user must insert to uninstall the agent

- **Events information:**

    ```
    "events": {
        "max_db_size": 700,
        "db_regen_errors": [
          "1725",
          "1726",
          "1731",
          "1733",
          "1734",
          "1735",
          "1736",
          "1737",
          "1738",
          "1739",
          "1740",
          "1743",
          "1744",
          "1750",
          "1808"
        ],
        "excludedPaths": [
          "C:\\Temp\\xxx",
          "C:\\Users\\pippo"
        ],
        "excludedProcessNames": [
          "C:\\Temp\\tryme.exe",
          "C:\\ProgramData\\test\\*.*",
          "C:\\Program Files\\testme\\"
        ],
        ......
    }
    ```

    - **max_db_size**, maximum size of the events.db file in MB, after reaching that older event will be delete
    - **db_regen_errors**, error that cause the regeneretion of "events.db", error code aren't reported in official documentation
    - **excludedPaths**, path to exclude from monitoring
    - **excludedProcessNames**, process name to exclude from monitoring
    
- **Server list:**
    
    ```
    "serverlist": {
      "servers": [
        {
          "server": "10.10.10.10"
        }
      ]
    }
    ```
    
    - **server**, HX main console IP address

- **Agent id**
    
## xlog.db

Contains only one table with the agent log. You can browse it with Sqlitebrowser or extract data to CSV with the attached script xlog2csv.py.

Xlog DB data are agent internals so it could be useful also for triage technical problems, following some examples of intresting information from our perspective:

- **Agent start**

    **Windows**
    ```
    datetime,timestamp_desc,message,process_name,pid
   	2022-05-26 11:04:12 +00:00,main.cc,"CmdLine: 'C:\Program Files (x86)\FireEye\xagt\xagt.exe'  --mode SERVICE",xagt.exe,4152
    ```
    **Linux**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-05-26 16:47:54 +00:00,main.cc,"CmdLine: -M DAEMON",xagt,608
    ```
    
- **Agent stop**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-05-26 11:07:13 +00:00,shutdown_service.cc,"SHUTDOWN: Begin (restart=false)",SERVICE,2088
    2022-05-26 11:07:12 +00:00,shutdown_service.cc,"SHUTDOWN: complete",SERVICE,2088
    ```
- **Agent restart**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-05-26 10:10:48 +00:00,shutdown_service.cc,"SHUTDOWN: Begin (restart=true)",SERVICE,2132
    2022-05-26 10:10:48 +00:00,shutdown_service.cc,"SHUTDOWN: complete",SERVICE,2132
    2022-05-26 10:10:48 +00:00,agent.cc,"Restarting xagt via pid:4600 rval:0",SERVICE,2132
    ```
- **Agent polling/network problem**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect 10.10.10.10:443.  Attempt: 1",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect setting a connection retry in 30000 ms",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect 0.0.0.0:49705 -> 10.10.10.10:443 status:-4062",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect scheduling a connection retry with status:-4062",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection.cc,"Aborting retry on error",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection_factory.cc,"Cluster roll over to #1 10.10.10.10:443 for full_poll",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection.cc,"Reconnect on connect error.",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect 10.10.10.10:443.  Attempt: 1",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect setting a connection retry in 30000 ms",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,"TCPConnect 0.0.0.0:49706 -> 10.10.10.10:443 status:-4062",SERVICE,2100
    2022-05-26 11:05:12 +00:00,tcp.cc,2TCPConnect scheduling a connection retry with status:-4062",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection.cc,"Aborting retry on error",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection_factory.cc,"All hosts attempted for full_poll.  Fail connection: v=-4062",SERVICE,2100
    2022-05-26 11:05:12 +00:00,connection.cc,"Error on connect.",SERVICE,2100
    2022-05-26 11:05:12 +00:00,poller.cc,"Error on poll connect.",SERVICE,2100
    2022-05-26 11:05:12 +00:00,poller.cc,"Scheduled full poll in 218000 msecs on aid XXXXXX.",SERVICE,2100
    ```
- **Installing new configuration**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-02-10 10:10:48 +00:00,agent.cc,"Installing dynamic configuration->{  'fips': {    'enabled': false  },  'credentials': {    'cacert': *****",SERVICE,2132
    ```
- **DLL/.so verification**
    ```
    datetime,timestamp_desc,message,process_name,pid
    2022-05-26 09:31:13 +00:00,verified_dll.cc,"File 'C:\Program Files (x86)\FireEye\xagt\api-ms-win-core-console-l1-1-0.dll' is code signed and the signature is verified.",SERVICE,2192
    2022-05-26 09:31:13 +00:00,verified_dll.cc,"File 'C:\Program Files (x86)\FireEye\xagt\api-ms-win-core-datetime-l1-1-0.dll' is code signed and the signature is verified.",SERVICE,2192
    2022-05-26 15:31:15 +00:00,verified_dll.cc,"Verifying signature for /var/lib/fireeye/xagt/exts/plugin/Eventor/EventorProxy.so",DAEMON,1955
    ```
- **Time skew**
    ```
    2022-04-21 14:00:26 +0000,time_mgr.cc,"Reported server_time: 1650549626s local_time: 1650549626s, query_diff: 62ms",SERVICE,5320
    ```

Xlog DB retention is calculated with the following trigger:

```
CREATE TRIGGER tr_after_insert_log AFTER INSERT ON log WHEN NEW._id % 10000 == 0 BEGIN DELETE FROM log WHERE _id <= NEW._id - 40000; END
```

So the maximum retention is 49999 log rows.

### xlog2csv.py

If you use the script remember to previously un-encrypt the xlog db with sqlcipher as previous mentioned.

Usage:

```
user$ python3 xlog2csv.py -h
usage: xlog2csv.py [-h] -i  -o  [-f] [-s]

options:
  -h, --help  show this help message and exit
  -i          Xlog DB path, the DB must be un-encrypted
  -o          CSV output file
  -f          Date filter "UTC ISO8601 start timestamp / UTC ISO8601 stop timestamp" eg. "2022-03-04 00:00:00 / 2022-05-15 23:34:59"
  -s          CSV column separator default: ","
```

Example:

```
python3 xlog2csv.py -i /home/user/win_xlog_clear.db -o /home/user/output_xlog.csv
```

Output example:

```
datetime,timestamp_desc,message,process_name,pid
"2022-02-09 13:38:17+0000","main.cc","CmdLine: 'C:\Program Files (x86)\FireEye\xagt\xagt.exe'  --mode SERVICE","xagt.exe","4152"
"2022-02-09 13:38:17+0000","main.cc","Running as: hostname\SYSTEM","xagt.exe","4152"
"2022-02-09 13:38:17+0000","crash_mon.cc","Local crash handler installed in process","xagt.exe","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","IP for default route at boot: 10.0.2.15","SERVICE","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","Local time is 2022-02-09T14:38:16","SERVICE","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","vnum: v34.28.1 platform: win/x64","SERVICE","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","host_os vnum: '10.0.19042' arch:x64","SERVICE","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","exe: C:\Program Files (x86)\FireEye\xagt\xagt.exe","SERVICE","4152"
"2022-02-09 13:38:17+0000","boot_logger.cc","cwd: C:\WINDOWS\system32","SERVICE","4152"
"2022-02-09 13:38:17+0000","svc_dispatch_win.cc","Starting service","SERVICE","4152"
"2022-02-09 13:38:17+0000","svc_dispatch_win.cc","Running service","SERVICE","4152"
"2022-02-09 13:38:17+0000","ssl_proc.cc","OpenSSL Startup (threads:true):0","SERVICE","4152"
```

Script's output CSV file is compatible with [Timesketch](https://timesketch.org/) standard CSV importer.

## events.db

Contains 3 tables, the interesting one is named "events". When a triage is requested from the main console, the agent queries the events database and reply with the requested informations. You can browse it with Sqlitebrowser, or you can extract data to CSV with the attached script events2csv.py.

Following two example of queries:

Events:
```
SELECT timestamp,name,pid,ppath,username,int1,int2,int3,int4,str1,str2,str3,str4,data1,data2 FROM events LEFT JOIN event_types ON events.type_id = event_types.id ORDER BY timestamp,sequence_num ASC
```
Statistics:
```
SELECT name, first_event, last_event, event_count FROM event_types JOIN (SELECT type_id, MIN(timestamp) as first_event, MAX(timestamp) as last_event, count(timestamp) as event_count FROM events GROUP BY type_id) ON event_types.id = type_id
```

DB contains all the events that the agent collect, every event has a type. For all events are reported:

- **Event type**, column "type_id", matching the ID with the contents of the "event_types" table you can extract the event type
- **Timestamp**, column "timestamp", UTC filetime timestamp, if multiple row has the same timestamp you can order also by column "sequence_num"
- **PID**,  column "pid", contains the PID of the process
- **Process**, column "ppath", contains the process that generate the event
- **User**, column "username", contains the user

Custom data are collected for each type of event, details below:

- **dnsLookupEvent**
    - DNS query domain, reported in column "str1"

- **addressNotificationEvent**
    - New IP Address, reported in column "data1" 

- **imageLoadEvent**
    - Loaded DLL path, reported in column "str1"
    - Device path, reported in column "str2"

- **processEvent**
    - Parent process, reported in column "str1"
    - Parent process PID, reported in column "int1"
    - Start time, reported in column "int3"
    - Executable's Hash, reported in column "data1"
    - Command line, reported in column "str3"
    - Process status, reported in column "int2"

- **ipv4NetworkEvent**
    - Source IP, reported in column "data2" in hex format
    - Destiantion IP, reported in column "data1" in hex format
    - Source port, reported in column "int2"
    - Destination port, reported in column "int1"
    - Protocol, reported in column "int3" as [number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)  

- **fileWriteEvent**
    - Parent process,reported in column "str3"
    - Parent process PID, reported in column "data2"
    - Device path, reported in column "str2"
    - File path, reported in column "str1"
    - Number of writes, reported in column "int1"
    - File size, reported in column "int2"
    - Bytes written, reported in column "int3"
    - File status (closed or opened), reported in column "flag1"
    - File hash, reported in column "data1"
    - File first bytes, reported in column "data2"
    - Open time, reported in column "data2"
    - Event Reason, reported in column "data2"
    - Open duration, reported in column "data2"
   
- **urlMonitorEvent**
    - Destiantion IP, reported in column "data1" in hex format
    - Source port, reported in column "int2"
    - Destination port, reported in column "int1"
    - HTTP method, reported in column "str1"
    - HTTP request, reported in column "str2"

- **regKeyEvent**
    - Register path, reported in column "str1", "str2" and "str4"
    - Register value, reported in column "data1"
    - modification type, reported in column "int1"
    - value type, reported in column "int2"

### events2csv.py

If you use the script remember to previously un-encrypt the events db with sqlcipher as previous mentioned.

Usage: 

```
user$ python3 events2csv.py -h
usage: events2csv.py [-h] -i  -o  [-f] [-s] [-j] [-e]

options:
  -h, --help  show this help message and exit
  -i          Events DB path, the DB must be un-encrypted
  -o          CSV output file
  -f          Date filter "UTC ISO8601 start timestamp / UTC ISO8601 stop timestamp" eg. "2022-03-04 00:00:00 / 2022-05-15 23:34:59"
  -s          CSV column separator - default: ","
  -j          Path to magic number json DB
  -e          Source system encoding - default iso8859-1
  
```
Example:
```
python3 events2csv.py -i /home/user/win_events_clear.db -o /home/user/output.csv -j /home/user/magic_signature.json -e "utf-8"
```

All the data mentioned above are parsed and inserted in the CSV file that the script produces. The script also enrich data with file extension and mime type. Magic number and the relative mime type and extensions are reported in "magic_signature.json" file.

Example output:
```
datetime,timestamp_desc,message,domain,ip_address,loaded_DDL,device_path,source_ip,source_port,destination_ip,destination_port,host,protocol,http_method,http_request,parent_process,parent_pid,start_time,hash,command_line,status,file_path,number_of_writes,file_size,bytes_written,data,mime_type,extension,open_time,event_reason,open_duration,path,value,modification_type,value_type,pid,process,user,event_id
"2022-02-10 10:10:51+0000","processEvent","Process SppExtComObj.Exe started by svchost.exe","","","","","","","","","","","","","\Device\HarddiskVolume2\Windows\System32\svchost.exe","760","","","","running","","","","","","","","","","","","","","","1340","C:\Windows\System32\SppExtComObj.Exe","NT AUTHORITY\NETWORK SERVICE","35"
"2022-02-10 10:10:51+0000","ipv4NetworkEvent","Process SearchApp.exe connection from 10.0.2.15:49678 to 204.79.197.200:443","","","","","10.0.2.15","49678","204.79.197.200","443","","TCP","","","","","","","","","","","","","","","","","","","","","","","4248","C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe","TEST-SOC-WIN\userone","68"
"2022-02-10 10:10:51+0000","imageLoadEvent","Process WmiPrvSE.exe load DLL C:\Windows\System32\ntdll.dll","","","C:\Windows\System32\ntdll.dll","\Device\HarddiskVolume2","","","","","","","","","","","","","","","","","","","","","","","","","","","","","3568","C:\Windows\System32\wbem\WmiPrvSE.exe","NT AUTHORITY\SYSTEM","85"
"2022-02-10 13:47:24+0000","addressNotificationEvent","Change IP Address to fe80:0000:0000:0000:b911:3d45:863a:7383","","fe80:0000:0000:0000:b911:3d45:863a:7383","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","92898"
"2022-04-08 09:41:42+0000","dnsLookupEvent","Process svchost.exe query DNS for v10.events.daa.microsoft.com","v10.events.data.microsoft.com","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","1308","C:\Windows\System32\svchost.exe","NT AUTHORITY\SYSTEM","125622"
"2022-04-08 09:41:57+0000","regKeyEvent","Process MsMpEng.exe create key registry HKEY_USERS\.DEFAULT\Software\Microsoft\SystemCertificates\Disallowed\CRLs","","","","","","","","","","","","","","","","","","","","","","","","","","","","","HKEY_USERS\.DEFAULT\Software\Microsoft\SystemCertificates\Disallowed\CRLs","","create key","","6464","C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2201.10-0\MsMpEng.exe","NT AUTHORITY\SYSTEM","131464"
"2022-06-16 12:23:43+0000","urlMonitorEvent","Process svchost.exe HTTP GET request to 3.au.download.windowsupdate.com:80","","","","","","49876","67.27.239.126","80","3.au.download.windowsupdate.com","","GET","GET /d/msdownload/update/software/updt/2022/04/windows10.0-kb5013887-x64-ndp48_aa0da938276607c9736d87066ade1776dafd7aa5.cab HTTP/1.1 | Connection: Keep-Alive | Accept: */* | Range: bytes=38535168-38666239 | User-Agent: Microsoft-Delivery-Optimization/10.0 | MS-CV: Mn+HQ2Hit0eMxW2Z.1.1.7.2.6.1.1.272 | Content-Length: 0 | Host: 3.au.download.windowsupdate.com","","","","","","","","","","","","","","","","","","","","","5320","C:\Windows\System32\svchost.exe","NT AUTHORITY\NETWORK SERVICE","784127"
"2022-06-16 12:54:53+0000","fileWriteEvent","Process StartMenuExperienceHost.exe write file ~tartUnifiedTileModelCache.tmp","","","","\Device\HarddiskVolume2","","","","","","","","","C:\Windows\System32\svchost.exe","752","","5be3738e6635e833004b0ed417302b53","","Closed","C:\Users\userone\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\~tartUnifiedTileModelCache.tmp","161","27828","23612","+54J3uAGaY0=","","","2022-06-16 12:54:53+0000","File closed","0","","","","","2668","C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe","TEST-SOC-WIN\userone","1066775"
```

Script's output CSV file is compatible with [Timesketch](https://timesketch.org/) standard CSV importer.

## Used software version

Fireeye HX agent 32.30 and 34.28.1 

Python 3.10.4

Sqlcipher 3.15.2

Sqlitebrowser 3.12.2 (x86)

## Thank's to

[Fleep project](https://github.com/ua-nick/fleep-py) for file signature identification code
