# ブルートフォース - チートシート

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

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

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
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

A common attack method against AJP is brute force, where an attacker attempts to guess the username and password combination to gain unauthorized access to the server. Brute force attacks can be automated using tools like Hydra or Burp Suite.

To protect against brute force attacks on AJP, it is important to use strong and unique passwords for all user accounts. Additionally, implementing account lockout policies can help prevent repeated login attempts. Monitoring server logs for suspicious activity and implementing rate limiting can also be effective in mitigating brute force attacks.

It is recommended to regularly update and patch the server software to address any vulnerabilities that could be exploited by attackers. Regular security audits and penetration testing can also help identify and address any weaknesses in the server's configuration.

By following these best practices, you can enhance the security of your AJP-enabled server and reduce the risk of unauthorized access through brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# ブルートフォース攻撃

ブルートフォース攻撃は、暗号化されたデータやパスワードを解読するために使用される一般的な攻撃手法です。この攻撃手法では、すべての可能な組み合わせを試し、正しい組み合わせを見つけるまで繰り返し実行します。

## ブルートフォース攻撃の手法

1. 辞書攻撃: 事前に作成された辞書ファイルを使用して、一連の単語やフレーズを試します。一般的なパスワードや一般的な単語の組み合わせを網羅しています。

2. 総当たり攻撃: すべての可能な組み合わせを順番に試します。この手法は非常に時間がかかる場合がありますが、正しい組み合わせを見つけることができます。

3. ハイブリッド攻撃: 辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず辞書攻撃を試し、その後総当たり攻撃を行います。

## ブルートフォース攻撃の対策

ブルートフォース攻撃からデータやパスワードを保護するためには、以下の対策を講じることが重要です。

1. 強力なパスワードの使用: パスワードは長く、複雑な文字列であるほど、ブルートフォース攻撃に対する耐性が高くなります。

2. ロックアウト機能の有効化: 一定回数の誤った試行後にアカウントをロックする機能を有効にすることで、ブルートフォース攻撃を防ぐことができます。

3. 二要素認証の使用: パスワードに加えて、追加の認証要素を必要とする二要素認証を使用することで、セキュリティを強化することができます。

4. ログ監視: ブルートフォース攻撃の試行を監視し、異常なアクティビティを検出するためにログを監視することが重要です。

ブルートフォース攻撃は非常に効果的な攻撃手法ですが、適切な対策を講じることで、データやパスワードを保護することができます。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# CouchDB

CouchDBは、ドキュメント指向のデータベースであり、HTTPプロトコルを使用してデータにアクセスすることができます。CouchDBは、データベースのブルートフォース攻撃に対して脆弱な場合があります。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために連続的に試行する攻撃手法です。

CouchDBのブルートフォース攻撃を防ぐためには、以下の方法があります。

1. 強力なパスワードの使用: CouchDBには、強力なパスワードを使用することが重要です。パスワードは、長さが十分であり、大文字と小文字、数字、特殊文字を含んでいる必要があります。

2. ログイン試行回数の制限: CouchDBには、ログイン試行回数を制限する機能があります。これにより、攻撃者が連続してログイン試行を行うことを防ぐことができます。

3. IP制限: CouchDBには、特定のIPアドレスからのアクセスを制限する機能があります。これにより、不正なアクセス元からの攻撃を防ぐことができます。

4. セキュリティパッチの適用: CouchDBは、定期的にリリースされるセキュリティパッチを適用することが重要です。これにより、既知の脆弱性を修正し、攻撃を防ぐことができます。

以上の方法を組み合わせることで、CouchDBのブルートフォース攻撃を効果的に防ぐことができます。
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
## Docker レジストリ

A Docker registry is a storage and distribution system for Docker images. It allows you to store and manage your Docker images in a central location, making it easy to share and deploy them across different environments.

Docker レジストリは、Docker イメージの保存と配布のためのストレージおよび配布システムです。中央の場所に Docker イメージを保存および管理することができ、異なる環境で共有および展開することが容易になります。

The Docker registry can be either public or private. Public registries, such as Docker Hub, allow anyone to access and download Docker images. Private registries, on the other hand, are restricted to authorized users and provide an additional layer of security.

Docker レジストリは、公開または非公開のいずれかになります。Docker Hub のような公開レジストリでは、誰でも Docker イメージにアクセスしてダウンロードすることができます。一方、非公開レジストリは、認証されたユーザーに制限され、追加のセキュリティレイヤーを提供します。

To access a private Docker registry, you need to authenticate yourself using a username and password or other authentication methods supported by the registry. Once authenticated, you can push your Docker images to the registry and pull them when needed.

非公開の Docker レジストリにアクセスするには、ユーザー名とパスワードまたはレジストリでサポートされている他の認証方法を使用して自分自身を認証する必要があります。認証が完了すると、Docker イメージをレジストリにプッシュし、必要な時にプルすることができます。

In addition to the public and private Docker registries, you can also set up your own custom registry using tools like Docker Registry or third-party solutions like Harbor. This allows you to have full control over your Docker images and their distribution.

公開および非公開の Docker レジストリに加えて、Docker Registry や Harbor のようなサードパーティのソリューションを使用して、独自のカスタムレジストリを設定することもできます。これにより、Docker イメージとその配布に対して完全な制御を持つことができます。
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

4. **Monitor for suspicious activity**: Regularly monitor Elasticsearch logs and network traffic for any signs of brute force attacks or unauthorized access attempts.

By following these security best practices, you can significantly reduce the risk of brute force attacks and protect your Elasticsearch instances from unauthorized access.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（File Transfer Protocol）は、ファイルの転送に使用されるプロトコルです。FTPサーバーに対してブルートフォース攻撃を行うことで、正当な認証情報を推測し、アクセスを試みることができます。

ブルートフォース攻撃は、辞書攻撃とも呼ばれ、自動化されたツールを使用して、膨大な数のパスワードの組み合わせを試行することで、正しいパスワードを見つけ出す手法です。この攻撃は、パスワードが弱い場合や、デフォルトの認証情報が使用されている場合に特に効果的です。

ブルートフォース攻撃を実行するためには、まずFTPサーバーのIPアドレスを特定する必要があります。次に、ユーザー名とパスワードの組み合わせを自動化されたツールで試行し、正しい認証情報を見つけ出します。

ブルートフォース攻撃は、時間がかかる場合がありますが、パスワードが弱い場合やデフォルトの認証情報が使用されている場合には非常に効果的です。したがって、FTPサーバーのセキュリティを強化するためには、強力なパスワードポリシーの実施や、デフォルトの認証情報の変更が重要です。
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

ポストフォームのブルートフォース攻撃は、ウェブアプリケーションへの不正アクセスを試みるためによく使われる手法です。この方法では、攻撃者はユーザー名とパスワードの異なる組み合わせをシステム的に試し、成功するログインを狙います。

To perform a brute force attack on a login form, the attacker typically uses an automated script or tool that sends HTTP POST requests to the login endpoint with different username and password combinations. The attacker may also use a wordlist or a dictionary of commonly used passwords to increase the chances of success.

ログインフォームへのブルートフォース攻撃を実行するために、攻撃者は通常、異なるユーザー名とパスワードの組み合わせでHTTP POSTリクエストをログインエンドポイントに送信する自動化スクリプトやツールを使用します。攻撃者は、成功の可能性を高めるために、ワードリストや一般的に使用されるパスワードの辞書も使用する場合があります。

It is important to note that brute forcing a login form is a time-consuming process and may trigger security mechanisms such as account lockouts or rate limiting. Therefore, it is recommended to use this technique responsibly and with proper authorization.

ログインフォームのブルートフォース攻撃は時間がかかるプロセスであり、アカウントのロックアウトやレート制限などのセキュリティメカニズムを引き起こす可能性があることに注意が必要です。そのため、この技術を責任を持って適切な認可を得て使用することが推奨されます。
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
http**s**の場合、「http-post-form」を「**https-post-form」に変更する必要があります。

### **HTTP - CMS --** (W)ordpress, (J)oomla or (D)rupal or (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
IMAP (Internet Message Access Protocol) is a widely used protocol for email retrieval. It allows users to access their email messages on a remote mail server. IMAP supports both online and offline modes, allowing users to manage their email messages even when they are not connected to the server.

#### Brute-Force Attack on IMAP

A brute-force attack is a common method used to gain unauthorized access to an IMAP account. In this attack, the attacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute-force attack on an IMAP server, the attacker typically uses a script or a specialized tool that automates the process. The tool tries different combinations of usernames and passwords, often using a list of commonly used passwords or a dictionary of words.

To protect against brute-force attacks on IMAP, it is important to use strong and unique passwords. Additionally, implementing account lockout policies can help prevent multiple failed login attempts within a certain time period.

#### Countermeasures

To protect against brute-force attacks on IMAP, consider implementing the following countermeasures:

1. Use strong and unique passwords for IMAP accounts.
2. Implement account lockout policies to prevent multiple failed login attempts.
3. Monitor and analyze log files for any suspicious activity.
4. Consider using two-factor authentication for added security.
5. Regularly update and patch the IMAP server software to address any security vulnerabilities.

By following these countermeasures, you can significantly reduce the risk of a successful brute-force attack on your IMAP server.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC（Internet Relay Chat）は、インターネット上でリアルタイムのテキストベースのコミュニケーションを行うためのプロトコルです。IRCは、チャットルームと呼ばれるグループチャットや、個別のプライベートメッセージを通じてユーザー間でのコミュニケーションを可能にします。

IRCサーバーに接続するためには、IRCクライアントソフトウェアを使用します。一般的なIRCクライアントには、mIRC、HexChat、irssiなどがあります。IRCクライアントを使用すると、IRCサーバーに接続し、チャットルームに参加したり、他のユーザーとのプライベートメッセージを送受信したりすることができます。

IRCは、ユーザー名とパスワードを使用して認証することができます。一部のIRCサーバーでは、ブルートフォース攻撃を防ぐために、一定の時間間隔でのログイン試行回数制限が設定されている場合があります。

ブルートフォース攻撃は、自動化された方法でパスワードを推測することによってアカウントに不正にアクセスする試みです。一般的なブルートフォース攻撃の手法には、辞書攻撃（事前に作成されたパスワードリストを使用して試行する）や、総当たり攻撃（すべての可能な組み合わせを試行する）があります。

ブルートフォース攻撃は、パスワードが弱い場合や、パスワードポリシーが緩い場合に特に有効です。パスワードを強化するためには、長さ、複雑さ、一意性を考慮した強力なパスワードを使用することが重要です。

ブルートフォース攻撃は、セキュリティテストやペネトレーションテストの一環として使用されることもあります。セキュリティ専門家は、システムの脆弱性を特定し、修正するためにブルートフォース攻撃を使用することがあります。ただし、許可なく他人のアカウントにアクセスすることは違法ですので、適切な許可を得ることが重要です。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) is a protocol that allows the transmission of SCSI commands over IP networks. It enables the use of storage devices over a network, making it possible to access remote storage resources as if they were local.

iSCSI works by encapsulating SCSI commands into TCP/IP packets, which are then sent over the network. This allows for the remote mounting of storage devices, such as disks or tape drives, on a client system.

One of the advantages of iSCSI is its flexibility and compatibility with existing infrastructure. It can be used with both Ethernet and Fibre Channel networks, and can leverage existing IP-based networks. This makes it a cost-effective solution for organizations that want to utilize their existing network infrastructure for storage purposes.

However, iSCSI also introduces security risks, as it relies on IP networks, which are susceptible to various attacks. One common attack against iSCSI is brute force, where an attacker attempts to guess the authentication credentials by systematically trying different combinations.

To protect against brute force attacks, it is important to use strong and complex passwords for iSCSI authentication. Additionally, implementing measures such as account lockouts and rate limiting can help mitigate the risk of successful brute force attacks.

Overall, iSCSI is a powerful protocol that enables the use of remote storage resources. However, it is crucial to implement proper security measures to protect against potential attacks.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
JWT（JSON Web Token）は、認証と情報の安全な伝送を可能にするためのオープンスタンダードです。JWTは、クライアントとサーバー間でデータを安全にやり取りするために使用されます。JWTは、ユーザーの認証情報やその他の情報を含むJSON形式のトークンです。

JWTは、3つのセクションから構成されています。ヘッダー、ペイロード、署名です。ヘッダーは、トークンのタイプや使用するアルゴリズムなどのメタデータを含みます。ペイロードは、トークンに含まれる情報を格納します。署名は、トークンの信頼性を確保するために使用されます。

JWTの一般的な攻撃手法の1つは、ブルートフォース攻撃です。ブルートフォース攻撃では、攻撃者は可能なすべての組み合わせを試し、正しい署名を見つけることを試みます。これにより、攻撃者はトークンを改ざんしたり、不正なアクセスを行ったりすることができます。

ブルートフォース攻撃を防ぐためには、強力なパスワードや署名アルゴリズムを使用することが重要です。また、トークンの有効期限を短く設定することも推奨されます。さらに、アカウントロックアウトやCAPTCHAなどのセキュリティメカニズムを実装することも有効です。

JWTのセキュリティを確保するためには、適切な暗号化と署名の実装が必要です。また、トークンの検証や不正なトークンの検出などのセキュリティチェックも重要です。
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
# LDAP

LDAP（Lightweight Directory Access Protocol）は、ディレクトリサービスにアクセスするためのプロトコルです。ディレクトリサービスは、ユーザー、グループ、コンピュータなどの情報を格納するために使用されます。LDAPは、ディレクトリサービスへのクエリや変更の要求を処理するために使用されます。

LDAPブルートフォース攻撃は、LDAPサーバーに対して総当たり攻撃を行う手法です。攻撃者は、ユーザー名とパスワードの組み合わせを試し、正しい認証情報を見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

LDAPブルートフォース攻撃を実行するためには、ブルートフォースツールを使用する必要があります。これらのツールは、自動的にユーザー名とパスワードの組み合わせを生成し、LDAPサーバーに送信します。攻撃者は、ツールが正しい認証情報を見つけるまで、繰り返し攻撃を行います。

LDAPブルートフォース攻撃は、パスワードポリシーの弱さやユーザーの無知によって成功する可能性があります。したがって、セキュリティを強化するためには、強力なパスワードポリシーの実装、アカウントロックアウトの設定、ログイン試行の監視などの対策が必要です。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）は、軽量なメッセージングプロトコルであり、IoT（Internet of Things）デバイス間の通信に広く使用されています。このプロトコルは、低帯域幅や不安定なネットワーク環境でも効率的に動作します。

MQTTは、パブリッシャーとサブスクライバーの2つの役割を持つクライアント間の非同期通信を可能にします。パブリッシャーはメッセージをトピックにパブリッシュし、サブスクライバーは特定のトピックにサブスクライブしてメッセージを受信します。

MQTTのセキュリティには注意が必要です。デフォルトの設定では、認証や暗号化が行われないため、攻撃者による盗聴や改ざんのリスクがあります。したがって、適切なセキュリティ対策を講じることが重要です。

MQTTのブルートフォース攻撃は、パスワードの推測に基づいて行われます。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを目指します。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、アカウントロックアウトやログイン試行回数の制限などのセキュリティメカニズムを設定する必要があります。

ブルートフォース攻撃を検出するためには、ログイン試行回数の異常な増加や異なるIPアドレスからのログイン試行などの異常なアクティビティを監視することが重要です。また、IPブラックリストやCAPTCHAなどの防御メカニズムを導入することも有効です。

MQTTのセキュリティを確保するためには、最新のバージョンのプロトコルを使用し、認証や暗号化を有効にすることが重要です。また、ファイアウォールや侵入検知システムなどのセキュリティソリューションを適切に設定することも必要です。

以上が、MQTTに関する概要とブルートフォース攻撃に対する対策です。セキュリティを確保するためには、適切な対策を講じることが重要です。
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
## MySQL

MySQLは、オープンソースのリレーショナルデータベース管理システム（RDBMS）です。多くのウェブアプリケーションやウェブサイトで使用されており、データの保存と取得を容易にします。

MySQLのブルートフォース攻撃は、パスワードを推測するために連続的に試行する攻撃手法です。この攻撃は、弱いパスワードを使用しているユーザーアカウントを見つけるために使用されます。

ブルートフォース攻撃は、一般的に辞書攻撃と総当たり攻撃の2つの方法で行われます。

- 辞書攻撃：事前に作成されたパスワードリストを使用して、パスワードを推測します。攻撃者は、一般的なパスワードや辞書に含まれる単語を試すことができます。

- 総当たり攻撃：すべての可能な組み合わせを試して、正しいパスワードを見つけることを試みます。この方法は非常に時間がかかるため、強力なパスワードを使用している場合は成功する可能性が低くなります。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保する必要があります。また、アカウントロックアウトやログイン試行回数の制限などのセキュリティメカニズムを使用することも重要です。
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# Brute Force

Brute force is a common method used in penetration testing to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. This technique can be applied to various systems, including Oracle SQL databases.

## Brute Forcing Oracle SQL

When it comes to Oracle SQL, there are several tools and techniques that can be used for brute forcing. Here are some commonly used methods:

1. **Dictionary Attack**: This method involves using a pre-generated list of commonly used passwords or words from a dictionary to attempt to gain unauthorized access. Tools like Hydra or Medusa can be used to automate this process.

2. **Password Guessing**: In this method, the attacker manually tries different passwords based on their knowledge of the target, such as personal information or common patterns. This can be a time-consuming process but can be effective if the attacker has some insight into the target's password habits.

3. **Rainbow Tables**: Rainbow tables are precomputed tables that contain a large number of possible password hashes and their corresponding plaintext values. By comparing the hash of the target password with the entries in the rainbow table, the attacker can quickly find a match. Tools like Ophcrack or RainbowCrack can be used for this purpose.

4. **Brute Forcing Tools**: There are specialized tools available that can automate the brute forcing process for Oracle SQL databases. These tools, such as SQLBrute or OraBrute, use various techniques like parallel processing and optimized algorithms to speed up the cracking process.

## Mitigating Brute Force Attacks

To protect against brute force attacks on Oracle SQL databases, it is important to implement strong security measures. Here are some recommended practices:

1. **Use Strong Passwords**: Encourage users to choose complex passwords that are difficult to guess. This includes a combination of uppercase and lowercase letters, numbers, and special characters.

2. **Account Lockouts**: Implement account lockout policies that temporarily lock user accounts after a certain number of failed login attempts. This can help prevent brute force attacks by slowing down the attacker's progress.

3. **Two-Factor Authentication**: Enable two-factor authentication for Oracle SQL accounts to add an extra layer of security. This requires users to provide a second form of verification, such as a code sent to their mobile device, in addition to their password.

4. **Monitoring and Logging**: Regularly monitor and review logs for any suspicious activity, such as multiple failed login attempts from the same IP address. This can help detect and respond to brute force attacks in a timely manner.

By implementing these security measures, you can significantly reduce the risk of successful brute force attacks on your Oracle SQL databases.
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
Brute force is a common method used in hacking to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords until the correct one is found. This method is often used when other methods, such as social engineering or exploiting vulnerabilities, are not successful.

Brute force attacks can be time-consuming and resource-intensive, especially if the password being targeted is long and complex. However, they can be effective against weak passwords or poorly implemented security measures.

There are several tools and resources available for conducting brute force attacks, including specialized software and scripts. These tools automate the process of trying different passwords and can be customized to target specific systems or accounts.

It is important to note that brute force attacks are illegal and unethical unless conducted with proper authorization and for legitimate purposes, such as penetration testing. Unauthorized brute force attacks can result in criminal charges and severe penalties.

To protect against brute force attacks, it is recommended to use strong, unique passwords that are not easily guessable. Additionally, implementing account lockouts, rate limiting, and CAPTCHA can help prevent automated brute force attacks. Regularly updating software and systems with the latest security patches can also help mitigate the risk of brute force attacks.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
### PostgreSQL

PostgreSQLはオープンソースのリレーショナルデータベース管理システムです。ブルートフォース攻撃は、PostgreSQLデータベースに対して非常に効果的な攻撃手法の1つです。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために、すべての可能な組み合わせを試行する方法です。

ブルートフォース攻撃は、通常、辞書攻撃と組み合わせて使用されます。辞書攻撃では、一般的なパスワードや単語のリストを使用して、攻撃対象のデータベースに対して試行します。ブルートフォース攻撃は、辞書攻撃が成功しなかった場合に使用され、すべての可能な組み合わせを試すことで、パスワードを特定します。

ブルートフォース攻撃は非常に時間がかかる場合がありますが、十分な計算リソースと時間があれば、成功する可能性があります。攻撃者は、高速なハードウェアやクラウドプロバイダーのリソースを利用して、ブルートフォース攻撃を実行することができます。

PostgreSQLデータベースをブルートフォース攻撃から保護するためには、強力なパスワードポリシーを実装し、パスワードの長さと複雑さを確保する必要があります。また、アカウントロックアウト機能やIP制限などのセキュリティメカニズムを使用することも重要です。さらに、最新のセキュリティパッチを適用し、PostgreSQLデータベースを常に最新の状態に保つことも重要です。

ブルートフォース攻撃は、PostgreSQLデータベースのセキュリティを脅かす可能性があるため、適切な対策を講じることが重要です。
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

A brute force attack on RDP involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This is done by using automated tools that can rapidly generate and test login credentials.

#### Methodology

1. **Enumeration**: Gather information about the target RDP server, such as the IP address, port number, and available usernames.
2. **Password List**: Create or obtain a password list that contains a large number of commonly used passwords, dictionary words, and variations.
3. **Brute Force Tool**: Use a brute force tool, such as Hydra or Medusa, to automate the process of trying different combinations of usernames and passwords.
4. **Configure Tool**: Set up the brute force tool with the target RDP server's IP address, port number, and the password list.
5. **Launch Attack**: Start the brute force attack and let the tool systematically try all possible combinations of usernames and passwords.
6. **Monitor Progress**: Monitor the tool's progress and look for any successful login attempts.
7. **Post-Attack**: Once the attack is complete, analyze the results and take appropriate actions, such as reporting any successful compromises or strengthening the security measures.

#### Countermeasures

To protect against brute force attacks on RDP, consider implementing the following countermeasures:

- **Strong Passwords**: Enforce the use of strong, complex passwords that are difficult to guess.
- **Account Lockout Policy**: Implement an account lockout policy that locks out user accounts after a certain number of failed login attempts.
- **Network Segmentation**: Separate the RDP server from the rest of the network to limit the potential impact of a successful brute force attack.
- **Two-Factor Authentication**: Implement two-factor authentication to add an extra layer of security to the RDP login process.
- **IP Whitelisting**: Restrict RDP access to specific IP addresses or ranges to limit the attack surface.
- **Monitoring and Logging**: Monitor RDP login attempts and log them for analysis and detection of suspicious activity.

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

- 強力なパスワードポリシーを実装する：長さ、複雑さ、一意性などの要件を設定し、強力なパスワードの使用を促します。
- パスワードのロックアウト：一定回数の誤ったパスワード試行後にアカウントをロックアウトすることで、攻撃者の試行回数を制限します。
- IP制限：特定のIPアドレスからのアクセスを制限することで、攻撃者のアクセスを制限します。
- 2要素認証（2FA）：追加のセキュリティレイヤーとして、2要素認証を実装します。

これらの対策を組み合わせることで、ブルートフォース攻撃からRedisを保護することができます。
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

One common brute-force attack method against Rsh is to systematically try different username and password combinations until a successful login is achieved. This can be done using automated tools such as Hydra or Medusa.

To perform a brute-force attack against Rsh, you would typically need a wordlist containing a list of possible usernames and passwords. The tool will then iterate through each combination, sending login requests to the target system. It is important to use a strong and diverse wordlist to increase the chances of success.

It is worth mentioning that brute-forcing Rsh is not recommended, as it is an outdated and insecure protocol. It is advisable to use more secure alternatives such as SSH (Secure Shell) for remote administration tasks.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsyncは、ファイル同期と転送のための強力なツールです。このツールは、ファイルの変更を検出し、変更された部分のみを転送することができます。これにより、大量のデータを効率的に転送することができます。

Rsyncは、ネットワーク上でファイルを転送するために使用されるため、セキュリティ上のリスクが存在します。攻撃者は、Rsyncの脆弱性を悪用して、不正なアクセスを試みることができます。

ブルートフォース攻撃は、Rsyncのパスワードを推測するための一般的な攻撃手法の1つです。攻撃者は、辞書攻撃や総当たり攻撃を使用して、正しいパスワードを見つけることを試みます。

Rsyncのセキュリティを強化するためには、強力なパスワードポリシーを実装し、パスワードの推測を困難にすることが重要です。また、公開鍵認証を使用することで、パスワードを使用せずにRsyncを安全に使用することもできます。

Rsyncのセキュリティをテストするためには、ブルートフォース攻撃をシミュレートすることができます。これにより、システムの脆弱性を特定し、適切な対策を講じることができます。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real-Time Streaming Protocol）は、ストリーミングメディアを配信するためのプロトコルです。RTSPは、クライアントとサーバー間でのメディアの制御や転送を可能にします。このプロトコルは、ビデオやオーディオのストリームをリアルタイムで送信するために使用されます。

RTSPの攻撃手法の一つに、ブルートフォース攻撃があります。ブルートフォース攻撃は、パスワードや認証情報を推測するために、連続的に試行する手法です。攻撃者は、辞書攻撃やランダムな文字列の組み合わせを使用して、正しいパスワードを見つけることを試みます。

ブルートフォース攻撃は、RTSPサーバーに対して行われる場合、サーバーのセキュリティを脆弱にする可能性があります。攻撃者が正しいパスワードを見つけると、サーバーにアクセスし、機密情報を盗み出すことができます。

RTSPサーバーのセキュリティを強化するためには、強力なパスワードポリシーを実装し、ブルートフォース攻撃を防ぐためにアカウントロックアウト機能を使用することが重要です。また、セキュリティパッチの適用やログの監視など、定期的なメンテナンスも必要です。

ブルートフォース攻撃は、RTSPサーバーの脆弱性を悪用する手法の一つです。セキュリティ意識を高め、適切な対策を講じることで、攻撃者からの侵入を防ぐことができます。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）は、ネットワークデバイスの管理と監視に使用されるプロトコルです。SNMPは、ネットワーク上のデバイスの情報を収集し、設定を変更するために使用されます。SNMPは、エージェントとマネージャの間で情報を交換するために使用されます。

SNMPは、デバイスの情報を取得するために、ブルートフォース攻撃の一部として使用されることがあります。ブルートフォース攻撃では、辞書やパスワードリストを使用して、デバイスのコミュニティストリング（SNMPの認証情報）を推測しようとします。

ブルートフォース攻撃は、自動化されたツールを使用して行われることが多く、大量のコミュニティストリングを試すことができます。攻撃者は、正しいコミュニティストリングを見つけることで、デバイスにアクセスし、機密情報を取得したり、設定を変更したりすることができます。

SNMPのブルートフォース攻撃を防ぐためには、強力なコミュニティストリングを使用し、不正なアクセスを検出するためのログ監視を行うことが重要です。また、SNMPバージョン3のようなセキュリティ機能を使用することも推奨されます。
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）は、ネットワーク上でファイル共有やリソース共有を行うためのプロトコルです。SMBは、Windowsオペレーティングシステムで広く使用されており、ファイルやプリンターなどのリソースをネットワーク上で共有するための機能を提供します。

SMBのブルートフォース攻撃は、辞書攻撃の一種であり、ユーザー名とパスワードの組み合わせを総当たりで試行し、正しい認証情報を見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃は、自動化ツールを使用して実行することができます。これにより、大量のユーザー名とパスワードの組み合わせを高速で試行することができます。攻撃者は、一般的なパスワードや辞書攻撃によって成功する可能性が高いパスワードを事前に選定することもあります。

SMBのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実施し、パスワードの複雑さを強化することが重要です。また、アカウントロックアウトポリシーを設定することで、一定回数の認証失敗後にアカウントをロックすることも有効です。さらに、ネットワーク上のSMBサーバーへのアクセスを制限することも推奨されます。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
SMTP（Simple Mail Transfer Protocol）は、電子メールの送信に使用されるプロトコルです。SMTPサーバーに接続し、メールを送信するために必要な情報を提供します。SMTPは、メールアドレスの確認、メールの送信、メールの受信など、さまざまな操作を実行するためのコマンドを提供します。

SMTPのブルートフォース攻撃は、辞書攻撃とも呼ばれ、SMTPサーバーに対して総当たり攻撃を行います。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーを特定するために使用されます。

ブルートフォース攻撃は、パスワードの推測に基づいており、時間がかかる場合があります。攻撃者は、辞書攻撃や総当たり攻撃のツールを使用して、自動的にパスワードを試すことができます。しかし、この攻撃は、セキュリティ対策が十分に強固な場合には成功しづらいです。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを採用し、パスワードの長さと複雑さを強化する必要があります。また、アカウントロックアウトやログイン試行回数の制限などのセキュリティ対策も有効です。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKSは、ネットワークプロトコルであり、プロキシサーバーを介してTCP/IP接続を確立するために使用されます。 SOCKSプロトコルは、クライアントとサーバーの間でデータを転送するための中間的な役割を果たします。 SOCKSプロキシは、ユーザーのIPアドレスを隠すために使用されることがあります。 SOCKSプロキシを使用すると、ユーザーは自分のIPアドレスを隠すことができ、インターネット上のリソースに匿名でアクセスすることができます。

SOCKSプロキシをハッキングに使用する場合、ブルートフォース攻撃は一般的な手法です。ブルートフォース攻撃では、ハッカーはすべての可能な組み合わせを試し、正しいパスワードを見つけるために繰り返しログインを試みます。これにより、ハッカーは不正なアクセスを試みることができます。

ブルートフォース攻撃は、パスワードが強力である場合には非常に困難ですが、弱いパスワードを使用している場合には非常に効果的です。ハッカーは、辞書攻撃やランダムな文字列の生成などの手法を使用して、パスワードを推測します。また、パスワードの長さや文字セットの制約を考慮する必要もあります。

ブルートフォース攻撃は、時間がかかる場合がありますが、成功すれば重要な情報を入手することができます。ハッカーは、ユーザーのアカウントにアクセスし、機密情報を盗むなどの悪意のある行為を行う可能性があります。
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
- ファイアウォールの設定：SSHポートへのアクセスを制限するために、ファイアウォールを使用する。

これらの対策を実施することで、SSHブルートフォース攻撃からシステムを保護することができます。
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

Telnetは、ネットワーク上のリモートコンピュータに接続するためのプロトコルです。このプロトコルを使用すると、リモートコンピュータにログインし、コマンドを実行することができます。Telnetは、ユーザー名とパスワードを使用して認証するため、セキュリティ上のリスクがあります。そのため、Telnetを使用する際には注意が必要です。

Telnetのブルートフォース攻撃は、辞書攻撃とも呼ばれます。攻撃者は、一連のパスワードを試し、正しいパスワードを見つけることを試みます。この攻撃は、パスワードが弱い場合やデフォルトのパスワードが使用されている場合に特に効果的です。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保する必要があります。また、Telnetの代わりによりセキュアなプロトコル（例：SSH）を使用することも推奨されます。

Telnetのブルートフォース攻撃は、セキュリティテストやペネトレーションテストの一環として使用されることがあります。ただし、許可なく他人のシステムにアクセスすることは違法ですので、適切な許可を得る必要があります。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）は、リモートデスクトッププロトコル（RDP）の一種であり、リモートマシンへのアクセスを提供します。VNCは、クライアントとサーバーの間でデスクトップ画面を共有するために使用されます。

VNCのブルートフォース攻撃は、パスワードの推測を行い、正しいパスワードを見つけることを試みます。これにより、攻撃者は不正なアクセスを取得し、リモートマシンを制御することができます。

ブルートフォース攻撃は、一般的に辞書攻撃と呼ばれる方法で実行されます。攻撃者は、事前に作成されたパスワードリストを使用して、すべての可能な組み合わせを試します。これにより、正しいパスワードが見つかるまで繰り返し試行することができます。

VNCのブルートフォース攻撃は、強力なパスワードポリシーが実装されていない場合に特に効果的です。攻撃者は、短いパスワードや一般的な単語を使用しているユーザーを狙います。

VNCのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの長さと複雑さを増やすことが重要です。また、アカウントロックアウト機能を有効にすることも推奨されます。これにより、一定回数の誤ったパスワード試行後にアカウントがロックされるため、攻撃者の試行回数を制限することができます。

さらに、VNCのポート（通常はポート5900）へのアクセスを制限することも重要です。不正なアクセスを試みる攻撃者は、ポートが閉じている場合には攻撃を行うことができません。

VNCのブルートフォース攻撃は、セキュリティ上の脆弱性を悪用するため、定期的なパッチ適用とセキュリティアップデートの実施も重要です。これにより、既知の脆弱性が修正され、攻撃者の攻撃を防ぐことができます。

最後に、VNCのログイン試行を監視し、異常なアクティビティを検出するためのセキュリティツールの使用も推奨されます。これにより、ブルートフォース攻撃などの不正なアクセス試行を早期に検知し、適切な対策を講じることができます。
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

Winrmは、Windowsリモート管理（WinRM）プロトコルを使用して、リモートでWindowsマシンを管理するためのサービスです。WinRMは、ネットワーク上のWindowsマシンと通信するための安全なリモート接続を提供します。

Winrmは、ブルートフォース攻撃の対象になる可能性があるため、セキュリティ上の注意が必要です。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証情報を推測するために連続的に試行する攻撃手法です。

Winrmのブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施し、複雑なパスワードを使用する。
- パスワードの定期的な変更を促す。
- ログイン試行回数の制限を設定する。
- ログイン試行の監視とログの分析を行う。
- マルチファクタ認証を使用する。

これらの対策を実施することで、Winrmのブルートフォース攻撃からシステムを保護することができます。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化することができます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ローカル

### オンラインクラッキングデータベース

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (ハッシュ、WPA2キャプチャ、およびMSOffice、ZIP、PDFのアーカイブ...)
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

7zは、高い圧縮率を持つオープンソースのファイルアーカイバです。7zファイルは、他の一般的なアーカイブ形式（zip、tar、gzipなど）よりも小さくなる傾向があります。

7zファイルのパスワードを解読するために、ブルートフォース攻撃を使用することができます。ブルートフォース攻撃は、すべての可能なパスワードの組み合わせを試すことで、正しいパスワードを見つける手法です。

ブルートフォース攻撃を実行するためには、パスワードリストが必要です。一般的なパスワードリストには、一般的なパスワードや辞書ワードが含まれています。また、特定のターゲットに関連する可能性のあるパスワードも含まれている場合があります。

ブルートフォース攻撃は非常に時間がかかる場合があります。パスワードの長さや複雑さによっては、数日または数週間かかることもあります。また、攻撃が検出される可能性もあるため、注意が必要です。

7zファイルのパスワードを解読するためには、パスワードクラッキングツールを使用することができます。一般的なツールには、John the RipperやHashcatなどがあります。これらのツールは、高速なパスワードクラッキング機能を提供し、ブルートフォース攻撃を効率的に実行することができます。

ブルートフォース攻撃は、合法的なセキュリティテストやパスワードの回復などの目的で使用されることもありますが、不正な目的で使用することは違法です。常に法律と倫理に従って行動するようにしてください。
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

ブルートフォース攻撃は、パスワードや暗号鍵を推測するために、すべての可能な組み合わせを試す攻撃手法です。この攻撃は、パスワードの弱さや予測可能性をテストするために使用されます。

### ブルートフォース攻撃の手法

1. 辞書攻撃：事前に作成された辞書ファイルを使用して、一連の単語やフレーズを試す方法です。この攻撃は、一般的なパスワードや一般的なフレーズに対して効果的です。

2. 総当たり攻撃：すべての可能な組み合わせを順番に試す方法です。この攻撃は、パスワードの長さや文字セットが限られている場合に有効です。

3. ハイブリッド攻撃：辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず、辞書攻撃を試し、成功しない場合には総当たり攻撃を試します。

### ブルートフォース攻撃のツール

1. Hydra：多くのプロトコル（SSH、FTP、Telnetなど）に対してブルートフォース攻撃を実行するためのツールです。

2. Medusa：SSH、FTP、Telnetなどのプロトコルに対してブルートフォース攻撃を実行するための高速なツールです。

3. John the Ripper：パスワードのハッシュを解読するためのツールで、ブルートフォース攻撃にも使用できます。

### ブルートフォース攻撃の対策

1. 強力なパスワードポリシーを実施する：長さ、複雑さ、一意性の要件を設定し、パスワードの変更を定期的に求める。

2. 二要素認証を使用する：パスワードに加えて、追加の認証要素（SMSコード、ワンタイムパスワードなど）を要求する。

3. ロックアウトポリシーを設定する：一定回数の認証失敗後にアカウントをロックするように設定する。

4. ログ監視を実施する：異常なアクティビティを検出し、ブルートフォース攻撃を早期に検知する。

5. キャプチャを使用する：ユーザーが人間であることを確認するために、キャプチャを導入する。

6. ブルートフォース攻撃の検出と防止のためのセキュリティソリューションを導入する。
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

1. 辞書攻撃: 事前に作成されたパスワードリストを使用して、ユーザーのパスワードを総当たりで試行します。一般的なパスワードや一般的な単語の組み合わせを試すことが多いです。

2. ブルートフォース攻撃: パスワードの全ての組み合わせを試行する手法です。これは非常に時間がかかるため、効率的な方法ではありません。しかし、強力なパスワードに対しても有効な手法です。

3. ハイブリッド攻撃: 辞書攻撃とブルートフォース攻撃を組み合わせた手法です。まず、辞書攻撃を試行し、成功しなかった場合にのみブルートフォース攻撃を行います。

NTLM クラッキングには、高性能なハードウェアやクラウドベースの計算リソースを利用することも可能です。これにより、クラッキングの速度を大幅に向上させることができます。

NTLM クラッキングは、合法的なセキュリティテストやパスワードリカバリの目的で使用されることがありますが、悪意のある目的で使用することは違法です。
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
### ケベロースティング

Keberoastingは、Active Directory（AD）環境で使用されるサービスアカウントのパスワードを解読するための攻撃手法です。この攻撃は、Kerberos認証プロトコルの脆弱性を利用しています。

攻撃者は、AD環境内のサービスアカウントのユーザー名を特定し、そのユーザー名に対してKerberosチケットを要求します。次に、攻撃者は取得したチケットをオフラインで解析し、サービスアカウントのパスワードを特定します。

Keberoasting攻撃は、サービスアカウントがKerberosのサービスチケットを要求する際に使用するサービスプリンシパル名（SPN）の脆弱性に基づいています。攻撃者は、SPNがRC4暗号化で保護されている場合、その暗号化を解読することでパスワードを取得します。

この攻撃手法を防ぐためには、AD環境内のサービスアカウントのパスワードを強力なものに設定し、暗号化アルゴリズムをより強力なものに変更する必要があります。また、サービスアカウントの権限を最小限に制限することも重要です。
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

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found. This method is effective when the password is weak or easily guessable. 

ブルートフォースは、システムやアカウントへの不正アクセスを得るために使用される一般的な方法です。正しいパスワードが見つかるまで、すべての可能なパスワードの組み合わせをシステマチックに試すことを含みます。この方法は、パスワードが弱いか、簡単に推測できる場合に効果的です。
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

* **Googleドライブにアップロード**すると、パスワードが自動的に削除されます
* **手動で**削除するには：
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

PFX証明書の作成や管理には、さまざまなツールやリソースが利用されます。一般的な手法としては、PFX証明書を作成するためのツールを使用し、秘密鍵と公開鍵のペアを生成します。また、PFX証明書を保護するために、強力なパスワードを設定することも重要です。

PFX証明書は、セキュリティの向上やデジタル通信の保護に役立つ重要なツールです。正しく管理され、適切に使用されることで、データの安全性を確保することができます。
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
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

Hashcatは、さまざまなハッシュアルゴリズムをサポートしており、異なるモードで使用することができます。以下に、主要なモードのいくつかを紹介します。

- **ハッシュモード**（モード0）：ハッシュ値を解読するために使用されます。ハッシュ値を入力として受け取り、対応する平文を見つけ出します。

- **ワードリストモード**（モード1）：事前に作成されたワードリストを使用して、ハッシュ値を解読します。ワードリストに含まれる単語を順番に試し、一致する平文を見つけ出します。

- **組み合わせモード**（モード2）：複数のワードリストを組み合わせて使用し、ハッシュ値を解読します。ワードリストの組み合わせを試し、一致する平文を見つけ出します。

- **ルールベースモード**（モード3）：ルールを適用してワードリストを変形させ、ハッシュ値を解読します。ルールには、文字の置換、追加、削除などの操作が含まれます。

- **ハイブリッドモード**（モード4）：ワードリストとルールベースの組み合わせを使用して、ハッシュ値を解読します。ワードリストをルールで変形させながら、一致する平文を見つけ出します。

これらのモードは、さまざまな攻撃シナリオに対応しており、ハッシュの解読に幅広く使用されます。
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

## ハッシュとは何ですか？

ハッシュは、パスワードやデータを暗号化するために使用される数学的な関数です。ハッシュ関数は、入力データを固定長のランダムな文字列（ハッシュ値）に変換します。ハッシュ関数は一方向関数であり、ハッシュ値から元のデータを復元することはできません。

## Windowsハッシュの種類

Windowsオペレーティングシステムでは、ユーザーのパスワードを保護するために、NTLM（NT LAN Manager）ハッシュとLM（LAN Manager）ハッシュの2種類のハッシュが使用されます。NTLMハッシュはより強力であり、LMハッシュはセキュリティ上の脆弱性があるため、現代のWindowsシステムでは非推奨とされています。

## ブルートフォース攻撃

ブルートフォース攻撃は、ハッシュを解読するための一般的な手法の1つです。この攻撃では、すべての可能なパスワードの組み合わせを試し、正しいパスワードを見つけるまで繰り返します。ブルートフォース攻撃は非常に時間がかかる場合がありますが、十分な計算リソースと時間があれば、ハッシュを解読することができます。

## ブルートフォース攻撃のツール

ブルートフォース攻撃を実行するためには、特定のツールを使用する必要があります。一般的なツールには、John the Ripper、Hashcat、Medusaなどがあります。これらのツールは、異なるハッシュタイプに対応しており、高速なハッシュクラッキングを実現するためのさまざまなテクニックを提供しています。

## ブルートフォース攻撃の対策

ブルートフォース攻撃から保護するためには、強力なパスワードポリシーを実装することが重要です。長いパスワード、大文字と小文字の組み合わせ、数字や特殊文字の使用など、複雑なパスワードを設定することが推奨されます。また、アカウントロックアウトポリシーを設定することも有効です。これにより、一定回数の誤ったパスワード入力後にアカウントがロックされるようになります。

## まとめ

Windowsハッシュのクラックは、ブルートフォース攻撃を使用して行われることがあります。ハッシュを解読するためには、特定のツールを使用し、十分な計算リソースと時間が必要です。ブルートフォース攻撃から保護するためには、強力なパスワードポリシーを実装し、アカウントロックアウトポリシーを設定することが重要です。
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

Brute force is a common method used to crack application hashes. It involves systematically trying every possible combination of characters until the correct password is found.

## Dictionary Attack

A dictionary attack is a type of brute force attack that uses a pre-defined list of commonly used passwords, known as a dictionary, to crack hashes. This method is effective against weak passwords that are easily guessable.

## Hybrid Attack

A hybrid attack combines elements of both brute force and dictionary attacks. It involves trying all possible combinations of characters, including variations of dictionary words, to crack hashes. This method is effective against stronger passwords that are not easily guessable.

## Rainbow Tables

Rainbow tables are precomputed tables of hashes and their corresponding plaintext passwords. They can be used to quickly crack hashes by looking up the plaintext password in the table. However, rainbow tables can be large and require a significant amount of storage space.

## GPU Acceleration

Graphics Processing Units (GPUs) can be used to accelerate the brute force cracking process. GPUs are highly parallel processors that can perform many calculations simultaneously, making them well-suited for password cracking. Tools like hashcat and John the Ripper support GPU acceleration.

## Online Hash Cracking Services

There are online services available that offer hash cracking capabilities. These services typically use powerful hardware and distributed computing to crack hashes quickly. However, it is important to note that using these services may raise legal and ethical concerns, as they can be used for malicious purposes.

## Conclusion

Brute force attacks, dictionary attacks, hybrid attacks, rainbow tables, GPU acceleration, and online hash cracking services are all methods that can be used to crack application hashes. It is important to use these techniques responsibly and within the bounds of the law.
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
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
