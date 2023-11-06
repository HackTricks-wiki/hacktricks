# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。
*
* .

</details>

## Gatekeeper

**Gatekeeper（ゲートキーパー）**は、Macオペレーティングシステム向けに開発されたセキュリティ機能で、ユーザーがシステム上で**信頼できるソフトウェアのみを実行**することを保証するために設計されています。これは、ユーザーがApp Store以外のソースからダウンロードして開こうとするソフトウェア（アプリ、プラグイン、インストーラーパッケージなど）を**検証**することによって機能します。

Gatekeeperの主要なメカニズムは、**検証**プロセスにあります。ダウンロードしたソフトウェアが**認識された開発者によって署名**されているかどうかをチェックし、ソフトウェアの信頼性を確認します。さらに、ソフトウェアが**Appleによって公証**されているかどうかも確認し、既知の悪意のあるコンテンツが含まれていないこと、および公証後に改ざんされていないことを確認します。

さらに、Gatekeeperは、ユーザーがダウンロードしたソフトウェアの初回の実行を承認するようユーザーに**プロンプトを表示**することで、ユーザーの制御とセキュリティを強化します。この保護機能により、ユーザーは無害なデータファイルと間違えて実行する可能性のある潜在的に有害な実行可能コードを誤って実行することを防ぐことができます。

### アプリケーションの署名

アプリケーションの署名は、Appleのセキュリティインフラストラクチャの重要な要素です。これは、ソフトウェアの作成者（開発者）の**身元を確認**し、コードが最後に署名されてから改ざんされていないことを保証するために使用されます。

以下は、その動作方法です。

1. **アプリケーションの署名:** 開発者がアプリケーションを配布する準備ができたら、**開発者が秘密鍵を使用してアプリケーションに署名**します。この秘密鍵は、開発者がApple Developer Programに登録した際にAppleから発行される**証明書**と関連付けられています。署名プロセスでは、アプリのすべての部分の暗号ハッシュを作成し、このハッシュを開発者の秘密鍵で暗号化します。
2. **アプリケーションの配布:** 署名されたアプリケーションは、開発者の証明書と共にユーザーに配布されます。この証明書には、対応する公開鍵が含まれています。
3. **アプリケーションの検証:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Macオペレーティングシステムは開発者の証明書から公開鍵を使用してハッシュを復号化します。その後、アプリケーションの現在の状態に基づいてハッシュを再計算し、これを復号化されたハッシュと比較します。一致する場合、開発者が署名した後にアプリケーションが**変更されていない**ことを意味し、システムはアプリケーションの実行を許可します。

アプリケーションの署名は、AppleのGatekeeperテクノロジーの重要な部分です。ユーザーが**インターネットからダウンロードしたアプリケーションを開こうとする**と、Gatekeeperはアプリケーションの署名を検証します。Appleから既知の開発者に発行された証明書で署名されており、コードが改ざんされていない場合、Gatekeeperはアプリケーションの実行を許可します。それ以外の場合、Gatekeeperはアプリケーションをブロックし、ユーザーに警告を表示します。

macOS Catalina以降、**GatekeeperはアプリケーションがAppleによって公証されているかどうかもチェック**します。公証プロセスでは、アプリケーションが既知のセキュリティの問題や悪意のあるコードを含んでいないかどうかをチェックし、これらのチェックに合格した場合、AppleはGatekeeperが検証できるアプリケーションにチケットを追加します。

#### 署名の確認

**マルウェアサンプル**をチェックする際には、常にバイナリの**署名を確認**する必要があります。署名した**開発者**が既に**マルウェア**と関連している可能性があるためです。
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization（公証）

Appleの公証プロセスは、ユーザーを潜在的に有害なソフトウェアから保護するための追加の安全策として機能します。これは、開発者が自分のアプリケーションをAppleの公証サービスに提出することを含みます。このサービスは、App Reviewとは異なるものであり、提出されたソフトウェアを悪意のあるコンテンツやコード署名の潜在的な問題から検査する自動化システムです。

ソフトウェアがこの検査を通過し、懸念事項がない場合、公証サービスは公証チケットを生成します。その後、開発者はこのチケットをソフトウェアに添付する必要があります。このプロセスは「ステープリング」と呼ばれます。さらに、公証チケットはオンラインで公開され、Gatekeeper（Appleのセキュリティテクノロジー）がアクセスできるようになります。

ユーザーがソフトウェアを初めてインストールまたは実行する際、実行可能ファイルにステープルされているか、オンラインで見つかるかにかかわらず、公証チケットの存在はGatekeeperにソフトウェアがAppleによって公証されたことを通知します。その結果、Gatekeeperは初回起動ダイアログに説明的なメッセージを表示し、ソフトウェアがAppleによって悪意のあるコンテンツのチェックを受けたことを示します。このプロセスにより、ユーザーは自分のシステムにインストールまたは実行するソフトウェアのセキュリティに対する信頼性が向上します。

### GateKeeperの列挙

GateKeeperは、信頼されていないアプリケーションの実行を防止するための複数のセキュリティコンポーネントであり、またその一部でもあります。

GateKeeperの状態は、次のコマンドで確認することができます：
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
GateKeeperの署名チェックは、**Quarantine属性を持つファイル**にのみ実行されます。すべてのファイルに対して実行されるわけではありません。
{% endhint %}

GateKeeperは、**設定と署名**に基づいてバイナリが実行可能かどうかをチェックします。

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

この設定を保持するデータベースは、**`/var/db/SystemPolicy`**にあります。次のコマンドをrootとして実行して、このデータベースを確認できます。
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
最初のルールが「**App Store**」で終わり、2番目のルールが「**Developer ID**」で終わっていることに注目し、前のイメージでは**App Storeと識別された開発者からのアプリの実行が有効になっている**ことがわかります。\
その設定をApp Storeに変更すると、「**Notarized Developer ID**」のルールが消えます。

また、**GKE**タイプのルールは数千あります。
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
これらは、**`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`、`/var/db/gke.bundle/Contents/Resources/gk.db`**、および**`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**から取得されたハッシュです。

**`spctl`**のオプション**`--master-disable`**と**`--global-disable`**は、これらの署名チェックを完全に**無効化**します。
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全に有効にされると、新しいオプションが表示されます：

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

GateKeeperによって**アプリが許可されるかどうかを確認**することができます。
```bash
spctl --assess -v /Applications/App.app
```
GateKeeperに新しいルールを追加して、特定のアプリの実行を許可することが可能です。以下のコマンドを使用します:

```bash
spctl --add --label "Approved" /path/to/app
```

このコマンドは、指定したパスにあるアプリを"Approved"というラベルでGateKeeperに追加します。これにより、アプリは実行可能となります。
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### ファイルの隔離

アプリケーションやファイルを**ダウンロード**する際、macOSの特定のアプリケーション（ウェブブラウザやメールクライアントなど）は、ダウンロードされたファイルに一般的に知られている「**隔離フラグ**」と呼ばれる拡張ファイル属性を付加します。この属性は、ファイルが信頼されていないソース（インターネット）から来ており、潜在的なリスクを持っている可能性があることを示すセキュリティ対策として機能します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。たとえば、一般的なBitTorrentクライアントソフトウェアは通常、このプロセスをバイパスします。

**隔離フラグが存在する場合、ユーザーがファイルを実行しようとすると、macOSのGatekeeperセキュリティ機能に通知されます**。

隔離フラグが存在しない場合（一部のBitTorrentクライアントを介してダウンロードされたファイルなど）、Gatekeeperのチェックは実行されない場合があります。したがって、安全性の低いまたは不明なソースからダウンロードされたファイルを開く際には注意が必要です。

{% hint style="info" %}
コード署名の**妥当性**をチェックすることは、コードとそのバンドルされたリソースの暗号ハッシュを生成するなど、**リソースを多く消費する**プロセスです。さらに、証明書の妥当性をチェックするには、発行後に取り消されていないかをAppleのサーバーにオンラインで確認する必要があります。これらの理由から、完全なコード署名と公証チェックは、**アプリが起動するたびに実行するのは現実的ではありません**。

したがって、これらのチェックは**隔離属性を持つアプリを実行するときにのみ実行されます**。
{% endhint %}

{% hint style="warning" %}
この属性は、ファイルを作成/ダウンロードするアプリケーションによって**設定する必要があります**。

ただし、サンドボックス化されたファイルは、作成されるすべてのファイルにこの属性が設定されます。また、サンドボックス化されていないアプリは、自分自身で設定するか、**Info.plist**に[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc)キーを指定することで、システムが作成されるファイルに`com.apple.quarantine`の拡張属性を設定します。
{% endhint %}

次のコマンドで、その状態を**確認し、有効/無効にする**ことができます（ルート権限が必要です）:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
次のコマンドを使用して、ファイルに拡張属性があるかどうかを確認することもできます:

```bash
xattr -p com.apple.quarantine <file>
```

このコマンドは、指定した `<file>` に拡張属性 `com.apple.quarantine` がある場合、その値を表示します。
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
次に、**拡張属性**の**値**を確認し、次のコマンドでクォレンティン属性を書き込んだアプリを特定します。
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
そして、次のコマンドでその属性を**削除**します：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
次のコマンドで、隔離されたファイルをすべて検索します：

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

### XProtect

XProtectは、macOSに組み込まれた**アンチマルウェア**機能です。XProtectは、アプリケーションが初めて起動されるか変更される際に、既知のマルウェアと危険なファイルタイプのデータベースと照合します。Safari、Mail、またはMessagesなどの特定のアプリを介してファイルをダウンロードすると、XProtectは自動的にファイルをスキャンします。データベース内の既知のマルウェアと一致する場合、XProtectはファイルの実行を**防止**し、脅威を警告します。

XProtectデータベースは、Appleによって定期的に**更新**され、これらの更新は自動的にMacにダウンロードおよびインストールされます。これにより、XProtectは常に最新の既知の脅威と同期されます。

ただし、XProtectは**完全なアンチウイルスソリューションではありません**。XProtectは特定の既知の脅威のリストのみをチェックし、ほとんどのアンチウイルスソフトウェアのようにオンアクセススキャンを実行しません。

最新のXProtectの更新に関する情報を取得するには、次のコマンドを実行します：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtectは、**/Library/Apple/System/Library/CoreServices/XProtect.bundle**というSIPで保護された場所にあり、バンドル内にはXProtectが使用する情報が含まれています：

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**：これらのcdhashを持つコードがレガシー権限を使用できるようにします。
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**：BundleIDとTeamIDまたは最小バージョンを示すことで、ロードが禁止されているプラグインと拡張機能のリストです。
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**：マルウェアを検出するためのYaraルールです。
* **`XProtect.bundle/Contents/Resources/gk.db`**：ブロックされたアプリケーションとTeamIDのハッシュを持つSQLite3データベースです。

XProtectに関連する別のアプリケーションである**`/Library/Apple/System/Library/CoreServices/XProtect.app`**もありますが、これはGatekeeperプロセスとは関係ありません。

## Gatekeeperの回避方法

Gatekeeperをバイパスする方法（ユーザーに何かをダウンロードさせ、Gatekeeperがそれを許可しないはずのときに実行させる方法）は、macOSの脆弱性と見なされます。これらは、過去にGatekeeperをバイパスするために使用されたいくつかの技術に割り当てられたCVEです：

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**によって抽出されると、**886文字以上のパス**を持つファイルは、com.apple.quarantineの拡張属性を継承できず、これにより**Gatekeeperをバイパス**することが可能になります。

詳細については、[**元のレポート**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を参照してください。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**でアプリケーションが作成されると、実行するための情報は`application.app/Contents/document.wflow`にあり、実行可能ファイルにはありません。実行可能ファイルは、**Automator Application Stub**と呼ばれる汎用のAutomatorバイナリです。

したがって、`application.app/Contents/MacOS/Automator\ Application\ Stub`を**シンボリックリンクで別のAutomator Application Stubに指定**することで、`document.wflow`（スクリプト）内の内容を実行し、実際の実行可能ファイルにはquarantine xattrがないため、Gatekeeperをトリガーせずに実行することができます。

例として期待される場所：`/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については、[**元のレポート**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を参照してください。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このバイパスでは、zipファイルが作成され、`application.app`ではなく`application.app/Contents`から圧縮が開始されました。したがって、**quarantine属性**は**`application.app/Contents`内のすべてのファイル**に適用されましたが、Gatekeeperがチェックしていたのは`application.app`であり、`application.app`がトリガーされたときには**quarantine属性が存在しなかったため、Gatekeeperがバイパス**されました。
```bash
zip -r test.app/Contents test.zip
```
詳細な情報については、[**元のレポート**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)を参照してください。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なるものの、この脆弱性の悪用は前のものと非常に似ています。この場合、**`application.app/Contents`** からApple Archiveを生成し、**Archive Utility** によって展開される際に **`application.app` には検疫属性が付与されない**ようにします。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
詳細な情報については、[**元のレポート**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)を参照してください。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**は、ファイルの属性の書き込みを誰にも制限するために使用できます。
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
さらに、**AppleDouble**ファイル形式は、そのACEを含むファイルをコピーします。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、xattrとして保存されているACLテキスト表現である**`com.apple.acl.text`**が、展開されたファイルのACLとして設定されることがわかります。したがって、他のxattrの書き込みを防止するACLを持つzipファイルにアプリケーションを圧縮した場合、quarantine xattrはアプリケーションに設定されませんでした。
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file shuold be without a wuarantine xattr
```
詳細については、[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を参照してください。

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chromeは、いくつかのmacOSの内部的な問題のために、ダウンロードされたファイルに隔離属性を設定していませんでした**。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDoubleファイル形式は、ファイルの属性を`._`で始まる別のファイルに保存し、これによりmacOSマシン間でファイルの属性をコピーするのに役立ちます。しかし、AppleDoubleファイルを展開した後、`._`で始まるファイルには**隔離属性が設定されていない**ことがわかりました。

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

ゲートキーパーをバイパスすることができるようになりました。クイックタイムのアプリケーションを作成するために、AppleDouble名規則（`._`で始まる）を使用してDMGファイルアプリケーションを作成し、クイックタイムのアプリケーションとして表示されるファイルを作成しました。この隠しファイルにはクイックタイムの属性が設定されていません。DMGファイルが実行されると、クイックタイムの属性がないため、ゲートキーパーをバイパスします。
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
