# macOSセキュリティ保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Gatekeeper

**Gatekeeper**は、Macオペレーティングシステム向けに開発されたセキュリティ機能で、ユーザーがシステム上で信頼できるソフトウェアのみを実行することを保証するために設計されています。これは、ユーザーがApp Store以外のソースからダウンロードして開こうとするソフトウェア（アプリ、プラグイン、インストーラーパッケージなど）を**検証**することによって機能します。

Gatekeeperの主な仕組みは、**検証**プロセスにあります。ダウンロードしたソフトウェアが**認識された開発者によって署名されているか**をチェックし、ソフトウェアの信頼性を確認します。さらに、ソフトウェアが**Appleによって公証**されているかどうかを確認し、既知の悪意のあるコンテンツが含まれていないこと、および公証後に改ざんされていないことを確認します。

さらに、Gatekeeperは、ユーザーがダウンロードしたソフトウェアの初回の開封を**承認するようユーザーに促す**ことで、ユーザーの制御とセキュリティを強化します。この保護機能により、ユーザーは無害なデータファイルと間違えて害のある実行可能なコードを誤って実行することを防ぐことができます。
```bash
# Check the status
spctl --status
# Enable Gatekeeper
sudo spctl --master-enable
# Disable Gatekeeper
sudo spctl --master-disable
```
### アプリケーションの署名

アプリケーションの署名は、Appleのセキュリティインフラストラクチャの重要な要素です。これは、ソフトウェアの作者（開発者）の身元を確認し、コードが最後に署名されてから改ざんされていないことを保証するために使用されます。

以下は、その仕組みです。

1. **アプリケーションの署名:** 開発者がアプリケーションを配布する準備ができたら、彼らは**プライベートキーを使用してアプリケーションに署名**します。このプライベートキーは、Apple Developer Programに登録する際にAppleが開発者に発行する**証明書**と関連付けられています。署名プロセスでは、アプリのすべての部分の暗号ハッシュを作成し、このハッシュを開発者のプライベートキーで暗号化します。
2. **アプリケーションの配布:** 署名されたアプリケーションは、開発者の証明書と共にユーザーに配布されます。証明書には、対応する公開キーが含まれています。
3. **アプリケーションの検証:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Macのオペレーティングシステムは、開発者の証明書から公開キーを使用してハッシュを復号化します。その後、アプリケーションの現在の状態に基づいてハッシュを再計算し、これを復号化されたハッシュと比較します。一致する場合、開発者が署名した後にアプリケーションが変更されていないことを意味し、システムはアプリケーションの実行を許可します。

アプリケーションの署名は、AppleのGatekeeperテクノロジーの重要な部分です。ユーザーが**インターネットからダウンロードしたアプリケーションを開こうとする**と、Gatekeeperはアプリケーションの署名を検証します。Appleが既知の開発者に発行した証明書で署名されており、コードが改ざんされていない場合、Gatekeeperはアプリケーションの実行を許可します。それ以外の場合、Gatekeeperはアプリケーションをブロックし、ユーザーに警告を表示します。

macOS Catalina以降、Gatekeeperはさらなるセキュリティレイヤーを追加するために、アプリケーションがAppleによって**公証されているかどうかもチェック**します。公証プロセスでは、アプリケーションが既知のセキュリティの問題や悪意のあるコードを持っていないかをチェックし、これらのチェックに合格した場合、AppleはGatekeeperが検証できるアプリケーションにチケットを追加します。

#### 署名の確認

**マルウェアのサンプル**を確認する場合は、常にバイナリの**署名を確認**する必要があります。署名した**開発者**は既に**マルウェア**と関連している可能性があるためです。
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
### ノタリゼーション

Appleのノタリゼーションプロセスは、ユーザーを潜在的に有害なソフトウェアから保護するための追加の保護策として機能します。これは、開発者が自分のアプリケーションをAppleのノタリーサービスに提出することを含みます。このサービスは、App Reviewとは異なるものであり、提出されたソフトウェアを悪意のあるコンテンツやコード署名の潜在的な問題の有無を調査する自動化されたシステムです。

ソフトウェアがこの検査を通過し、懸念事項を引き起こさない場合、ノタリーサービスはノタリゼーションチケットを生成します。その後、開発者はこのチケットを自分のソフトウェアに添付する必要があります。このプロセスは「ステープリング」として知られています。さらに、ノタリゼーションチケットはオンラインでも公開され、AppleのセキュリティテクノロジーであるGatekeeperがアクセスできるようになります。

ユーザーがソフトウェアを初めてインストールまたは実行する際、実行可能ファイルにステープルされているか、オンラインで見つかるかに関わらず、ノタリゼーションチケットの存在はGatekeeperにソフトウェアがAppleによってノタリゼーションされたことを通知します。その結果、Gatekeeperは初回起動ダイアログに説明的なメッセージを表示し、ソフトウェアがAppleによって悪意のあるコンテンツのチェックを受けたことを示します。このプロセスにより、ユーザーは自分のシステムにインストールまたは実行するソフトウェアのセキュリティに対する信頼性が向上します。

### クォリンティンファイル

アプリケーションやファイルをダウンロードする際、特定のmacOSアプリケーション（ウェブブラウザやメールクライアントなど）は、ダウンロードされたファイルに一般的に「クォリンティンフラグ」として知られる拡張ファイル属性を添付します。この属性は、ファイルを信頼できないソース（インターネット）からのものとしてマークし、潜在的なリスクを持つ可能性があることを示すセキュリティ対策として機能します。ただし、すべてのアプリケーションがこの属性を添付するわけではありません。たとえば、一般的なBitTorrentクライアントソフトウェアは通常、このプロセスをバイパスします。

クォリンティンフラグが存在する場合（一部のBitTorrentクライアントを介してダウンロードされたファイルなど）、ユーザーがファイルを実行しようとすると、macOSのGatekeeperセキュリティ機能に通知されます。

クォリンティンフラグが存在しない場合（一部のBitTorrentクライアントを介してダウンロードされたファイルなど）、Gatekeeperのチェックは実行されない場合があります。したがって、ユーザーは安全性の低いまたは不明なソースからダウンロードされたファイルを開く際に注意を払う必要があります。

{% hint style="info" %}
コード署名の妥当性をチェックすることは、コードとそのバンドルされたリソースの暗号ハッシュを生成するなど、リソースを多く消費するプロセスです。さらに、証明書の妥当性をチェックするには、発行後に取り消されていないかどうかをAppleのサーバーにオンラインで確認する必要があります。これらの理由から、完全なコード署名とノタリゼーションのチェックは、アプリが起動するたびに実行するのは現実的ではありません。

したがって、これらのチェックは「クォリンティン属性を持つアプリを実行する場合にのみ実行されます。」
{% endhint %}

{% hint style="warning" %}
**Safariやその他のウェブブラウザやアプリケーションがダウンロードしたファイルにマークする必要があることに注意してください。**

さらに、サンドボックス化されたプロセスによって作成されたファイルにも、サンドボックスからの脱出を防ぐためにこの属性が追加されます。
{% endhint %}

次のコマンドで状態を確認し、有効/無効にすることができます（ルート権限が必要です）:
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
xattr portada.png
com.apple.macl
com.apple.quarantine
```
次のコマンドで、**拡張属性**の**値**を確認します：

```bash
xattr -l <file>
```

このコマンドは、指定した `<file>` の拡張属性の値を表示します。
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```
そして、次のようにしてその属性を**削除**します：
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
## XProtect

XProtectは、macOSに組み込まれた**アンチマルウェア**機能です。これは、Appleのセキュリティシステムの一部であり、マルウェアや悪意のあるプラグインからMacを守るためにバックグラウンドで静かに動作します。

XProtectは、ダウンロードされたファイルを**既知のマルウェアと危険なファイルタイプのデータベース**と照合することで機能します。Safari、Mail、またはMessagesなどの特定のアプリを介してファイルをダウンロードすると、XProtectは自動的にファイルをスキャンします。データベース内の既知のマルウェアと一致する場合、XProtectはファイルの実行を**防止**し、脅威を警告します。

XProtectのデータベースは、Appleによって**定期的に更新**され、これらの更新は自動的にMacにダウンロードおよびインストールされます。これにより、XProtectは常に最新の既知の脅威と同期されます。

ただし、XProtectは**完全なアンチウイルスソリューションではない**ことに注意してください。XProtectは特定の既知の脅威のリストのみをチェックし、ほとんどのアンチウイルスソフトウェアのようにオンアクセススキャンを実行しません。したがって、XProtectは既知のマルウェアに対する保護層を提供しますが、インターネットからファイルをダウンロードしたり、メールの添付ファイルを開く際には注意が必要です。

最新のXProtectの更新に関する情報を取得するには、次のコマンドを実行します：

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラの一部です。その名前からもわかるように、MRTの主な機能は、感染したシステムから既知のマルウェアを**除去すること**です。

マック上でマルウェアが検出されると（XProtectまたは他の手段によって）、MRTは自動的に**マルウェアを除去**するために使用されます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されるときや新しいマルウェアの定義がダウンロードされるときに実行されます（MRTがマルウェアを検出するためのルールはバイナリ内にあるようです）。

XProtectとMRTは、どちらもmacOSのセキュリティ対策の一部ですが、異なる機能を果たしています：

* **XProtect**は予防ツールです。ファイルが（特定のアプリケーションを介して）ダウンロードされるときに**ファイルをチェック**し、既知のマルウェアの種類を検出した場合は、**ファイルを開かないように**して、最初にシステムにマルウェアが感染するのを防ぎます。
* 一方、**MRT**は**反応型のツール**です。マルウェアがシステムで検出された後、問題のあるソフトウェアを除去してシステムをクリーンアップすることを目的としています。

## プロセス制限

### SIP - システム整合性保護

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### サンドボックス

MacOSサンドボックスは、サンドボックスプロファイルで指定された**許可されたアクションに制限されたアプリケーション**の実行を制限します。これにより、**アプリケーションが予期されたリソースにのみアクセスする**ことが保証されます。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明性、同意、および制御

**TCC（透明性、同意、および制御）**は、macOSのメカニズムであり、プライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**するためのものです。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## 信頼キャッシュ

Apple macOSの信頼キャッシュ、またはAMFI（Apple Mobile File Integrity）キャッシュは、macOSのセキュリティメカニズムであり、**許可されていないまたは悪意のあるソフトウェアの実行を防止**するために設計されています。基本的には、ソフトウェアの**整合性と信頼性を検証するためにオペレーティングシステムが使用する暗号ハッシュのリスト**です。

macOSでアプリケーションまたは実行可能ファイルが実行しようとすると、オペレーティングシステムはAMFI信頼キャッシュをチェックします。ファイルのハッシュが信頼キャッシュに見つかった場合、システムはそのプログラムを実行を**許可**します。なぜなら、それを信頼されたものと認識しているからです。

## 起動制約

Appleの署名されたバイナリを起動できる場所と方法を制御します：

* launchdによって実行されるべきアプリを直接起動することはできません。
* /System/のような信頼された場所の外部でアプリを実行することはできません。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
