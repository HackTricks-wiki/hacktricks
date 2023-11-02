# macOSセキュリティ保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指すことが多く、これらの3つのmacOSセキュリティモジュールは、**ユーザーが潜在的に悪意のあるソフトウェアを実行するのを防ぐ**ために使用されます。

詳細は次の場所で確認できます：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

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

**TCC（透明性、同意、および制御）**は、macOSの機構であり、一般的にはプライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**します。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれる場合があります。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 起動/環境制約と信頼キャッシュ

macOSの起動制約は、プロセスの起動を**調整するセキュリティ機能**であり、プロセスの起動を**誰が**、**どのように**、**どこから**行えるかを定義します。macOS Venturaで導入されたこれらは、システムバイナリを**信頼キャッシュ**内の制約カテゴリに分類します。各実行可能バイナリには、**自己**、**親**、**責任**の制約を含む**起動**のための**ルール**が設定されています。macOS Sonomaでは、サードパーティのアプリケーションにも拡張され、これらの機能はプロセスの起動条件を制御することで、潜在的なシステムの脆弱性を緩和するのに役立ちます。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラの一部です。その名前からもわかるように、MRTの主な機能は、感染したシステムから既知のマルウェアを**削除すること**です。

Macでマルウェアが検出されると（XProtectまたは他の手段によって）、MRTを使用してマルウェアを自動的に**削除**することができます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されるときや新しいマルウェア定義がダウンロードされるときに実行されます（マルウェアを検出するためのMRTのルールはバイナリ内にあるようです）。

XProtectとMRTは、どちらもmacOSのセキュリティ対策の一部ですが、異なる機能を果たしています：

* **XProtect**は予防ツールです。ファイルが（特定のアプリケーションを介して）ダウンロードされるときに**ファイルをチェック**し、既知のマルウェアの種類を検出した場合は、ファイルを**開かないように**して、マルウェアが最初にシステムに感染するのを防ぎます。
* 一方、**MRT**は**反応型のツール**です。マルウェアがシステムで検出された後、問題のあるソフトウェアを**削除**してシステムをクリーンアップすることを目的としています。

MRTアプリケーションは、**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## バックグラウンドタスクの管理

**macOS**は、ツールがコードの実行を継続するためのよく知られた**手法を使用するたびにアラート**を表示するようになりました。これにより、ユーザーは**どのソフトウェアが持続しているか**をよりよく把握することができます。

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**デーモン**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**エージェント**で実行されます。

**`backgroundtaskmanagementd`**が永続フォルダに何かがインストールされていることを知る方法は、**FSEventsを取得**し、それに対していくつかの**ハンドラ**を作成することです。

さらに、Appleが管理している**よく知られたアプリケーション**のリストが含まれているplistファイルがあります。場所は次のとおりです：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### 列挙

AppleのCLIツールを使用して、設定されているすべてのバックグラウンドアイテムを列挙することができます。
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、[**DumpBTM**](https://github.com/objective-see/DumpBTM)を使用してこの情報をリストすることも可能です。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は**`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**に保存されており、TerminalにはFDAが必要です。

### BTMの操作

新しい永続性が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**というタイプのイベントが発生します。したがって、このイベントが送信されないようにするか、エージェントがユーザーに警告しないようにする方法は、攻撃者がBTMを**バイパス**するのに役立ちます。

* **データベースのリセット**: 以下のコマンドを実行すると、データベースがリセットされます（基盤から再構築されるはずです）。ただし、何らかの理由で、これを実行した後、**システムが再起動されるまで新しい永続性は警告されません**。
* **root**が必要です。
```bash
# Reset the database
sfltool resettbtm
```
* **エージェントの停止**: エージェントに停止シグナルを送信することで、新しい検出が見つかった際にユーザーに通知されないようにすることが可能です。
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **バグ**: もし**永続性を作成したプロセスがすぐに終了する**場合、デーモンはそれに関する情報を取得しようと試み、失敗し、新しい永続性が存在することを示すイベントを送信することができません。

BTMに関する参考文献と**詳細情報**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか**？ HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセス**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有**するには、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
