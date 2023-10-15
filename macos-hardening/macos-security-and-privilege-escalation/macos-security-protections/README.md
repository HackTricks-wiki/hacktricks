# macOSセキュリティ保護

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指すことが多く、これらの3つのmacOSセキュリティモジュールは、**ユーザーが潜在的に悪意のあるソフトウェアを実行するのを防ぐ**ために使用されます。

詳細は次を参照してください：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## プロセス制限

### SIP - システム整合性保護

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### サンドボックス

MacOSサンドボックスは、サンドボックスプロファイルで指定された**許可されたアクションに制限されたアプリケーション**の実行を制限します。これにより、**アプリケーションが予期されたリソースにのみアクセスすることが保証**されます。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明性、同意、および制御

**TCC（透明性、同意、および制御）**は、macOSの機構であり、一般的にはプライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**します。これには、位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれる場合があります。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 起動制約

**Appleの署名されたバイナリ**を**どこから**および**何を**起動できるかを制御します：

* launchdによって実行されるべきアプリを直接起動できません。
* 信頼された場所（/System/など）の外部でアプリを実行できません。

この制約に関する情報を含むファイルは、macOSの**`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**にあります（iOSでは、**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**にあるようです）。

ツール[**img4tool**](https://github.com/tihmstar/img4tool)を使用して、キャッシュを抽出することができるようです：
```bash
img4tool -e in.img4 -o out.bin
```
(ただし、M1ではコンパイルできませんでした)。[**pyimg4**](https://github.com/m1stadev/PyIMG4)を使用することもできますが、次のスクリプトはその出力では機能しません。

次に、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)のようなスクリプトを使用してデータを抽出できます。

そのデータから、**`0`の起動制約値**を持つアプリをチェックできます。これは制約されていないアプリです（各値の詳細については[**こちら**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)を参照してください）。

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラの一部です。その名前からもわかるように、MRTの主な機能は、感染したシステムから既知のマルウェアを**削除すること**です。

マルウェアがMacで検出されると（XProtectまたは他の手段によって）、MRTを使用してマルウェアを自動的に**削除**することができます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されるか、新しいマルウェア定義がダウンロードされると実行されます（マルウェアを検出するためのMRTのルールはバイナリ内にあるようです）。

XProtectとMRTは、どちらもmacOSのセキュリティ対策の一部ですが、異なる機能を持っています：

* **XProtect**は予防ツールです。ファイルがダウンロードされると（特定のアプリケーションを介して）、**ファイルをチェック**し、既知のマルウェアの種類を検出した場合は、**ファイルを開かないように**して、最初にシステムにマルウェアが感染するのを防ぎます。
* 一方、**MRT**は**反応型のツール**です。マルウェアがシステムで検出された後、問題のあるソフトウェアを削除してシステムをクリーンアップすることを目的としています。

MRTアプリケーションは、**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## バックグラウンドタスクの管理

**macOS**は、ツールがコードの実行を継続するためのよく知られた**手法（ログインアイテム、デーモンなど）**を使用するたびに**アラートを表示**するため、ユーザーは**どのソフトウェアが継続しているか**をよりよく把握できます。

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
* **バグ**: もし**永続化を作成したプロセスがすぐに終了する**場合、デーモンはそれに関する**情報を取得しようと試み、**失敗し、新しい永続化が行われていることを示す**イベントを送信することができなくなります。

BTMに関する参考文献と**詳細情報**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

## Trust Cache

Apple macOSの信頼キャッシュ、時にはAMFI（Apple Mobile File Integrity）キャッシュとも呼ばれるものは、macOSでの**不正なソフトウェアや悪意のあるソフトウェアの実行を防止する**ためのセキュリティメカニズムです。基本的には、オペレーティングシステムがソフトウェアの**整合性と信頼性を検証するために使用する暗号ハッシュのリスト**です。

macOSでアプリケーションや実行可能ファイルが実行しようとすると、オペレーティングシステムはAMFI信頼キャッシュをチェックします。もしファイルのハッシュが信頼キャッシュに見つかれば、システムはそのプログラムを実行を**許可**します。なぜなら、それを信頼できるものとして認識しているからです。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
