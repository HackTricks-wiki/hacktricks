# macOS セキュリティ保護

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告掲載したい場合**や**HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)や [**telegram グループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>

## Gatekeeper

Gatekeeper は通常、**Quarantine + Gatekeeper + XProtect** の組み合わせを指し、これら 3 つの macOS セキュリティモジュールが**ダウンロードされた潜在的に悪意のあるソフトウェアの実行を防ぐ**ことを試みます。

詳細情報:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## プロセス制限

### SIP - システム整合性保護

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### サンドボックス

macOS サンドボックスは、アプリケーションが使用するサンドボックスプロファイルで指定された**許可されたアクションに制限**することで、**アプリケーションが予想されるリソースのみにアクセスする**ことを保証するのに役立ちます。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **透明性、同意、および制御**

**TCC (透明性、同意、および制御)** は macOS のメカニズムで、通常はプライバシーの観点から、特定の機能へのアプリケーションアクセスを**制限および制御する**ものです。これには、位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 起動/環境制約 & 信頼キャッシュ

macOS の起動制約は、**誰が**プロセスを起動できるか、**どのように**、**どこから**起動できるかを定義することで、プロセスの開始を**規制する**セキュリティ機能です。macOS Ventura で導入され、システムバイナリを**信頼キャッシュ**内の制約カテゴリに分類します。すべての実行可能バイナリには、**自身**、**親**、および**責任者**の制約を含む**起動ルール**が設定されています。macOS Sonoma でサードパーティアプリにも**環境**制約として拡張され、プロセスの起動条件を管理することで、潜在的なシステムの悪用を軽減するのに役立ちます。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - マルウェア削除ツール

マルウェア削除ツール (MRT) も macOS のセキュリティインフラの一部です。名前が示すように、MRT の主な機能は、**感染したシステムから既知のマルウェアを削除する**ことです。

Mac でマルウェアが検出されると（XProtect または他の手段によって）、MRT は自動的に**マルウェアを削除する**ために使用できます。MRT はバックグラウンドで静かに動作し、通常はシステムが更新されるたび、または新しいマルウェア定義がダウンロードされるたびに実行されます（マルウェアを検出するための MRT のルールはバイナリ内にあるようです）。

XProtect と MRT はどちらも macOS のセキュリティ対策の一部ですが、異なる機能を果たします：

* **XProtect** は予防ツールです。特定のアプリケーションを介して**ダウンロードされるファイルをチェックし**、既知のマルウェアタイプを検出すると、ファイルが開かれるのを**防ぎ**、そもそもシステムが感染するのを防ぎます。
* **MRT** は、反応的なツールです。システムでマルウェアが検出された後に動作し、不正なソフトウェアを削除してシステムをクリーンアップすることが目的です。

MRT アプリケーションは **`/Library/Apple/System/Library/CoreServices/MRT.app`** にあります。

## バックグラウンドタスク管理

**macOS** は、ツールがよく知られた**コード実行の永続化技術**（ログインアイテム、デーモンなど）を使用するたびに**警告**を発し、ユーザーが**どのソフトウェアが永続化しているか**をよりよく理解できるようにします。

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` にある**デーモン**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` にある**エージェント**で動作します。

**`backgroundtaskmanagementd`** が永続的なフォルダに何かがインストールされていることを知る方法は、**FSEvents を取得し**、それらのための**ハンドラー**を作成することです。

さらに、Apple が維持している頻繁に永続化する**よく知られたアプリケーション**を含む plist ファイルがあり、その場所は次のとおりです：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

AppleのCLIツールを実行して、設定されているすべてのバックグラウンド項目を**列挙する**ことが可能です：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、この情報は[**DumpBTM**](https://github.com/objective-see/DumpBTM)を使用してリストすることも可能です。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** に保存されており、ターミナルはFDAが必要です。

### BTMをいじる

新しい永続性が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** のタイプのイベントが発生します。したがって、この**イベント**の送信を**防ぐ**方法や、**エージェントがユーザーに警告するのを阻止する**方法は、攻撃者がBTMを_**バイパス**_するのに役立ちます。

* **データベースのリセット**: 以下のコマンドを実行するとデータベースがリセットされます（基本から再構築されるはずですが）、何らかの理由で、これを実行した後は、**システムが再起動されるまで新しい永続性に対する警告は出ません**。
* **root** 権限が必要です。
```bash
# Reset the database
sfltool resettbtm
```
* **エージェントを停止する**: エージェントに停止信号を送ることで、新しい検出が見つかったときに**ユーザーに警告しない**ようにすることが可能です。
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
* **バグ**: **永続性を作成したプロセスが直後にすぐに終了した場合**、デーモンはそのプロセスについての**情報を取得**しようとしますが、**失敗し**、新しいものが永続していることを示すイベントを**送信できなくなります**。

BTMについての**詳細情報**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
