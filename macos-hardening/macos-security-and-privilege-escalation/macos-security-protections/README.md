# macOSセキュリティ保護

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
- ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指すために使用され、これらはmacOSの3つのセキュリティモジュールであり、**ユーザーが潜在的に悪意のあるソフトウェアを実行するのを防ごうとします**。

詳細は次のとおりです：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## プロセス制限

### SIP - システム整合性保護

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### サンドボックス

MacOSサンドボックスは、サンドボックス内で実行されるアプリケーションを**サンドボックスプロファイルで指定された許可されたアクションに制限**します。これにより、**アプリケーションが予期されるリソースにのみアクセスすることが保証**されます。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明性、同意、および制御

**TCC（透明性、同意、お制御）**はセキュリティフレームワークです。これは、アプリケーションの**権限を管理**するために設計されており、特に、アプリケーションが**機密機能へのアクセスを規制**します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、およびフルディスクアクセス**などの要素が含まれます。TCCは、アプリがこれらの機能にアクセスできるのは、明示的なユーザーの同意を得た後であることを確認し、プライバシーと個人データの制御を強化します。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 起動/環境制約と信頼キャッシュ

macOSの起動制約は、プロセスの開始を**規制**するセキュリティ機能であり、プロセスの**誰が**、**どのように**、**どこから**起動できるかを定義します。macOS Venturaで導入された信頼キャッシュ内の制約カテゴリにシステムバイナリを分類します。各実行可能バイナリには、**自己**、**親**、および**責任者**の制約を含む、その**起動**のための**ルール**が設定されています。macOS Sonomaでは、サードパーティアプリケーションに拡張された**環境**制約として、これらの機能はプロセスの起動条件を規制することで、潜在的なシステムの悪用を緩和します。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - マルウェア除去ツール

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラの一部です。その名前が示すように、MRTの主な機能は、感染したシステムから既知のマルウェアを**除去すること**です。

Macでマルウェアが検出されると（XProtectによるものまたは他の手段によるもの）、MRTを使用してマルウェアを自動的に**除去**できます。MRTはバックグラウンドで静かに動作し、通常、システムが更新されるときや新しいマルウェア定義がダウンロードされるときに実行されます（マルウェアを検出するMRTのルールはバイナリ内にあるようです）。

XProtectとMRTは、macOSのセキュリティ対策の一部ですが、異なる機能を果たします：

- **XProtect**は予防ツールです。**ファイルをダウンロードする際に**（特定のアプリケーションを介して）、ファイルに既知のマルウェアが検出されると、**ファイルの開封を防止**して、最初にシステムにマルウェアが感染するのを防ぎます。
- 一方、**MRT**は**反応的なツール**です。システムでマルウェアが検出された後に動作し、問題のあるソフトウェアを除去してシステムをクリーンアップすることを目指します。

MRTアプリケーションは、**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## バックグラウンドタスクの管理

**macOS**は今や、ツールがコード実行を維持するためのよく知られた**手法を使用するたびにアラートを表示**するため、ユーザーは**どのソフトウェアが維持されているかをよりよく把握**できます。

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**デーモン**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**エージェント**で実行されます。

**`backgroundtaskmanagementd`**が永続フォルダに何かがインストールされていることを知る方法は、**FSEventsを取得**してそれらのためのいくつかの**ハンドラ**を作成することです。

さらに、Appleが管理している**よく知られたアプリケーション**を含むplistファイルがあり、次の場所にあります：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

AppleのCLIツールを使用して、設定されたすべてのバックグラウンドアイテムを列挙することが可能です：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、この情報を[**DumpBTM**](https://github.com/objective-see/DumpBTM)でリストアップすることも可能です。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は**`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**に保存されており、TerminalにFDAが必要です。

### BTMをいじる

新しい永続性が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**タイプのイベントが発生します。したがって、この**イベント**が送信されるのを**防止**する方法や**エージェントがユーザーに警告するのを防ぐ**方法は、攻撃者がBTMを_**バイパス**_するのに役立ちます。

* **データベースをリセットする**：次のコマンドを実行すると、データベースがリセットされます（基盤から再構築する必要があります）。ただし、何らかの理由で、これを実行した後、**システムが再起動されるまで新しい永続性が警告されなくなります**。
* **root**が必要です。
```bash
# Reset the database
sfltool resettbtm
```
* **エージェントの停止**: エージェントに停止シグナルを送信して、新しい検出が見つかった際にユーザーにアラートを表示させないようにすることが可能です。
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
* **バグ**: もし**永続性を作成したプロセスがすぐに存在しなくなる**と、デーモンはそれに関する**情報を取得**しようとして**失敗**し、新しいものが永続化されていることを示すイベントを送信できなくなります。

BTMに関する**参考文献や詳細**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
