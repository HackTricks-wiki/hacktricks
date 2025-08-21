# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指し、これはユーザーが**潜在的に悪意のあるソフトウェアを実行するのを防ぐ**ために試みる3つのmacOSセキュリティモジュールです。

詳細情報は以下にあります:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processes Limitants

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandboxは、サンドボックス内で実行されるアプリケーションを、アプリが実行されている**Sandboxプロファイルで指定された許可されたアクション**に制限します。これにより、**アプリケーションが期待されるリソースのみをアクセスすることが保証されます**。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**はセキュリティフレームワークです。これは、アプリケーションの**権限を管理する**ために設計されており、特に機密機能へのアクセスを規制します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などの要素が含まれます。TCCは、アプリが明示的なユーザーの同意を得た後にのみこれらの機能にアクセスできるようにし、プライバシーと個人データに対する制御を強化します。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOSの起動制約は、**プロセスの開始を規制する**ためのセキュリティ機能であり、**誰がプロセスを起動できるか、どのように、どこから**起動するかを定義します。macOS Venturaで導入され、システムバイナリを**信頼キャッシュ**内の制約カテゴリに分類します。すべての実行可能バイナリには、**自己、親、責任**の制約を含む**起動**のための**ルール**が設定されています。macOS Sonomaでは、これらの機能が**環境**制約としてサードパーティアプリに拡張され、プロセスの起動条件を管理することで潜在的なシステムの悪用を軽減します。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

マルウェア除去ツール（MRT）は、macOSのセキュリティインフラストラクチャの一部です。名前が示すように、MRTの主な機能は**感染したシステムから既知のマルウェアを除去する**ことです。

マルウェアがMac上で検出されると（XProtectまたは他の手段によって）、MRTを使用して自動的に**マルウェアを除去**できます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されるときや新しいマルウェア定義がダウンロードされるときに実行されます（MRTがマルウェアを検出するためのルールはバイナリ内にあるようです）。

XProtectとMRTはどちらもmacOSのセキュリティ対策の一部ですが、異なる機能を果たします：

- **XProtect**は予防的なツールです。これは、**ファイルがダウンロードされる際にチェック**し、既知のマルウェアのタイプが検出されると、**ファイルのオープンを防ぎ**、マルウェアがシステムに感染するのを防ぎます。
- **MRT**は、逆に、**反応的なツール**です。これは、システム上でマルウェアが検出された後に動作し、問題のあるソフトウェアを除去してシステムをクリーンにすることを目的としています。

MRTアプリケーションは**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## Background Tasks Management

**macOS**は、ツールが**コード実行を持続させるためのよく知られた技術**（ログイン項目、デーモンなど）を使用するたびに**警告**を出すようになり、ユーザーは**どのソフトウェアが持続しているか**をよりよく知ることができます。

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**デーモン**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**エージェント**によって実行されます。

**`backgroundtaskmanagementd`**が何かが持続的なフォルダにインストールされていることを知る方法は、**FSEventsを取得し**、それらのための**ハンドラー**を作成することです。

さらに、Appleが管理する**よく知られたアプリケーション**を含むplistファイルがあり、場所は`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`です。
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
### Enumeration

AppleのCLIツールを使用して、構成されたすべてのバックグラウンドアイテムを**列挙**することが可能です:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、この情報を[**DumpBTM**](https://github.com/objective-see/DumpBTM)を使用してリストすることも可能です。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** に保存されており、Terminal は FDA を必要とします。

### BTM の操作

新しい永続性が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** タイプのイベントが発生します。したがって、この **イベント** が送信されるのを **防ぐ** 方法や、**エージェントがユーザーに警告するのを防ぐ** 方法は、攻撃者が BTM を _**バイパス**_ するのに役立ちます。

- **データベースのリセット**: 次のコマンドを実行すると、データベースがリセットされます（ゼロから再構築されるべきです）。ただし、何らかの理由で、これを実行した後は **システムが再起動されるまで新しい永続性は警告されません**。
- **root** が必要です。
```bash
# Reset the database
sfltool resettbtm
```
- **エージェントを停止する**: エージェントに停止信号を送信することで、**新しい検出が見つかったときにユーザーに警告しない**ようにすることができます。
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
- **バグ**: **永続性を作成したプロセスがそれのすぐ後に存在する場合**、デーモンはそれについて**情報を取得しようとし**、**失敗し**、**新しいものが永続していることを示すイベントを送信できなくなります**。

BTMに関する参考文献と**詳細情報**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
