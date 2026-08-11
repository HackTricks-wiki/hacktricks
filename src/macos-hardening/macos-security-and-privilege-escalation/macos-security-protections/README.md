# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指します。これは、**ダウンロードされた潜在的に悪意のあるソフトウェアをユーザーが実行するのを防ぐ**3つのmacOSセキュリティモジュールです。

詳細情報:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## プロセスの制限

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandboxは、Sandbox内で実行される**アプリケーションを、そのアプリが使用しているSandbox profileで指定された許可済みのアクションに制限**します。これにより、**アプリケーションが想定されたリソースにのみアクセスする**ことを保証できます。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**はセキュリティフレームワークです。これは、アプリケーションの**権限を管理**するために設計されており、特に機密性の高い機能へのアクセスを制御します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などが含まれます。TCCは、アプリが明示的なユーザーの同意を得た後にのみこれらの機能へアクセスできるようにすることで、プライバシーと個人データの管理を強化します。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOSのLaunch constraintsは、**プロセスを起動できる主体**、**方法**、**場所**を定義して、**プロセスの開始を制御**するセキュリティ機能です。macOS Venturaで導入され、**trust cache**内でシステムバイナリを制約カテゴリに分類します。すべての実行可能バイナリには、**self**、**parent**、**responsible**の制約を含む、**起動**に関する**ルール**が設定されています。macOS Sonomaではサードパーティ製アプリにも**Environment** Constraintsとして拡張され、プロセスの起動条件を管理することで、潜在的なシステム悪用の軽減に役立ちます。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT)は、macOSのセキュリティインフラストラクチャの一部です。その名前が示すとおり、MRTの主な機能は、**感染したシステムから既知のマルウェアを削除すること**です。

Macでマルウェアが検出されると（XProtectによる検出か、それ以外の方法による検出かを問わず）、MRTを使用して**マルウェアを自動的に削除**できます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されたとき、または新しいマルウェア定義がダウンロードされたときに実行されます（MRTがマルウェアを検出するためのルールはバイナリ内にあるようです）。

XProtectとMRTはいずれもmacOSのセキュリティ対策の一部ですが、それぞれ異なる機能を実行します。

- **XProtect**は予防ツールです。**ファイルがダウンロードされる際にチェック**し（特定のアプリケーション経由）、既知の種類のマルウェアを検出すると、**ファイルが開かれるのを防ぎます**。これにより、そもそもマルウェアがシステムに感染するのを防ぎます。
- 一方、**MRT**は**事後対応ツール**です。システム上でマルウェアが検出された後に動作し、問題のソフトウェアを削除してシステムをクリーンアップすることを目的とします。

MRTアプリケーションは**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## Background Tasks Management

**macOS**は現在、ツールがコード実行を永続化する、よく知られた**手法**（Login Items、Daemonsなど）を使用するたびに**警告**を表示するため、ユーザーは**どのソフトウェアが永続化しているのか**をより正確に把握できます。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**daemon**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**agent**によって実行されます。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**が、何かが永続化用フォルダにインストールされたことを認識する方法は、**FSEventsを取得**し、それらに対するいくつかの**handlers**を作成することです。<sup>[[1]](#references)</sup>

さらに、**よく知られたアプリケーション**が記載されたplistファイルがあり、Appleによって頻繁に永続化されるアプリケーションが管理されています。このファイルは次の場所にあります: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Apple cli tool を実行して、設定されている**すべての**バックグラウンド項目を列挙できます。<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、[**DumpBTM**](https://github.com/objective-see/DumpBTM) を使用してこの情報を一覧表示することも可能です。<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** に保存されており、Terminal には FDA が必要です。<sup>[[2]](#references)</sup>

### BTMへの干渉

新しい persistence が検出されると、タイプ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** のイベントが発生します。したがって、この **event** が送信されるのを**防ぐ**、または **agent がユーザーに alert するのを防ぐ**方法は、攻撃者による BTM の _**bypass**_ に役立ちます。<sup>[[1]](#references)</sup>

- **データベースのリセット**: 次のコマンドを実行するとデータベースがリセットされます（最初から再構築されるはずです）。ただし、これを実行した後は、システムを再起動するまで**新しい persistence の alert は表示されません**。<sup>[[1]](#references)</sup>
- **root** が必要です。
```bash
# Reset the database
sfltool resettbtm
```
- **エージェントを停止**: エージェントに停止シグナルを送信すると、新しい検知結果が見つかったときに**ユーザーへ通知しなくなる**ようにできます。<sup>[[1]](#references)</sup>
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
- **Bug**: **persistenceを作成したプロセスが直後に終了すると**、daemonはそのプロセスに関する**情報を取得**しようとしますが、**失敗し、新しいitemがpersistenceしていることを示すeventを送信できません**。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: 「macOSのBackground Task Managementを解明（およびBypass）する」 - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [新しい（Developer向け）Tool: 「DumpBTM」 - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Macでlogin itemsとbackground tasksを管理する - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
