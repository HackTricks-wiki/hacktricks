# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指します。これは、**ダウンロードされた潜在的に悪意のあるソフトウェアをユーザーが実行するのを防止**しようとする3つのmacOSセキュリティモジュールです。

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

MacOS Sandboxは、Sandbox内で実行される**アプリケーションの動作を制限**し、そのアプリが使用している**Sandboxプロファイルで許可されたアクション**のみを実行できるようにします。これにより、**アプリケーションが想定されたリソースにのみアクセスする**ことが保証されます。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**はセキュリティフレームワークです。これは、アプリケーションの**権限を管理**するために設計されており、特に機密性の高い機能へのアクセスを制御します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などが含まれます。TCCは、アプリが明示的なユーザーの同意を得た後にのみこれらの機能へアクセスできるようにし、個人データのプライバシーと制御を強化します。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOSのLaunch constraintsは、**誰が**、**どのように**、**どこから**プロセスを起動できるかを定義することで、**プロセスの起動を制御**するセキュリティ機能です。macOS Venturaで導入され、システムバイナリを**trust cache**内の制約カテゴリに分類します。すべての実行可能バイナリには、**self**、**parent**、**responsible**の制約を含む、**起動**に関する一連の**ルール**が設定されています。macOS Sonomaではサードパーティアプリにも**Environment Constraints**として拡張され、プロセスの起動条件を管理することで、システムの潜在的な悪用を軽減します。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT)は、macOSのセキュリティインフラストラクチャの一部です。その名前が示すとおり、MRTの主な機能は**感染したシステムから既知のmalwareを削除すること**です。

Mac上でmalwareが検出されると（XProtectまたはその他の手段によって）、MRTを使用して**malwareを自動的に削除**できます。MRTはバックグラウンドで静かに動作し、通常はシステムが更新されたとき、または新しいmalware定義がダウンロードされたときに実行されます（MRTがmalwareを検出するためのルールはバイナリ内に存在するようです）。

XProtectとMRTはどちらもmacOSのセキュリティ対策の一部ですが、異なる機能を実行します。

- **XProtect**は予防的なツールです。**ファイルがダウンロードされる際にチェック**し（特定のアプリケーション経由）、既知のmalwareの種類を検出すると、**ファイルが開かれるのを防止**します。これにより、malwareが最初からシステムに感染するのを防ぎます。
- 一方、**MRT**は**事後対応型のツール**です。システム上でmalwareが検出された後に動作し、問題のソフトウェアを削除してシステムをクリーンアップすることを目的とします。

MRTアプリケーションは**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## Background Tasks Management

**macOS**は、ツールがコード実行を永続化するよく知られた**手法（Login Items、Daemonsなど）を使用するたびに**警告**を表示するようになりました。これにより、ユーザーは**どのソフトウェアが永続化しているのか**をより適切に把握できます。<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**daemon**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**agent**によって実行されます。<sup>[1]</sup>

**`backgroundtaskmanagementd`**が、何かが永続化用のフォルダーにインストールされたことを把握する方法は、**FSEventsを取得**し、それらに対する**handler**を作成することです。<sup>[1]</sup>

さらに、Appleが管理する、頻繁に永続化を行う**よく知られたアプリケーション**を含むplistファイルがあり、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`に保存されています。<sup>[3]</sup>
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

Apple cli toolを実行することで、設定されている**すべての**バックグラウンド項目を列挙できます。<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、[**DumpBTM**](https://github.com/objective-see/DumpBTM) を使用してこの情報を一覧表示することもできます。<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** に保存され、Terminal には FDA が必要です。<sup>[2]</sup>

### BTM を操作する

新しい persistence が見つかると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** タイプの event が発生します。そのため、この **event** が送信されるのを**防止**したり、**agent がユーザーに alert を表示するのを阻止**したりする方法は、攻撃者が BTM を _**bypass**_ するのに役立ちます。<sup>[1]</sup>

- **データベースをリセットする**: 以下の command を実行すると、データベースがリセットされます（ゼロから再構築されるはずです）。しかし、何らかの理由により、これを実行した後は、system を reboot するまで **新しい persistence に対する alert が表示されません**。<sup>[1]</sup>
- **root** が必要です。
```bash
# Reset the database
sfltool resettbtm
```
- **エージェントを停止**: Agent に停止シグナルを送信すると、新たな検知が見つかった際に **ユーザーへ警告しなくなる**。<sup>[1]</sup>
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
- **Bug**: **persistenceを作成したprocessが、その直後にすぐexitすると**、daemonはそのprocessに関する**informationを取得しようとする**ものの**失敗し**、新しいものがpersistenceしていることを示す**eventを送信できなくなる**。<sup>[1]</sup>

## References

- [1] [OBTS v6.0: 「macOSのBackground Task Managementを解明（およびBypass）する」 - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: 「DumpBTM」 - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Macでlogin itemsとbackground tasksを管理する - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
