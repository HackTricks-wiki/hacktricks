# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper は通常、**Quarantine + Gatekeeper + XProtect** の組み合わせを指します。これは、**ダウンロードされた悪意のある可能性があるソフトウェアをユーザーが実行するのを防止**しようとする macOS の 3 つのセキュリティモジュールです。

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

MacOS Sandbox は、Sandbox 内で実行される**アプリケーションを、アプリが使用する Sandbox profile に指定された許可済みのアクションに制限**します。これにより、**アプリケーションが想定されたリソースにのみアクセスする**ことを保証できます。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** はセキュリティフレームワークです。これは、アプリケーションの**権限を管理**するために設計されており、具体的には機密性の高い機能へのアクセスを制御します。これには、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセス**などが含まれます。TCC は、アプリがこれらの機能にアクセスする前に明示的なユーザーの同意を得る必要があるようにすることで、プライバシーと個人データの管理を強化します。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS の launch constraints は、プロセスの**起動を制御**するためのセキュリティ機能であり、プロセスを**誰が**、**どのように**、**どこから起動できるか**を定義します。macOS Ventura で導入され、システムバイナリを **trust cache** 内の constraint category に分類します。すべての executable binary には、**self**、**parent**、**responsible** constraints を含む、**launch** に関する**ルール**が設定されています。macOS Sonoma ではサードパーティ製アプリにも **Environment Constraints** として拡張され、これらの機能はプロセスの起動条件を管理することで、システムの潜在的な exploit を軽減します。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) は、macOS のセキュリティインフラストラクチャのもう 1 つの要素です。その名前が示すとおり、MRT の主な機能は**感染したシステムから既知の malware を削除すること**です。

Mac 上で malware が検出されると（XProtect による検出でも、その他の手段による検出でも）、MRT を使用して**malware を自動的に削除**できます。MRT はバックグラウンドで静かに動作し、通常はシステムが更新されたとき、または新しい malware definition がダウンロードされたときに実行されます（MRT が malware を検出するためのルールは binary 内に存在するようです）。

XProtect と MRT はどちらも macOS のセキュリティ対策の一部ですが、それぞれ異なる機能を実行します。

- **XProtect** は予防的なツールです。**ファイルがダウンロードされる際に**（特定のアプリケーション経由で）**ファイルをチェック**し、既知の種類の malware を検出すると、**ファイルが開かれるのを防止**します。これにより、そもそも malware がシステムに感染するのを防ぎます。
- 一方、**MRT** は**事後対応型のツール**です。システム上で malware が検出された後に動作し、問題のソフトウェアを削除してシステムをクリーンアップすることを目的とします。

MRT アプリケーションは **`/Library/Apple/System/Library/CoreServices/MRT.app`** にあります。

## Background Tasks Management

**macOS** は現在、ツールが Login Items や Daemons などの、code execution を永続化するよく知られた**手法を使用するたびに警告**を表示します。これにより、ユーザーは**どのソフトウェアが永続化しているのか**をより正確に把握できます。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` にある **daemon** と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` にある **agent** によって動作します。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** が、永続化に使用されるフォルダーに何かがインストールされたことを把握する方法は、**FSEvents を取得**し、それらに対するいくつかの **handler** を作成することです。<sup>[[1]](#references)</sup>

さらに、頻繁に永続化を行う**よく知られたアプリケーション**を記載した plist file があり、Apple によって管理されています。このファイルは `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist` にあります。<sup>[[3]](#references)</sup>
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

Apple の cli tool を実行して、設定されている **すべての** background items を **enumerate** できます。<sup>[[3]](#references)</sup>
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

### BTM への干渉

新しい persistence が検出されると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** タイプの event が発生します。そのため、この **event** が送信されるのを**防止**する方法、または **agent がユーザーに alert するのを防止**する方法は、攻撃者による BTM の _**bypass**_ に役立ちます。<sup>[[1]](#references)</sup>

- **データベースのリセット**: 以下のコマンドを実行するとデータベースがリセットされます（ゼロから再構築されるはずです）。ただし、何らかの理由により、これを実行した後はシステムを reboot するまで、**新しい persistence が alert されなくなります**。<sup>[[1]](#references)</sup>
- **root** が必要です。
```bash
# Reset the database
sfltool resettbtm
```
- **Agentを停止**: Agentに停止シグナルを送信すると、新しい検出結果が見つかったときに**ユーザーへ警告しなくなります**。<sup>[[1]](#references)</sup>
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
- **Bug**: **persistenceを作成したプロセスが、その直後にすぐ終了した場合**、daemonはそのプロセスに関する**情報を取得**しようとしますが、**失敗**し、新しいものがpersistenceしていることを示す**eventを送信できません**。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "macOSのBackground Task Managementの謎を解明（およびバイパス）" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [新しい（Developer向け）Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Macでlogin itemsとbackground tasksを管理する - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
