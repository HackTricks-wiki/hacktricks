# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeperは通常、**Quarantine + Gatekeeper + XProtect**の組み合わせを指します。これは、**downloadedされた潜在的に悪意のあるソフトウェアをユーザーが実行するのを防止**しようとする3つのmacOS security moduleです。

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

MacOS Sandboxは、Sandbox内で実行される**アプリケーションを、そのアプリが使用しているSandbox profileで指定された許可済みのアクションに制限**します。これにより、**アプリケーションが想定されたリソースのみにアクセスする**ことを保証できます。


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)**はsecurity frameworkです。これは、アプリケーションの**permissionを管理**するために設計されており、特に機密性の高い機能へのアクセスを規制します。これには、**location services、contacts、photos、microphone、camera、accessibility、full disk access**などが含まれます。TCCは、アプリがこれらの機能にアクセスする前に明示的なユーザーの同意を取得する必要があることを保証し、個人データのprivacyとcontrolを強化します。


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOSのlaunch constraintsは、**プロセスを起動できる主体**、**その方法**、**起動元**を定義することで、**プロセスの起動を規制**するsecurity featureです。macOS Venturaで導入され、system binaryを**trust cache**内のconstraint categoryに分類します。すべてのexecutable binaryには、**self**、**parent**、**responsible** constraintsを含む、**launch**に関する一連の**rules**が設定されています。macOS Sonomaではthird-party appにも**Environment Constraints**として拡張され、これらのfeatureはプロセスの起動条件を管理することで、system exploitationの可能性を軽減します。


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT)は、macOSのsecurity infrastructureのもう1つの構成要素です。その名前が示すとおり、MRTの主な機能は**感染したsystemから既知のmalwareを削除すること**です。

Macでmalwareが検出されると（XProtectによるものでも、その他の方法によるものでも）、MRTを使用して**malwareを自動的に削除**できます。MRTはバックグラウンドで静かに動作し、通常はsystemがupdateされたとき、または新しいmalware definitionがdownloadされたときに実行されます（MRTがmalwareを検出するためのrulesはbinary内に存在するようです）。

XProtectとMRTはいずれもmacOSのsecurity measureの一部ですが、それぞれ異なる機能を実行します。

- **XProtect**はpreventative toolです。特定のapplication経由で**downloadされたファイルをチェック**し、既知の種類のmalwareを検出すると、**ファイルが開かれるのを防止**します。これにより、malwareが最初からsystemに感染するのを防ぎます。
- 一方、**MRT**は**reactive tool**です。system上でmalwareが検出された後に動作し、問題のsoftwareを削除してsystemをclean upすることを目的とします。

MRT applicationは**`/Library/Apple/System/Library/CoreServices/MRT.app`**にあります。

## Background Tasks Management

**macOS**は現在、toolがcode executionをpersistさせるよく知られた**technique**（Login Items、Daemonsなど）を使用するたびに**alert**を表示するため、ユーザーは**どのsoftwareがpersistしているか**をより正確に把握できます。<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

これは、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`にある**daemon**と、`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`にある**agent**によって実行されます。<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`**がpersistent folderに何かがinstallされたことを認識する方法は、**FSEventsを取得**し、それらに対するいくつかの**handler**を作成することです。<sup>[[1]](#references)</sup>

さらに、Appleがmaintainしている、頻繁にpersistする**well known application**を含むplist fileがあり、次の場所にあります: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Apple cli tool を実行すると、設定されている**すべての**バックグラウンド項目を**列挙**できます。<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
さらに、この情報は [**DumpBTM**](https://github.com/objective-see/DumpBTM) を使用して一覧表示することも可能です。<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
この情報は **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** に保存されており、Terminal には FDA が必要です。<sup>[[2]](#references)</sup>

### BTM への干渉

新しい persistence が検出されると、**`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** タイプの event が発生します。そのため、この **event** が送信されるのを**防止**する、または **agent がユーザーに alert を表示するのを防ぐ**方法があれば、攻撃者による _**BTM の bypass**_ に役立ちます。<sup>[[1]](#references)</sup>

- **データベースの reset**: 以下の command を実行するとデータベースが reset されます（最初から再構築されるはずです）。ただし、何らかの理由により、これを実行した後は、system を reboot するまで**新しい persistence が alert されなくなります**。<sup>[[1]](#references)</sup>
- **root** が必要です。
```bash
# Reset the database
sfltool resettbtm
```
- **Agentを停止**: Agentに停止シグナルを送信することで、新たな検知が見つかった際に**ユーザーへ警告しない**ようにできます。<sup>[[1]](#references)</sup>
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
- **Bug**: **persistence を作成したプロセスが、その直後にすぐ終了すると**、daemon はそのプロセスに関する **情報を取得しようとします**が、**失敗し**、新しいものが persistence されたことを示す **event を送信できなくなります**。<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
