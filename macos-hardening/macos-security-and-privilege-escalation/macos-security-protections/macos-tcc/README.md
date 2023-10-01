# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **基本情報**

**TCC（透明性、同意、および制御）**は、macOSの機構であり、通常はプライバシーの観点からアプリケーションの特定の機能へのアクセスを**制限および制御**します。これには、位置情報サービス、連絡先、写真、マイクロフォン、カメラ、アクセシビリティ、フルディスクアクセスなどが含まれます。

ユーザーの視点からは、TCCは、**TCCによって保護された機能へのアクセスをアプリケーションが要求するときに**表示されます。これが発生すると、**ユーザーにはアクセスを許可するかどうかを尋ねるダイアログが表示**されます。

また、ユーザーが**ファイルをプログラムにドラッグ＆ドロップする**など、**明示的な意図**によってアプリにアクセスを**許可する**ことも可能です（もちろん、プログラムはそれにアクセスできる必要があります）。

![TCCプロンプトの例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**は、`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`にある**デーモン**によって処理され、`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`で構成されています（`com.apple.tccd.system`というマッハサービスを登録）。

ログインしているユーザーごとに定義された**ユーザーモードのtccd**が`/System/Library/LaunchAgents/com.apple.tccd.plist`に実行され、マッハサービス`com.apple.tccd`と`com.apple.usernotifications.delegate.com.apple.tccd`を登録します。

ここでは、システムとユーザーとして実行されているtccdを見ることができます：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
アプリケーションの**親から継承された権限**と**Bundle ID**および**Developer ID**に基づいて、**権限**が**追跡**されます。

### TCCデータベース

選択は、TCCシステム全体のデータベースである**`/Library/Application Support/com.apple.TCC/TCC.db`**に保存されます。また、ユーザーごとの設定の場合は**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**に保存されます。これらのデータベースは**SIP（System Integrity Protection）によって編集が制限されていますが、読み取ることはできます**。

さらに、**フルディスクアクセス**を持つプロセスは、**ユーザーモードのデータベースを編集**することができます。

{% hint style="info" %}
**通知センターUI**は、**システムのTCCデータベースを変更**することができます：

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
{% tab title="システムDB" %}
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

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
両方のデータベースをチェックすることで、アプリが許可された権限、禁止された権限、または持っていない権限（要求される場合があります）を確認できます。
{% endhint %}

* **`auth_value`** には、denied（0）、unknown（1）、allowed（2）、またはlimited（3）の異なる値が入る可能性があります。
* **`auth_reason`** には、次の値が入る可能性があります：Error（1）、User Consent（2）、User Set（3）、System Set（4）、Service Policy（5）、MDM Policy（6）、Override Policy（7）、Missing usage string（8）、Prompt Timeout（9）、Preflight Unknown（10）、Entitled（11）、App Type Policy（12）
* テーブルの**他のフィールド**の詳細については、[**このブログ記事**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)を参照してください。

{% hint style="info" %}
一部のTCCの権限には、kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotosなどがあります。これらをすべて定義する公開リストは存在しませんが、この[**既知のリスト**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)を確認できます。

**Full Disk Access**の名前は**`kTCCServiceSystemPolicyAllFiles`**であり、**`kTCCServiceAppleEvents`**は他のアプリケーションにイベントを送信することを可能にし、一般的には**タスクの自動化**に使用されます。さらに、**`kTCCServiceSystemPolicySysAdminFiles`**は、ユーザのホームフォルダを変更する**`NFSHomeDirectory`**属性を変更することができ、それによりTCCを**バイパス**することができます。
{% endhint %}

また、`システム環境設定 --> セキュリティとプライバシー --> プライバシー --> ファイルとフォルダー`で、アプリに与えられた**既存の権限**も確認できます。

{% hint style="success" %}
注意してくださいが、ユーザはこれらのデータベースを直接変更することはできません（rootであっても）SIPのためです。新しいルールを設定または変更する唯一の方法は、システム環境設定パネルまたはアプリがユーザに要求するプロンプトです。

ただし、ユーザは**`tccutil`**を使用してルールを**削除またはクエリ**することができます。&#x20;
{% endhint %}

### TCC署名チェック

TCCデータベースはアプリケーションの**バンドルID**を保存していますが、アプリが許可を使用するために正しいものであることを確認するための**署名**に関する**情報**も保存しています。

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
これにより、Calendarがユーザーにリマインダー、カレンダー、アドレス帳へのアクセスを求めることを防ぎます。

### 機密情報が保護されていない場所

* $HOME (それ自体)
* $HOME/.ssh、$HOME/.awsなど
* /tmp

### ユーザーの意図 / com.apple.macl

前述のように、**ファイルをAppにドラッグ＆ドロップすることで、Appにファイルへのアクセスを許可する**ことができます。このアクセスはTCCデータベースには特定されませんが、ファイルの**拡張属性**として指定されます。この属性には、許可されたAppのUUIDが**保存されます**：
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

また、コンピュータ内のアプリのUUIDを許可するファイルを別のコンピュータに移動すると、同じアプリでも異なるUIDを持つため、そのアプリにアクセス権限は付与されません。
{% endhint %}

拡張属性`com.apple.macl`は、他の拡張属性とは異なり、**SIPによって保護**されているため、**クリアすることはできません**。ただし、[**この投稿で説明されているように**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)、ファイルを**圧縮**し、**削除**してから**解凍**することで無効化することが可能です。

### TCCバイパス

## 参考文献

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[NFTコレクション](https://opensea.io/collection/the-peass-family)
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
