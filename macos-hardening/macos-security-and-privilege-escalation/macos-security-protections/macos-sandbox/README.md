# macOS Sandbox

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>

## 基本情報

macOS Sandbox（初期にはSeatbeltと呼ばれていた）は、アプリが実行されているSandboxプロファイルで指定された**許可されたアクションに**実行中のアプリケーションを**制限します**。これにより、**アプリケーションが予想されるリソースのみにアクセスすることを保証するのに役立ちます**。

**`com.apple.security.app-sandbox`** の**権限**を持つアプリは、サンドボックス内で実行されます。**Appleのバイナリ**は通常、Sandbox内で実行され、**App Store**内で公開するためには、**この権限が必須です**。したがって、ほとんどのアプリケーションはサンドボックス内で実行されます。

プロセスができること、できないことを制御するために、**Sandboxにはカーネル全体のすべてのシステムコールにフックがあります**。アプリの**権限**に**依存して**、Sandboxは特定のアクションを**許可します**。

Sandboxの重要なコンポーネントには以下が含まれます:

* **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
* **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* ユーザーランドで実行される**デーモン** `/usr/libexec/sandboxd`
* **コンテナ** `~/Library/Containers`

コンテナフォルダ内には、バンドルIDの名前で**サンドボックスで実行された各アプリのフォルダが見つかります**：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
各バンドルIDフォルダ内には、アプリの**plist**と**Dataディレクトリ**が含まれています：
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
サンドボックスから「脱出」して他のフォルダにアクセスするためのシンボリックリンクがあっても、アプリはそれらにアクセスするための**権限を持っている必要があります**。これらの権限は**`.plist`**内にあります。
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandboxedアプリケーションによって作成/変更されたものは、**隔離属性**を取得します。これにより、Sandboxアプリが**`open`**を使用して何かを実行しようとした場合にGatekeeperをトリガーすることによって、sandbox空間が保護されます。
{% endhint %}

### サンドボックスプロファイル

サンドボックスプロファイルは、その**サンドボックス**で**許可/禁止**されることを示す設定ファイルです。**Sandbox Profile Language (SBPL)**を使用し、[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))プログラミング言語を使用します。

以下に例を示します：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
この[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)をチェックして、許可されるか拒否されるかもしれないアクションをもっと確認してください。
{% endhint %}

重要な**システムサービス**も独自のカスタム**サンドボックス**内で実行されます。例えば`mdnsresponder`サービスです。これらのカスタム**サンドボックスプロファイル**は以下で確認できます：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 他のサンドボックスプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**のアプリは**プロファイル** **`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルで、**`com.apple.security.network.server`**のような権限がプロセスにネットワークの使用を許可する方法を確認できます。

SIPは/System/Library/Sandbox/rootless.conf内のplatform_profileというサンドボックスプロファイルです。

### サンドボックスプロファイルの例

特定のサンドボックスプロファイルでアプリケーションを開始するには、次のコマンドを使用できます：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="タッチ" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
Since there is no English text provided that requires translation, I cannot proceed with a translation task. Please provide the relevant English text that you would like to be translated into Japanese.
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
Since the provided text does not contain any English content to translate, there is nothing to translate. The markdown syntax provided is for a code block with a title, which does not require translation as per the instructions. If you have any specific English text that needs to be translated into Japanese, please provide the text.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
```
{% endcode %}

{% code title="touch3.sb" %}
```
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Windows**で動作する**Apple製のソフトウェア**には、アプリケーションのサンドボックス化などの追加のセキュリティ対策が**ない**ことに注意してください。
{% endhint %}

バイパス例:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (サンドボックスの外に`~$`で始まる名前のファイルを書き込むことができます)。

### MacOS サンドボックス プロファイル

macOSはシステムのサンドボックスプロファイルを**/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles** の二箇所に保存しています。

そして、サードパーティのアプリケーションが _**com.apple.security.app-sandbox**_ 権限を持っている場合、システムはそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** プロファイルを適用します。

### **iOS サンドボックス プロファイル**

デフォルトのプロファイルは **container** と呼ばれ、SBPLテキスト表現はありません。メモリ内では、このサンドボックスはサンドボックスの各権限に対する許可/拒否のバイナリツリーとして表されます。

### サンドボックスのデバッグとバイパス

**macOSではプロセスはサンドボックス化されて生まれません：iOSとは異なり**、iOSではカーネルによってプログラムの最初の命令が実行される前にサンドボックスが適用されますが、macOSでは**プロセスは自らサンドボックスに入ることを選択する必要があります。**

プロセスは、権限 `com.apple.security.app-sandbox` を持っている場合、ユーザーランドから自動的にサンドボックス化されて起動します。このプロセスの詳細な説明については、以下をチェックしてください:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID 権限の確認**

[**これによると**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)、**`sandbox_check`** (これは `__mac_syscall` です)は、特定のPIDでサンドボックスによって操作が許可されているかどうかをチェックすることができます。

[**ツール sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)は、PIDが特定のアクションを実行できるかどうかをチェックすることができます:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App StoreアプリのカスタムSBPL

企業がデフォルトのものではなく、**カスタムサンドボックスプロファイル**でアプリを実行することが可能です。そのためには、Appleによって承認される必要がある権限 **`com.apple.security.temporary-exception.sbpl`** を使用する必要があります。

この権限の定義は **`/System/Library/Sandbox/Profiles/application.sb:`** で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
この権限の後の文字列を**Sandboxプロファイルとして評価します**。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
