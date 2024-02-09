# macOS サンドボックス

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出する**

</details>

## 基本情報

MacOS サンドボックス（最初は Seatbelt と呼ばれていました）は、**アプリケーションがサンドボックス内で実行される際に許可されたアクション**をサンドボックスプロファイルで指定されたものに**制限**します。これにより、**アプリケーションが予期されるリソースにのみアクセス**することが保証されます。

**`com.apple.security.app-sandbox`** **権限**を持つアプリケーションは、サンドボックス内で実行されます。**Apple バイナリ**は通常、サンドボックス内で実行され、**App Store** に公開するためには、**この権限が必須**です。したがって、ほとんどのアプリケーションはサンドボックス内で実行されます。

プロセスが何を行うかを制御するために、**サンドボックスには** カーネル全体の **すべてのシスコール** に **フックがあります**。アプリケーションの **権限**に応じて、サンドボックスは特定のアクションを**許可**します。

サンドボックスの重要なコンポーネントには次のものがあります:

* **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
* **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* ユーザーランドで実行される **デーモン** `/usr/libexec/sandboxd`
* **コンテナ** `~/Library/Containers`

コンテナフォルダ内には、**バンドルIDの名前で実行される各アプリケーションのサンドボックス内でのフォルダ**があります。
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
各バンドルIDフォルダの中には、Appの**plist**と**Dataディレクトリ**が含まれています：
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
シンボリックリンクがあっても、サンドボックスから「脱出」して他のフォルダにアクセスするためには、アプリがそれらにアクセスする**権限を持っている**必要があります。これらの権限は**`.plist`**内にあります。
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
Sandboxアプリケーションによって作成/変更されたすべてのものには、**quarantine属性**が付与されます。これにより、Sandboxアプリケーションが**`open`**を使用して何かを実行しようとすると、GatekeeperがトリガーされてSandboxスペースが防がれます。
{% endhint %}

### Sandboxプロファイル

Sandboxプロファイルは、そのSandboxで何が**許可/禁止**されるかを示す構成ファイルです。これは**Sandbox Profile Language (SBPL)**を使用し、[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))プログラミング言語を使用しています。

ここに例を示します：
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
[**こちらの研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **をチェックして、許可または拒否できるさらなるアクションを確認してください。**
{% endhint %}

重要な**システムサービス**も独自の**sandbox**内で実行されます。例えば、`mdnsresponder`サービスがあります。これらの独自の**sandboxプロファイル**は以下で確認できます:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 他のsandboxプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**アプリは**プロファイル** **`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルで、**`com.apple.security.network.server`**などの権限がプロセスがネットワークを使用することを許可する方法を確認できます。

SIPは/System/Library/Sandbox/rootless.confにあるplatform\_profileというSandboxプロファイルです。

### Sandboxプロファイルの例

**特定のsandboxプロファイル**を使用してアプリケーションを起動するには、以下を使用できます:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
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
{% code title="touch2.sb" %}
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
{% endcode %}

{% code title="touch3.sb" %}
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
**Apple-authored** **software**が**Windows**上で実行される場合、アプリケーションのサンドボックス化などの追加のセキュリティ対策はありません。
{% endhint %}

バイパスの例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（サンドボックス外に`~$`で始まる名前のファイルを書き込むことができます）。

### MacOSサンドボックスプロファイル

macOSはシステムのサンドボックスプロファイルを**/usr/share/sandbox/**と**/System/Library/Sandbox/Profiles**の2か所に保存しています。

サードパーティのアプリケーションが _**com.apple.security.app-sandbox**_ 権限を持っている場合、システムはそのプロセスに**/System/Library/Sandbox/Profiles/application.sb**プロファイルを適用します。

### **iOSサンドボックスプロファイル**

デフォルトのプロファイルは**container**と呼ばれ、SBPLテキスト表現はありません。メモリ上では、このサンドボックスは、各権限ごとにAllow/Denyバイナリツリーとして表現されます。

### デバッグ＆サンドボックスバイパス

macOSでは、iOSとは異なり、プロセスはカーネルによって最初からサンドボックス化されるわけではありません。**プロセスは自らサンドボックスに参加する必要があります**。つまり、macOSでは、プロセスは、アクティブにサンドボックスに入るまでサンドボックスによって制限されません。

プロセスは、`com.apple.security.app-sandbox`権限を持っている場合、ユーザーランドから起動されるときに自動的にサンドボックス化されます。このプロセスの詳細な説明については、次を確認してください：

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID権限の確認**

[**これによると**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)、**`sandbox_check`**（`__mac_syscall`です）は、特定のPIDでサンドボックスによって操作が許可されているかどうかを確認できます。

[**ツールsbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)は、PIDが特定のアクションを実行できるかどうかを確認できます。
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App StoreアプリでのカスタムSBPL

企業がアプリを**デフォルトのものではなくカスタムのサンドボックスプロファイル**で実行することが可能です。Appleによって承認される必要がある権限**`com.apple.security.temporary-exception.sbpl`**を使用する必要があります。

この権限の定義は**`/System/Library/Sandbox/Profiles/application.sb:`**で確認することができます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
これは**この権限の後に文字列を評価**して、Sandboxプロファイルとして扱います。

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
