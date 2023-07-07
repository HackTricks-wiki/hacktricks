# macOSサンドボックス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

MacOSサンドボックス（最初はSeatbeltと呼ばれていました）は、**サンドボックスプロファイルで指定された許可されたアクションに制限**されるように、サンドボックス内で実行されるアプリケーションの動作を制御します。これにより、**アプリケーションが予期されたリソースにのみアクセスすることが保証**されます。

**`com.apple.security.app-sandbox`**という**エンタイトルメント**を持つアプリは、サンドボックス内で実行されます。**Appleのバイナリ**は通常、サンドボックス内で実行され、**App Store**に公開するためには、**このエンタイトルメントが必須**です。したがって、ほとんどのアプリケーションはサンドボックス内で実行されます。

プロセスが何を行えるか、行えないかを制御するために、サンドボックスにはカーネル全体の**すべてのシスコールにフック**があります。アプリの**エンタイトルメント**に応じて、サンドボックスは特定のアクションを**許可**します。

サンドボックスの重要なコンポーネントには次のものがあります：

* **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
* **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* ユーザーランドで実行される**デーモン** `/usr/libexec/sandboxd`
* **コンテナ** `~/Library/Containers`

コンテナフォルダ内には、**バンドルIDの名前で実行される各サンドボックス化されたアプリのフォルダ**があります：
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
各バンドルIDフォルダ内には、アプリの**plist**と**データディレクトリ**が含まれています。
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
シンボリックリンクがSandboxから「脱出」して他のフォルダにアクセスするために存在していても、アプリはそれらにアクセスするための**権限を持っている必要があります**。これらの権限は**`.plist`**内にあります。
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
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
[...]
```
### サンドボックスプロファイル

サンドボックスプロファイルは、そのサンドボックスで何が**許可/禁止**されるかを示す設定ファイルです。これは、**サンドボックスプロファイル言語（SBPL）**を使用しており、[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))プログラミング言語を使用しています。

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
[**こちらの研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **をチェックして、許可または拒否される可能性のあるさらなるアクションを確認してください。**
{% endhint %}

重要な**システムサービス**も、`mdnsresponder`サービスなど、独自の**サンドボックス**内で実行されます。これらのカスタム**サンドボックスプロファイル**は以下で確認できます：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 他のサンドボックスプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**のアプリは、**プロファイル** **`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルでは、**`com.apple.security.network.server`**などのエンタイトルメントがプロセスがネットワークを使用することを許可しているかどうかを確認できます。

SIPは、/System/Library/Sandbox/rootless.confにあるplatform\_profileという名前のサンドボックスプロファイルです。

### サンドボックスプロファイルの例

**特定のサンドボックスプロファイル**でアプリケーションを起動するには、次のコマンドを使用します：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
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

このファイルは、macOSのサンドボックスに関する情報を提供します。サンドボックスは、アプリケーションが制限された環境で実行されるようにするセキュリティ機能です。サンドボックスは、アプリケーションがシステムリソースにアクセスする際に制限を課すことで、悪意のある動作や特権のエスカレーションを防止します。

このファイルでは、サンドボックスの基本的な機能と制限について説明します。サンドボックスの設定方法やカスタマイズ方法についても解説します。

サンドボックスは、アプリケーションのセキュリティを強化するために重要な役割を果たします。正しく設定されたサンドボックスは、悪意のある攻撃からシステムを保護することができます。

このファイルは、macOSのサンドボックスに関する情報を提供します。サンドボックスは、アプリケーションが制限された環境で実行されるようにするセキュリティ機能です。サンドボックスは、アプリケーションがシステムリソースにアクセスする際に制限を課すことで、悪意のある動作や特権のエスカレーションを防止します。

このファイルでは、サンドボックスの基本的な機能と制限について説明します。サンドボックスの設定方法やカスタマイズ方法についても解説します。

サンドボックスは、アプリケーションのセキュリティを強化するために重要な役割を果たします。正しく設定されたサンドボックスは、悪意のある攻撃からシステムを保護することができます。
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
注意してください。**Windows**上で実行される**Apple製のソフトウェア**は、アプリケーションのサンドボックス化などの追加のセキュリティ対策はありません。
{% endhint %}

バイパスの例：

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（`~$`で始まる名前のサンドボックス外のファイルを書き込むことができます）。

### デバッグ＆サンドボックスのバイパス

**macOSでは、プロセスはサンドボックス化された状態で生まれません：iOSとは異なり、サンドボックスはプログラムの最初の命令が実行される前にカーネルによって適用されますが、macOSではプロセスは自らサンドボックスに入ることを選択する必要があります。**

プロセスは、`com.apple.security.app-sandbox`という権限を持っている場合、ユーザーランドから自動的にサンドボックス化されます。このプロセスの詳細な説明については、次を参照してください：

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PIDの特権をチェックする**

[これによると](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)、**`sandbox_check`**（`__mac_syscall`です）は、特定のPIDのサンドボックスによって操作が許可されているかどうかをチェックできます。

[**ツールsbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)は、PIDが特定のアクションを実行できるかどうかをチェックできます：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App StoreアプリでのカスタムSBPL

企業は、デフォルトのものではなく、**カスタムのサンドボックスプロファイル**を使用してアプリを実行することができます。これには、Appleによって承認される必要がある**`com.apple.security.temporary-exception.sbpl`**というエンタイトルメントを使用する必要があります。

このエンタイトルメントの定義は、**`/System/Library/Sandbox/Profiles/application.sb:`**で確認することができます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
これは、**この権限の後にある文字列をSandboxプロファイルとして評価**します。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか**？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたり**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
