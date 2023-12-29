# macOS 危険な権限とTCC権限

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

{% hint style="warning" %}
**`com.apple`**で始まる権限は第三者には利用できず、Appleのみが付与できることに注意してください。
{% endhint %}

## 高

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** 権限は**SIPをバイパス**することを許可します。[こちらを参照してください](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** 権限は**SIPをバイパス**することを許可します。[こちらを参照してください](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていた)**

この権限は、カーネルを除く任意のプロセスの**タスクポートを取得**することを許可します。[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

この権限は、**`com.apple.security.cs.debugger`** 権限を持つ他のプロセスが、この権限を持つバイナリによって実行されるプロセスのタスクポートを取得し、**コードを注入する**ことを許可します。[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`task_for_pid()`を呼び出して、`Get Task Allow`権限が`true`に設定されている未署名および第三者アプリの有効なタスクポートを取得できます。しかし、デバッグツール権限があっても、デバッガーは`Get Task Allow`権限を持たないプロセスのタスクポートを取得することは**できず**、そのためシステムインテグリティ保護によって保護されています。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限は、Appleによって署名されていない、またはメイン実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを**ロードすることを許可**します。そのため、攻撃者は任意のライブラリのロードを悪用してコードを注入する可能性があります。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

この権限は**`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、ライブラリ検証を**直接無効にする**のではなく、プロセスが`csops`システムコールを呼び出して無効にすることを**許可**します。\
[**こちらを参照してください**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、ライブラリやコードを注入するために使用できる**DYLD環境変数の使用を許可**します。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**このブログ**](https://objective-see.org/blog/blog\_0x4C.html) **と** [**このブログ**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの権限は**TCC**データベースを**変更することを許可**します。

### **`system.install.apple-software`** と **`system.install.apple-software.standar-user`**

これらの権限は、ユーザーに許可を求めずに**ソフトウェアをインストールすることを許可**します。これは**権限昇格**に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**カーネルにカーネル拡張をロードするように要求する**ために必要な権限です。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** 権限を持つと、**`com.apple.iCloudHelper`** XPCサービスと通信し、**iCloudトークンを提供する**ことが可能です。

**iMovie** と **Garageband** はこの権限を持っていました。

その権限からiCloudトークンを**取得するためのエクスプロイトについての詳細情報**は、トーク: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)をチェックしてください。

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するのかはわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)には、これを使用してリブート後にSSV保護されたコンテンツを更新することができると**言及されています**。方法を知っている場合はPRを送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)には、これを使用してリブート後にSSV保護されたコンテンツを更新することができると**言及されています**。方法を知っている場合はPRを送ってください！

### `keychain-access-groups`

この権限はアプリケーションがアクセスできる**キーチェーン**グループをリストします：
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

**フルディスクアクセス**権限を与えます。これはTCCで最も高い権限の一つです。

### **`kTCCServiceAppleEvents`**

アプリに他のアプリケーションへイベントを送信することを許可し、これは一般的に**タスクの自動化**に使用されます。他のアプリを制御することで、それらのアプリに付与された権限を悪用することができます。

例えば、ユーザーにパスワードを求めるようにさせることです：

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

または、**任意のアクション**を実行させること。

### **`kTCCServiceEndpointSecurityClient`**

他の権限の中でも、**ユーザーのTCCデータベースを書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

**`NFSHomeDirectory`** 属性を変更して、ユーザーのホームフォルダのパスを変更し、それによって**TCCをバイパス**することを許可します。

### **`kTCCServiceSystemPolicyAppBundles`**

デフォルトでは禁止されているアプリバンドル内（app.app内）のファイルを変更することを許可します。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持っている人を _システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_ で確認することができます。

### `kTCCServiceAccessibility`

このプロセスは、macOSのアクセシビリティ機能を**悪用**することができます。つまり、例えばキーストロークを押すことができます。したがって、Finderのようなアプリの制御を要求し、この権限でダイアログを承認することができます。

## 中程度

### `com.apple.security.cs.allow-jit`

この権限は、`mmap()` システム関数に `MAP_JIT` フラグを渡すことで、**書き込み可能で実行可能なメモリを作成**することを許可します。[**こちらで詳細を確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限は、**Cコードをオーバーライドまたはパッチ**すること、長い間非推奨とされている**`NSCreateObjectFileImageFromMemory`**（根本的に安全でない）を使用すること、または**DVDPlayback**フレームワークを使用することを許可します。[**こちらで詳細を確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めることは、メモリ安全でないコード言語の一般的な脆弱性にアプリをさらすことになります。アプリがこの例外を必要とするかどうか慎重に検討してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限は、ディスク上の自身の実行可能ファイルのセクションを強制的に変更することを許可します。[**こちらで詳細を確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
実行可能メモリ保護を無効にする権限は、アプリから基本的なセキュリティ保護を取り除く極端な権限であり、攻撃者が検出されることなくアプリの実行コードを書き換える可能性を生じさせます。可能であれば、より狭い範囲の権限を優先してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限は、nullfsファイルシステムをマウントすることを許可します（デフォルトでは禁止されています）。ツール: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master)。

### `kTCCServiceAll`

このブログポストによると、通常このTCC権限は以下の形で見つかります：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべてのTCC権限を要求する**ことを許可します。

### **`kTCCServicePostEvent`**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社の広告を掲載**したいですか？ または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に従ってください。**
* **ハッキングのコツを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) と [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
