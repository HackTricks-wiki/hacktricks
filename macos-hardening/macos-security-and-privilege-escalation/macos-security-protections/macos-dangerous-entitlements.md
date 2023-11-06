# macOS 危険な権限とTCCの許可

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

{% hint style="warning" %}
**`com.apple`**で始まる権限は、サードパーティには利用できません。Appleのみがそれらを付与できます。
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

権限**`com.apple.rootless.install.heritable`**は**SIPをバイパス**することができます。詳細については[こちらを参照してください](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

権限**`com.apple.rootless.install`**は**SIPをバイパス**することができます。詳細については[こちらを参照してください](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow`)**

この権限は、カーネルを除く**任意の**プロセスの**タスクポートを取得**することができます。詳細については[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

この権限は、**`com.apple.security.cs.debugger`**権限を持つ他のプロセスが、この権限を持つバイナリで実行されるプロセスのタスクポートを取得し、それにコードを注入することができます。詳細については[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`Get Task Allow`権限が`true`に設定された署名されていないサードパーティアプリに対して、`task_for_pid()`を呼び出して有効なタスクポートを取得することができます。ただし、デバッグツール権限を持っていても、デバッガは**`Get Task Allow`権限を持たないプロセスのタスクポート**を取得することはできません。したがって、これらのプロセスはシステム整合性保護によって保護されています。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限は、Appleによって署名されていないか、メインの実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを**ロードすることができます**。したがって、攻撃者は任意のライブラリのロードを悪用してコードを注入することができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

この権限は、**`com.apple.security.cs.disable-library-validation`**と非常に似ていますが、**ライブラリの検証を直接無効にする**代わりに、プロセスがそれを無効にするために`csops`システムコールを呼び出すことができるようにします。詳細については[**こちらを参照してください**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、ライブラリやコードを注入するために使用される可能性のある**DYLD環境変数**の使用を許可します。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` と `com.apple.rootless.storage`.`TCC`

[**このブログによると**](https://objective-see.org/blog/blog\_0x4C.html)、これらの権限は**TCC**データベースを**変更**することを許可します。

### **`system.install.apple-software`** と **`system.install.apple-software.standar-user`**

これらの権限は、ユーザーの許可を求めることなくソフトウェアを**インストール**することができます。これは特権エスカレーションに役立ちます。

### `com.apple.private.security.kext-management`

カーネルにカーネル拡張をロードするために必要な権限です。

### **`com.apple.private.icloud-account-access`**

権限**`com.apple.private.icloud-account-access`**を使用すると、**`com.apple.iCloudHelper`** XPCサービスと通信し、iCloudトークンを提供することができます。

**iMovie**と**Garageband**にはこの権限があります。

この権限から**icloudトークンを取得する**エクスプロイトについての詳細は、次のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)
### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するのかわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **によると、これは**再起動後にSSVで保護されたコンテンツを更新するために使用できると言われています。方法を知っている場合は、PRを送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **によると、これは**再起動後にSSVで保護されたコンテンツを更新するために使用できると言われています。方法を知っている場合は、PRを送ってください！

### `keychain-access-groups`

このエンタイトルメントは、アプリケーションがアクセスできる**キーチェーン**グループのリストです：
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

フルディスクアクセス権限を与えます。TCCで最も高い権限の1つです。

### **`kTCCServiceAppleEvents`**

アプリが他のアプリケーションにイベントを送信することを許可します。これは一般的に**タスクの自動化**に使用される他のアプリケーションに対して権限を悪用することができます。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの**ホームフォルダを変更**するための`NFSHomeDirectory`属性を変更することができ、それによりTCCを**バイパス**することができます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリのバンドル内（app.app内）のファイルを変更することができますが、これはデフォルトでは**許可されていません**。

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

## Medium

### `com.apple.security.cs.allow-jit`

このエンタイトルメントは、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、**書き込みと実行が可能なメモリ**を作成することを許可します。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

このエンタイトルメントは、Cコードを**オーバーライドまたはパッチ**すること、長期間非推奨とされている**`NSCreateObjectFileImageFromMemory`**（基本的には安全ではない）を使用すること、または**DVDPlayback**フレームワークを使用することを許可します。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
このエンタイトルメントを含めると、アプリはメモリの安全でないコード言語における一般的な脆弱性にさらされる可能性があります。この例外が必要かどうかを慎重に考慮してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

このエンタイトルメントは、ディスク上の自身の実行可能ファイルのセクションを**強制的に変更**して終了することを許可します。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
Disable Executable Memory Protectionエンタイトルメントは、アプリから基本的なセキュリティ保護を削除し、攻撃者が検出されずにアプリの実行可能コードを書き換えることが可能になる極端なエンタイトルメントです。可能な場合は、より狭いエンタイトルメントを選択してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `kTCCServiceAll`

このブログ記事によると、このTCC権限は通常、以下の形式で見つかります：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスにすべてのTCC権限を要求することを許可します。
