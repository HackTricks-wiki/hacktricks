# macOS危険な権限とTCCの許可

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

## 高

### `com.apple.rootless.install.heritable`

権限**`com.apple.rootless.install.heritable`**は**SIPをバイパス**することができます。詳細については[こちらを参照](macos-sip.md#com.apple.rootless.install.heritable)してください。

### **`com.apple.rootless.install`**

権限**`com.apple.rootless.install`**は**SIPをバイパス**することができます。詳細については[こちらを参照](macos-sip.md#com.apple.rootless.install)してください。

### **`com.apple.system-task-ports`（以前は`task_for_pid-allow`と呼ばれていました）**

この権限を使用すると、カーネルを除く**任意の**プロセスの**タスクポート**を取得できます。詳細については[**こちらを参照**](../mac-os-architecture/macos-ipc-inter-process-communication/)してください。

### `com.apple.security.get-task-allow`

この権限を持つ他のプロセスは、この権限を持つバイナリで実行されるプロセスのタスクポートを取得し、それに**コードをインジェクト**することができます。詳細については[**こちらを参照**](../mac-os-architecture/macos-ipc-inter-process-communication/)してください。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`Get Task Allow`権限が`true`に設定された署名されていないサードパーティアプリに対して`task_for_pid()`を呼び出して有効なタスクポートを取得できます。ただし、デバッグツール権限を持っていても、デバッガは**`Get Task Allow`権限を持たないプロセスのタスクポート**を取得することはできません。したがって、これらのプロセスはシステム整合性保護によって保護されています。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)してください。

### `com.apple.security.cs.disable-library-validation`

この権限を使用すると、Appleによって署名されていないか、メインの実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを**ロード**することができます。したがって、攻撃者は任意のライブラリのロードを悪用してコードをインジェクトすることができます。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)してください。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限を使用すると、ライブラリやコードをインジェクトするために使用できる**DYLD環境変数**を使用することができます。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)してください。

### `com.apple.private.tcc.manager`および`com.apple.rootless.storage`.`TCC`

[**このブログによると**](https://objective-see.org/blog/blog\_0x4C.html)、これらの権限を使用すると、**TCC**データベースを**変更**することができます。

### com.apple.private.security.kext-management

カーネルに**カーネル拡張をロード**するように要求するための権限が必要です。

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するかわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)には、再起動後にSSVで保護されたコンテンツを更新するために使用できると記載されています。詳細がわかる場合は、PRを送信してください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)には、再起動後にSSVで保護されたコンテンツを更新するために使用できると記載されています。詳細がわかる場合は、PRを送信してください！

### **`kTCCServiceSystemPolicyAllFiles`**

**フルディスクアクセス**権限を付与します。TCCで最も高い権限の1つです。

### **`kTCCServiceAppleEvents`**

アプリが**タスクの自動化**に一般的に使用される他のアプリにイベントを送信できるようにします。他のアプリに付与された権限を悪用することができます。
### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーがホームフォルダを変更するために`NFSHomeDirectory`属性を変更することを許可し、それによってTCCをバイパスすることができます。

### **`kTCCServiceSystemPolicyAppBundles`**

デフォルトでは許可されていないアプリ内のフォルダ（app.app内）のアプリを変更することができます。

## Medium

### `com.apple.security.cs.allow-jit`

この権限を使用すると、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、書き込みと実行が可能なメモリを作成することができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限を使用すると、Cコードをオーバーライドまたはパッチすることができます。また、基本的に安全ではない**`NSCreateObjectFileImageFromMemory`**を使用したり、**DVDPlayback**フレームワークを使用したりすることができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めると、アプリはメモリの安全でないコード言語による一般的な脆弱性にさらされることになります。この例外が必要かどうかを慎重に考慮してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限を使用すると、自身の実行可能ファイルのセクションをディスク上で変更して強制的に終了することができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
Disable Executable Memory Protection Entitlementは、アプリの基本的なセキュリティ保護を削除する極端な権限であり、攻撃者が検出されずにアプリの実行可能コードを書き換えることが可能になります。可能な限り狭い権限を使用してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
