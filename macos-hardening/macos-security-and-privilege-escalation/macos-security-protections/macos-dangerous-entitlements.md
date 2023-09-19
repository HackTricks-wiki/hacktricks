# macOS 危険な権限

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

{% hint style="warning" %}
注意：**`com.apple`**で始まる権限は、サードパーティには利用できません。Appleのみがそれらを付与できます。
{% endhint %}

## High

### `com.apple.security.get-task-allow`

この権限により、この権限を持つバイナリで実行されるプロセスのタスクポートを取得し、それに**コードをインジェクト**することができます。詳細については、[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### **`com.apple.system-task-ports`（以前は`task_for_pid-allow`と呼ばれていました）**

この権限により、カーネルを除く**任意の**プロセスのタスクポートを取得することができます。詳細については、[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`Get Task Allow`権限が`true`に設定された未署名のサードパーティアプリに対して、`task_for_pid()`を呼び出して有効なタスクポートを取得することができます。ただし、デバッグツール権限を持っていても、`Get Task Allow`権限を持たないプロセスのタスクポートをデバッガは取得できず、そのためシステム整合性保護によって保護されています。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限により、Appleによって署名されていないか、メインの実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを**ロードすることができます**。したがって、攻撃者は任意のライブラリのロードを悪用してコードをインジェクトすることができます。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限により、ライブラリやコードをインジェクトするために使用される可能性のある**DYLD環境変数**を使用することができます。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

## Medium

### `com.apple.security.cs.allow-jit`

この権限により、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、**書き込みと実行が可能なメモリ**を作成することができます。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限により、Cコードを**オーバーライドまたはパッチ**することができます。また、基本的に安全ではない**`NSCreateObjectFileImageFromMemory`**を使用することもできます。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めると、アプリはメモリの安全でないコード言語による一般的な脆弱性にさらされることになります。この例外が必要かどうかを慎重に考慮してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限により、**自身の実行可能ファイルのセクションをディスク上で変更**して強制的に終了することができます。詳細については、[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
Disable Executable Memory Protection権限は、アプリの基本的なセキュリティ保護を削除する極端な権限であり、アプリの実行可能コードを検出せずに攻撃者が書き換えることが可能になります。可能な限り狭い権限を選択してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO
* [💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、Twitterで[🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)@carlospolopmをフォローしてください。
* ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
