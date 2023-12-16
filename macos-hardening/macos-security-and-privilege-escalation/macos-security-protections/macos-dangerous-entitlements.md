# macOS 危険な権限とTCCの許可

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

{% hint style="warning" %}
**`com.apple`** で始まる権限は、サードパーティには利用できません。Appleのみがそれらを付与できます。
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

権限 **`com.apple.rootless.install.heritable`** は **SIPをバイパス**することができます。詳細については[こちらを参照](macos-sip.md#com.apple.rootless.install.heritable)してください。

### **`com.apple.rootless.install`**

権限 **`com.apple.rootless.install`** は **SIPをバイパス**することができます。詳細については[こちらを参照](macos-sip.md#com.apple.rootless.install)してください。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow`)**

この権限は、カーネルを除く**任意の**プロセスの**タスクポートを取得**することができます。詳細については[**こちらを参照**](../mac-os-architecture/macos-ipc-inter-process-communication/)してください。

### `com.apple.security.get-task-allow`

この権限により、**`com.apple.security.cs.debugger`** 権限を持つ他のプロセスが、この権限を持つバイナリで実行されるプロセスのタスクポートを取得し、それにコードを注入することができます。詳細については[**こちらを参照**](../mac-os-architecture/macos-ipc-inter-process-communication/)してください。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`Get Task Allow` 権限が `true` に設定された署名されていないサードパーティアプリに対して `task_for_pid()` を呼び出すことで有効なタスクポートを取得できます。ただし、デバッグツール権限を持っていても、デバッガは **`Get Task Allow` 権限を持たないプロセスのタスクポート** を取得することはできず、そのためシステム整合性保護によって保護されています。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)してください。

### `com.apple.security.cs.disable-library-validation`

この権限により、Appleによって署名されていないか、メインの実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを **ロードすることができます**。したがって、攻撃者は任意のライブラリのロードを悪用してコードを注入することができます。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)してください。

### `com.apple.private.security.clear-library-validation`

この権限は **`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、**ライブラリの検証を直接無効にする**代わりに、プロセスがそれを無効にするために `csops` システムコールを呼び出すことができるようにします。詳細については[**こちらを参照**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)してください。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限により、ライブラリやコードを注入するために使用される可能性のある **DYLD環境変数** を使用することができます。詳細については[**こちらを参照**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)してください。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**このブログ**](https://objective-see.org/blog/blog\_0x4C.html) **および** [**このブログ**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの権限により、**TCC** データベースを **変更**することができます。

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの権限により、ユーザーの許可を求めることなくソフトウェアを **インストール**することができます。これは特権エスカレーションに役立ちます。

### `com.apple.private.security.kext-management`

カーネルにカーネル拡張をロードするために必要な権限です。

### **`com.apple.private.icloud-account-access`**

権限 **`com.apple.private.icloud-account-access`** を使用すると、**`com.apple.iCloudHelper`** XPCサービスと通信し、iCloudトークンを提供することができます。

**iMovie** と **Garageband** にはこの権限があります。

この権限から **icloudトークンを取得する** 攻撃についての詳細は、以下のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)
### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するのかわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **には、再起動後にSSVで保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法を知っている場合は、PRを送ってください！**

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **には、再起動後にSSVで保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法を知っている場合は、PRを送ってください！**

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

**フルディスクアクセス**権限を与えます。これは、TCCで最も高い権限の1つです。

### **`kTCCServiceAppleEvents`**

このアプリは、**タスクの自動化**に一般的に使用される他のアプリにイベントを送信することができます。他のアプリを制御することで、これらの他のアプリに付与された権限を悪用することができます。

例えば、ユーザーにパスワードを求めるように他のアプリに指示することができます:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

または、それらに**任意のアクションを実行**させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限の中には、**ユーザーのTCCデータベースを書き込む**ことができるものもあります。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーがホームフォルダのパスを変更するために**`NFSHomeDirectory`**属性を**変更**することができ、それによって**TCCをバイパス**することができます。

### **`kTCCServiceSystemPolicyAppBundles`**

デフォルトでは**許可されていない**アプリ内のファイル（app.app内のアプリ内バンドル内のファイル）を変更することができます。

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持っているユーザーは、_システム設定_ > _プライバシーとセキュリティ_ > _アプリの管理_で確認することができます。

## 中程度

### `com.apple.security.cs.allow-jit`

この権限を持つと、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、**書き込みと実行が可能なメモリ**を作成することができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限を持つと、Cコードを**オーバーライドまたはパッチ**することができ、長期間非推奨とされている**`NSCreateObjectFileImageFromMemory`**（基本的には安全ではない）を使用することができます。また、**DVDPlayback**フレームワークも使用できます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めると、アプリはメモリの安全でないコード言語における一般的な脆弱性にさらされる可能性があります。この例外が必要かどうかを慎重に考慮してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限を持つと、自身の実行可能ファイルのディスク上のセクションを**強制的に変更**して終了することができます。詳細については[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
Disable Executable Memory Protection Entitlementは、アプリの基本的なセキュリティ保護を削除する極端な権限であり、攻撃者が検出されずにアプリの実行可能コードを書き換えることが可能になります。可能な限り狭い範囲の権限を使用してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限を持つと、通常は禁止されているnullfsファイルシステムをマウントすることができます。ツール：[**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master)。

### `kTCCServiceAll`

このブログポストによると、このTCC権限は通常、次の形式で見つかります：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべてのTCC権限を要求する**ことを許可します。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
