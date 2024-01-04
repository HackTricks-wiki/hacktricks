# macOS 危険な権限とTCC権限

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

{% hint style="warning" %}
**`com.apple`**で始まる権限は第三者には利用できず、Appleのみが付与できることに注意してください。
{% endhint %}

## 高

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** 権限は**SIPをバイパス**することを可能にします。[こちらを参照してください](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** 権限は**SIPをバイパス**することを可能にします。[こちらを参照してください](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていた)**

この権限は、カーネルを除く任意のプロセスの**タスクポートを取得**することを可能にします。[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

この権限は、**`com.apple.security.cs.debugger`** 権限を持つ他のプロセスが、この権限を持つバイナリによって実行されるプロセスのタスクポートを取得し、**コードを注入する**ことを可能にします。[**こちらを参照してください**](../mac-os-architecture/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`task_for_pid()`を呼び出して、`Get Task Allow`権限が`true`に設定されている未署名およびサードパーティアプリの有効なタスクポートを取得できます。しかし、デバッグツール権限があっても、デバッガーは`Get Task Allow`権限を持たないプロセスのタスクポートを取得することは**できません**。これらのプロセスはシステムインテグリティ保護によって保護されています。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限は、Appleによって署名されていない、またはメイン実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを**読み込むことを可能にします**。したがって、攻撃者は任意のライブラリの読み込みを悪用してコードを注入する可能性があります。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

この権限は**`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、ライブラリ検証を**直接無効にする**のではなく、プロセスが`csops`システムコールを呼び出して無効にすることを可能にします。\
[**こちらを参照してください**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、ライブラリやコードを注入するために使用できる**DYLD環境変数の使用**を可能にします。[**こちらを参照してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**このブログ**](https://objective-see.org/blog/blog\_0x4C.html) **と** [**このブログ**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの権限は**TCC**データベースを**変更**することを可能にします。

### **`system.install.apple-software`** と **`system.install.apple-software.standar-user`**

これらの権限は、ユーザーに許可を求めることなく**ソフトウェアをインストール**することを可能にし、**権限昇格**に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**カーネルにカーネル拡張をロード**するように要求するために必要な権限です。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** 権限を持つと、**`com.apple.iCloudHelper`** XPCサービスと通信し、**iCloudトークンを提供**することが可能です。

**iMovie** と **Garageband** はこの権限を持っていました。

その権限から**iCloudトークンを取得する**ためのエクスプロイトについての詳細は、トーク: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)をご覧ください。

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を可能にするのかはわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)によると、これはリブート後にSSV保護されたコンテンツを更新するために使用できると言及されています。方法を知っている場合はPRを送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)によると、これはリブート後にSSV保護されたコンテンツを更新するために使用できると言及されています。方法を知っている場合はPRを送ってください！

### `keychain-access-groups`

この権限は、アプリケーションがアクセスできる**キーチェーン**グループをリストします：
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

例えば、ユーザーにパスワードを求めるように仕向けることができます：

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

デフォルトでは禁止されているアプリバンドル内のファイル（app.app内）を変更することを許可します。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持っている人を _システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_ で確認できます。

### `kTCCServiceAccessibility`

このプロセスは、**macOSのアクセシビリティ機能を悪用**することができます。つまり、例えばキーストロークを押すことができるということです。したがって、Finderのようなアプリの制御を要求し、この権限でダイアログを承認することができます。

## 中程度

### `com.apple.security.cs.allow-jit`

この権限は、`mmap()` システム関数に `MAP_JIT` フラグを渡すことで、**書き込み可能で実行可能なメモリを作成**することを許可します。詳細は[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限は、**Cコードをオーバーライドまたはパッチ**すること、長く非推奨とされている**`NSCreateObjectFileImageFromMemory`**（根本的に安全でない）を使用すること、または**DVDPlayback**フレームワークを使用することを許可します。詳細は[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めると、メモリ安全でないコード言語の一般的な脆弱性にアプリがさらされる可能性があります。アプリがこの例外を必要とするかどうか慎重に検討してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限は、**自身の実行可能ファイルのセクションをディスク上で変更**して強制終了することを許可します。詳細は[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。

{% hint style="danger" %}
実行可能メモリ保護を無効にする権限は、アプリから基本的なセキュリティ保護を取り除く極端な権限であり、攻撃者が検出されることなくアプリの実行コードを書き換える可能性を生じさせます。可能であれば、より狭い範囲の権限を優先してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限は、デフォルトでは禁止されているnullfsファイルシステムをマウントすることを許可します。ツール: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
