# macOS危険な権限とTCC権限

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

{% hint style="warning" %}
**`com.apple`**で始まる権限はサードパーティには利用できず、Appleのみがそれらを付与できます。
{% endhint %}

## 高

### `com.apple.rootless.install.heritable`

権限**`com.apple.rootless.install.heritable`**は**SIPをバイパス**することを可能にします。詳細は[こちら](macos-sip.md#com.apple.rootless.install.heritable)を参照してください。

### **`com.apple.rootless.install`**

権限**`com.apple.rootless.install`**は**SIPをバイパス**することを可能にします。詳細は[こちら](macos-sip.md#com.apple.rootless.install)を参照してください。

### **`com.apple.system-task-ports`（以前は`task_for_pid-allow`と呼ばれていました）**

この権限は、カーネルを除く**任意の**プロセスの**タスクポートを取得**することを可能にします。詳細は[こちら](../macos-proces-abuse/macos-ipc-inter-process-communication/)を参照してください。

### `com.apple.security.get-task-allow`

この権限は、他のプロセスが**`com.apple.security.cs.debugger`**権限を持つプロセスのタスクポートを取得し、この権限を持つバイナリによって実行されるプロセスにコードを**インジェクト**することを可能にします。詳細は[こちら](../macos-proces-abuse/macos-ipc-inter-process-communication/)を参照してください。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリケーションは、`Get Task Allow`権限が`true`に設定された未署名およびサードパーティアプリケーションの有効なタスクポートを取得するために`task_for_pid()`を呼び出すことができます。ただし、デバッガーはデバッグツール権限を持っていても、**`Get Task Allow`権限を持たないプロセス**のタスクポートを取得できず、したがってシステム整合性保護によって保護されているプロセスのタスクポートを取得できません。詳細は[こちら](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)を参照してください。

### `com.apple.security.cs.disable-library-validation`

この権限は、Appleによって署名されていないか、メインの実行可能ファイルと同じTeam IDで署名されていないフレームワーク、プラグイン、またはライブラリを**ロード**することを可能にします。したがって、攻撃者は任意のライブラリのロードを悪用してコードをインジェクトすることができます。詳細は[こちら](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)を参照してください。

### `com.apple.private.security.clear-library-validation`

この権限は**`com.apple.security.cs.disable-library-validation`**と非常に似ており、**ライブラリの検証を直接無効にする**代わりに、プロセスが**`csops`システムコールを呼び出して無効にする**ことを可能にします。\
詳細は[こちら](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)を参照してください。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、ライブラリやコードをインジェクトするために使用できる**DYLD環境変数**の使用を可能にします。詳細は[こちら](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)を参照してください。

### `com.apple.private.tcc.manager`または`com.apple.rootless.storage`.`TCC`

[**このブログによると**](https://objective-see.org/blog/blog\_0x4C.html) **および** [**このブログによると**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)、これらの権限は**TCC**データベースを**変更**することを可能にします。

### **`system.install.apple-software`**および**`system.install.apple-software.standar-user`**

これらの権限は、ユーザーに許可を求めることなく**ソフトウェアをインストール**することを可能にします。これは**特権昇格**に役立ちます。

### `com.apple.private.security.kext-management`

カーネルに**カーネル拡張機能をロードするように要求**するための権限が必要です。

### **`com.apple.private.icloud-account-access`**

権限**`com.apple.private.icloud-account-access`**を使用すると、**`com.apple.iCloudHelper`** XPCサービスと通信し、**iCloudトークンを提供**できます。

**iMovie**と**Garageband**にはこの権限がありました。

この権限から**iCloudトークンを取得**するためのエクスプロイトについての詳細については、次のトークを参照してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するかわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **によると、これは**再起動後にSSVで保護されたコンテンツを更新するために使用できる可能性があります。方法を知っている場合は、PRを送信してください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **によると、これは**再起動後にSSVで保護されたコンテンツを更新するために使用できる可能性があります。方法を知っている場合は、PRを送信してください！

### `keychain-access-groups`

この権限リストには、アプリケーションがアクセスできる**キーチェーン**グループが含まれています：
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

**フルディスクアクセス**権限を与え、持っているできるTCCの最高権限の1つです。

### **`kTCCServiceAppleEvents`**

アプリケーションが**タスクの自動化**に一般的に使用される他のアプリケーションにイベントを送信することを許可します。他のアプリを制御することで、これらの他のアプリに付与された権限を悪用することができます。

ユーザにパスワードを求めさせるようにすることもできます：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

またはそれらを**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限の中で、**ユーザーのTCCデータベースを書き込む**ことができます。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの**ホームフォルダーパスを変更する**ユーザーの**`NFSHomeDirectory`**属性を**変更**することができ、それにより**TCCをバイパス**することができます。

### **`kTCCServiceSystemPolicyAppBundles`**

デフォルトでは**許可されていない**アプリのバンドル内のファイル（app.app内）を変更できます。

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持っているユーザーを確認することができます。_システム設定_ > _プライバシーとセキュリティ_ > _アプリの管理_.

### `kTCCServiceAccessibility`

プロセスは**macOSのアクセシビリティ機能を悪用**することができます。つまり、例えばキーストロークを押すことができます。そのため、Finderのようなアプリを制御するアクセスをリクエストし、この権限でダイアログを承認することができます。

## Medium

### `com.apple.security.cs.allow-jit`

この権限により、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、**書き込み可能かつ実行可能なメモリを作成**することができます。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)を参照してください。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限により、**Cコードをオーバーライドまたはパッチ**することができ、長期間非推奨の**`NSCreateObjectFileImageFromMemory`**（基本的に安全ではない）を使用したり、**DVDPlayback**フレームワークを使用したりすることができます。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)を参照してください。

{% hint style="danger" %}
この権限を含めると、アプリがメモリの安全でないコード言語に一般的な脆弱性にさらされる可能性があります。この例外がアプリに必要かどうかを慎重に検討してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限により、ディスク上の自身の実行可能ファイルのセクションを**強制的に終了**することができます。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)を参照してください。

{% hint style="danger" %}
実行可能メモリ保護を無効にする権限は、アプリから基本的なセキュリティ保護を削除し、攻撃者がアプリの実行可能コードを検出されずに書き換えることが可能になります。可能であれば、より狭い権限を選択してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限により、デフォルトでは禁止されているnullfsファイルシステムをマウントすることができます。ツール: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

このブログ投稿によると、このTCC権限は通常、以下の形式で見つかります:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスが**すべてのTCC権限を要求する**ことを許可します。

### **`kTCCServicePostEvent`**

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**する
* **ハッキングテクニックを共有するためにPRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>
