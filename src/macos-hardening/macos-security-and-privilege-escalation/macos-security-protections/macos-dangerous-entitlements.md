# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** で始まる権限は第三者には利用できず、Appleのみが付与できます。

## High

### `com.apple.rootless.install.heritable`

権限 **`com.apple.rootless.install.heritable`** は **SIPをバイパス** することを許可します。詳細は [こちらを確認してください](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

権限 **`com.apple.rootless.install`** は **SIPをバイパス** することを許可します。詳細は [こちらを確認してください](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていました)**

この権限は、カーネルを除く **任意の** プロセスの **タスクポートを取得** することを許可します。詳細は [**こちらを確認してください**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.get-task-allow`

この権限は、**`com.apple.security.cs.debugger`** 権限を持つ他のプロセスが、この権限を持つバイナリによって実行されるプロセスのタスクポートを取得し、**コードを注入する** ことを許可します。詳細は [**こちらを確認してください**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`task_for_pid()` を呼び出して、`Get Task Allow` 権限が `true` に設定された署名されていないおよび第三者のアプリの有効なタスクポートを取得できます。しかし、デバッグツール権限があっても、デバッガは **`Get Task Allow` 権限を持たない** プロセスのタスクポートを取得できず、それらはシステム整合性保護によって保護されています。詳細は [**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限は、**Appleによって署名されていないか、メイン実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリをロードすることを許可します**。これにより、攻撃者は任意のライブラリのロードを悪用してコードを注入する可能性があります。詳細は [**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

この権限は **`com.apple.security.cs.disable-library-validation`** に非常に似ていますが、**ライブラリ検証を直接無効にするのではなく**、プロセスが **`csops` システムコールを呼び出して無効にすることを許可します**。\
詳細は [**こちらを確認してください**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、**ライブラリやコードを注入するために使用される可能性のあるDYLD環境変数を使用することを許可します**。詳細は [**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**このブログによると**](https://objective-see.org/blog/blog_0x4C.html) **および** [**このブログによると**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)、これらの権限は **TCC** データベースを **変更する** ことを許可します。

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの権限は、ユーザーに対して許可を求めることなく **ソフトウェアをインストールする** ことを許可します。これは **特権昇格** に役立つ可能性があります。

### `com.apple.private.security.kext-management`

カーネルにカーネル拡張をロードするように要求するために必要な権限です。

### **`com.apple.private.icloud-account-access`**

権限 **`com.apple.private.icloud-account-access`** により、**`com.apple.iCloudHelper`** XPCサービスと通信することが可能になり、**iCloudトークンを提供** します。

**iMovie** と **Garageband** はこの権限を持っていました。

この権限から **iCloudトークンを取得する** ためのエクスプロイトに関する詳細は、トークを確認してください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するのかはわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、再起動後にSSV保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法がわかる方はPRを送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、再起動後にSSV保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法がわかる方はPRを送ってください！

### `keychain-access-groups`

この権限リストは、アプリケーションがアクセスできる **キーチェーン** グループを示します:
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

**フルディスクアクセス** 権限を付与します。これは、持つことができる TCC の最高権限の一つです。

### **`kTCCServiceAppleEvents`**

アプリが一般的に **タスクを自動化** するために他のアプリケーションにイベントを送信することを許可します。他のアプリを制御することで、これらの他のアプリに付与された権限を悪用することができます。

例えば、ユーザーにパスワードを要求させることができます：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Or making them perform **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

ユーザーの TCC データベースに**書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの**`NFSHomeDirectory`** 属性を**変更**することを許可し、これによりホームフォルダのパスを変更し、**TCCをバイパス**することができます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリバンドル内のファイルを変更することを許可します（app.app 内）、これは**デフォルトでは禁止されています**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つユーザーを確認するには、_システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_ に移動します。

### `kTCCServiceAccessibility`

プロセスは**macOSのアクセシビリティ機能を悪用する**ことができ、例えばキーストロークを押すことができるようになります。したがって、Finder のようなアプリを制御するためのアクセスを要求し、この権限でダイアログを承認することができます。

## Medium

### `com.apple.security.cs.allow-jit`

この権限は、`mmap()` システム関数に `MAP_JIT` フラグを渡すことで、**書き込み可能かつ実行可能なメモリを作成する**ことを許可します。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限は、**C コードをオーバーライドまたはパッチする**ことを許可し、長い間非推奨の**`NSCreateObjectFileImageFromMemory`**（根本的に安全でない）を使用するか、**DVDPlayback** フレームワークを使用することを許可します。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)。

> [!CAUTION]
> この権限を含めると、アプリがメモリ安全でないコード言語の一般的な脆弱性にさらされます。この例外がアプリに必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

この権限は、ディスク上の**自分の実行可能ファイルのセクションを変更する**ことを許可し、強制的に終了させることができます。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)。

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は、アプリから基本的なセキュリティ保護を取り除く極端な権限であり、攻撃者が検出されることなくアプリの実行可能コードを書き換えることを可能にします。可能であれば、より狭い権限を優先してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限は、nullfs ファイルシステムをマウントすることを許可します（デフォルトでは禁止されています）。ツール: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

このブログ投稿によると、この TCC 権限は通常次の形式で見つかります:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべてのTCC権限を要求させる**ことを許可します。

### **`kTCCServicePostEvent`**

{{#include ../../../banners/hacktricks-training.md}}

</details>




{{#include /banners/hacktricks-training.md}}
