# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Note that entitlements starting with **`com.apple`** are not available to third-parties, only Apple can grant them... Or if you are using an enterprise certificate you could create your own entitlements starting with **`com.apple`** actually and bypass protections based on this.

## High

### `com.apple.rootless.install.heritable`

The entitlement **`com.apple.rootless.install.heritable`** allows to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

The entitlement **`com.apple.rootless.install`** allows to **bypass SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

This entitlement allows to get the **task port for any** process, except the kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

This entitlement allows other processes with the **`com.apple.security.cs.debugger`** entitlement to get the task port of the process run by the binary with this entitlement and **inject code on it**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps with the Debugging Tool Entitlement can call `task_for_pid()` to retrieve a valid task port for unsigned and third-party apps with the `Get Task Allow` entitlement set to `true`. However, even with the debugging tool entitlement, a debugger **can’t get the task ports** of processes that **don’t have the `Get Task Allow` entitlement**, and that are therefore protected by System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

This entitlement allows to **load frameworks, plug-ins, or libraries without being either signed by Apple or signed with the same Team ID** as the main executable, so an attacker could abuse some arbitrary library load to inject code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

This entitlement is very similar to **`com.apple.security.cs.disable-library-validation`** but **instead** of **directly disabling** library validation, it allows the process to **call a `csops` system call to disable it**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

This entitlement allows to **use DYLD environment variables** that could be used to inject libraries and code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), these entitlements allows to **modify** the **TCC** database.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

These entitlements allows to **install software without asking for permissions** to the user, which can be helpful for a **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement needed to ask the **kernel to load a kernel extension**.

### **`com.apple.private.icloud-account-access`**

The entitlement **`com.apple.private.icloud-account-access`** it's possible to communicate with **`com.apple.iCloudHelper`** XPC service which will **provide iCloud tokens**.

**iMovie** and **Garageband** had this entitlement.

For more **information** about the exploit to **get icloud tokens** from that entitlement check the talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: I don't know what this allows to do

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **is mentioned that this could be used to** update the SSV-protected contents after a reboot. If you know how it send a PR please!

### `keychain-access-groups`

This entitlement list **keychain** groups the application has access to:
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

これは **Full Disk Access** の権限を付与します。これは TCC の中でも最も高い権限の一つです。

### **`kTCCServiceAppleEvents`**

アプリが一般的に**タスクの自動化**に使用される他のアプリケーションにイベントを送信できるようにします。他のアプリを制御することで、それらに付与された権限を悪用できます。

例えば、他のアプリにユーザーのパスワードを尋ねさせることができます：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
あるいはそれらに**任意の操作**を実行させることもできます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限と同様に、ユーザーのTCCデータベースに**書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーのホームフォルダパスを変更するユーザーの**`NFSHomeDirectory`**属性を**変更**できるため、結果としてTCCを**バイパス**できます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリのバンドル内（app.app 内）のファイルを変更でき、これは**デフォルトで禁止**されています。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

誰がこのアクセス権を持っているかは _System Settings_ > _Privacy & Security_ > _App Management_ で確認できます。

### `kTCCServiceAccessibility`

このプロセスは**macOS のアクセシビリティ機能を悪用**できるようになります。つまり例えば、キー入力を送信できるようになり、Finder のようなアプリを制御するためのアクセスを要求し、この権限でダイアログを承認できる可能性があります。

## Trustcache/CDhash related entitlements

Trustcache/CDhash 保護（Apple バイナリのダウングレード版の実行を防ぐ）をバイパスするために使用され得る entitlements がいくつかあります。

## Medium

### `com.apple.security.cs.allow-jit`

This entitlement allows to **create memory that is writable and executable** by passing the `MAP_JIT` flag to the `mmap()` system function. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

This entitlement allows to **override or patch C code**, use the long-deprecated **`NSCreateObjectFileImageFromMemory`** (which is fundamentally insecure), or use the **DVDPlayback** framework. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> この entitlement を含めると、メモリ安全でないコード言語における一般的な脆弱性にアプリが晒されます。アプリがこの例外を本当に必要とするか慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

This entitlement allows to **modify sections of its own executable files** on disk to forcefully exit. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は極めて強力なエンタイトルメントで、アプリから基本的なセキュリティ保護を取り除き、攻撃者がアプリの実行コードを書き換えても検出されない可能性を生じさせます。可能であれば、より限定的なエンタイトルメントを優先してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

This entitlement allows to mount a nullfs file system (forbidden by default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

このブログ投稿によると、この TCC 権限は通常以下の形式で見つかります：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスが**すべてのTCC権限を要求できるようにする**。

### **`kTCCServicePostEvent`**

`CGEventPost()`を介してシステム全体で**合成されたキーボードおよびマウスイベントを注入する**ことを許可します。この権限を持つプロセスは、任意のアプリケーションでキーストローク、マウスクリック、スクロールイベントをシミュレートでき、実質的にデスクトップの**リモート制御**を可能にします。

これは`kTCCServiceAccessibility`や`kTCCServiceListenEvent`と組み合わせると特に危険で、入力の読み取りと注入の両方が可能になるためです。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体の**すべてのキーボードおよびマウスイベントを傍受することを許可します**（入力モニタリング／キーロギング）。プロセスは`CGEventTap`を登録して、任意のアプリケーションで入力されたすべてのキー入力（パスワード、クレジットカード番号、プライベートメッセージを含む）を捕捉できます。

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

ディスプレイバッファの**読み取りを許可します** — 任意のアプリケーションのスクリーンショット取得や画面録画が可能で、保護されたテキストフィールドも含まれます。OCRと組み合わせることで、画面上のパスワードや機密データを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma以降、スクリーンキャプチャは永続的なメニューバー表示を示します。古いバージョンでは、画面録画が完全にサイレントで行われることがあります。

### **`kTCCServiceCamera`**

内蔵カメラや接続されたUSBカメラからの**写真およびビデオの撮影を許可します**。camera-entitled binaryへのコードインジェクションにより、サイレントな映像監視が可能になります。

### **`kTCCServiceMicrophone`**

すべての入力デバイスからの**オーディオ録音を許可します**。マイクアクセスを持つバックグラウンドデーモンは、目に見えるアプリケーションウィンドウなしで持続的な環境音の監視を提供します。

### **`kTCCServiceLocation`**

Wi‑Fi triangulationやBluetoothビーコンを介してデバイスの**物理的な位置**を照会することを許可します。継続的な監視は自宅／職場の住所、移動パターン、日常の行動ルーチンを明らかにします。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（名前、メール、電話 — スピアフィッシングに有用）、**Calendar**（会議スケジュール、参加者リスト）、**Photos**（個人写真や認証情報を含む可能性のあるスクリーンショット、位置情報メタデータ）へのアクセス。

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** は、通常サンドボックスがブロックするシステム全体のMach/XPCサービスとの通信を許可することで、App Sandboxを弱体化させます。これは**primary sandbox escape primitive**であり — 侵害されたサンドボックス化アプリはmach-lookup例外を使用して特権デーモンに到達し、それらのXPCインターフェースを悪用できます。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
For detailed exploitation chain: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, see:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** は、ユーザー空間のドライババイナリが IOKit インターフェースを介してカーネルと直接通信することを可能にします。DriverKit バイナリはハードウェア（USB、Thunderbolt、PCIe、HID デバイス、オーディオ、ネットワーキング）を管理します。

DriverKit バイナリを侵害すると、次が可能になります:
- **カーネルの攻撃面** — 不正な `IOConnectCallMethod` 呼び出し経由
- **USB デバイスのなりすまし**（HID 注入のためのキーボードのエミュレーション）
- **DMA 攻撃** — PCIe/Thunderbolt インターフェース経由
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
IOKit/DriverKit の詳細なエクスプロイトについては、次を参照してください:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
