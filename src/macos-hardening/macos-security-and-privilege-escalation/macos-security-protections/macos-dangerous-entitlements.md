# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** で始まる entitlements は third-party では利用できず、Apple のみが付与できます... ただし enterprise certificate を使用している場合は、実際には **`com.apple`** で始まる独自の entitlements を作成し、これに基づく保護を bypass できる可能性があります。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement により **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install.heritable)を確認してください。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement により **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install)を確認してください。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていた)**

この entitlement により、kernel を除く**任意の** process の **task port** を取得できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.get-task-allow`

この entitlement により、**`com.apple.security.cs.debugger`** entitlement を持つ他の process が、この entitlement を持つ binary によって実行されている process の task port を取得し、**その process に code を inject** できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement を持つ apps は、`task_for_pid()` を呼び出して、`Get Task Allow` entitlement が `true` に設定された unsigned および third-party apps の有効な task port を取得できます。しかし、debugging tool entitlement を持っていても、debugger は **`Get Task Allow` entitlement を持たない** process、つまり System Integrity Protection によって保護されている process の **task ports を取得できません**。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)を確認してください。

### `com.apple.security.cs.disable-library-validation`

この entitlement により、**Apple によって署名されていない、または main executable と同じ Team ID で署名されていない frameworks、plug-ins、libraries を load** できます。そのため attacker は、任意の library load を悪用して code を inject できる可能性があります。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)を確認してください。

### `com.apple.private.security.clear-library-validation`

この entitlement は **`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、**library validation を直接 disable する**代わりに、process が runtime で **`csops` system call を呼び出して disable** できるようにします。

この entitlement name は、これを消費する `csops` operation の隣にある XNU に hardcode されています:<sup>[[2]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`（`bsd/kern/kern_proc.c`）のkernel handlerは、このprimitiveがいかに限定的かを正確に示しています。<sup>[[3]](#references)</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
したがって、この操作は次のようになります。

- **macOS-only**（他のすべてのプラットフォームでは `ENOTSUP`）。
- **自身に対してのみ**動作する（`forself == 1`）ため、これを使って別のプロセスから library validation を無効化することはできません。
- プロセスが実際に **entitlement を保持している**必要があり、プロセスに `CS_INSTALLER` のフラグが設定されている場合、または subsystem root path 配下で実行されている場合は拒否されます。
- プロセスの code-signing flags から **`CS_REQUIRE_LV | CS_FORCED_LV`** をクリアします。

XNU のコメントには想定されているユースケースと、攻撃者にとって興味深い理由が説明されています。

> このオプションは、実行中のプロセスから library validation を削除するために使用されます。これは、プログラムが untrusted libraries をロードする必要がある plugin architectures で使用されます。[...] プロセスが untrusted library をロードした後は、将来 library validation に依存しても有効ではありません。

つまり、**この entitlement を持つバイナリはすべて dylib-injection target になります**。`CS_REQUIRE_LV` を無効化した後に、そのバイナリ内でコードを実行する（または独自の plug-in をロードさせる）ことができれば、ホストプロセスが信頼されて実行できる操作をそのまま利用できます。

### `com.apple.security.cs.allow-dyld-environment-variables`

この entitlement により、library や code の inject に使用できる **DYLD environment variables** を**使用できるようになります**。[**詳細はこちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) を確認してください。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**この blog**](https://objective-see.org/blog/blog_0x4C.html) **および** [**この blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) **によると、これらの entitlements により** **TCC** database を **modify** できます。

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの entitlements により、ユーザーに**権限を求めずに software を install** できます。これは **privilege escalation** に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**kernel に kernel extension の load を要求する**ために必要な entitlement です。

### **`com.apple.private.icloud-account-access`**

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** はこの entitlement を保持していました。

この entitlement を利用して **iCloud tokens を取得する** exploit の詳細については、次の talk を確認してください。[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これで何ができるのかは不明です

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **では、これを使用して** reboot 後に SSV-protected contents を update できる可能性があると**述べられています**。方法を知っている場合は PR を送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **では、これを使用して** reboot 後に SSV-protected contents を update できる可能性があると**述べられています**。方法を知っている場合は PR を送ってください！

### `keychain-access-groups`

この entitlement は、application が access できる **keychain** groups を一覧表示します：
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

**Full Disk Access** 権限を付与します。これは、TCC で取得できる最も強力な権限の 1 つです。

### **`kTCCServiceAppleEvents`**

一般的に **automating tasks** に使用される、他のアプリケーションへイベントを送信することをアプリに許可します。他のアプリを制御できるため、それらのアプリに付与された権限を悪用できます。

例えば、ユーザーにパスワードを尋ねさせることができます:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
または、**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限に加えて、**ユーザーのTCCデータベースに書き込む**ことができます。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの **`NFSHomeDirectory`** 属性を**変更**できます。これによりホームフォルダのパスが変更され、**TCCをバイパス**できます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリバンドル（app.app 内部）のファイルを変更できます。これはデフォルトでは**許可されていません**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つアプリは、_システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_ で確認できます。

### `kTCCServiceAccessibility`

このプロセスは、**macOSのアクセシビリティ機能を悪用**できるようになります。つまり、例えばキーストロークを送信できます。そのため、この権限を使ってFinderなどのアプリを制御するアクセス権を要求し、ダイアログを承認できます。

## Trustcache/CDhash関連のentitlement

Appleバイナリのダウングレードされたバージョンの実行を防ぐTrustcache/CDhash保護をバイパスするために使用できるentitlementがいくつかあります。

## 中程度

### `com.apple.security.cs.allow-jit`

このentitlementにより、`mmap()`システム関数に`MAP_JIT`フラグを渡して、**書き込み可能かつ実行可能なメモリを作成**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)を確認してください。

### `com.apple.security.cs.allow-unsigned-executable-memory`

このentitlementにより、**Cコードをオーバーライドまたはpatch**したり、長らく非推奨となっている**`NSCreateObjectFileImageFromMemory`**（基本的に安全ではありません）を使用したり、**DVDPlayback** frameworkを使用したりできます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)を確認してください。

> [!CAUTION]
> このentitlementを含めると、メモリ安全性の低いコード言語における一般的な脆弱性にアプリがさらされます。アプリにこの例外が必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

このentitlementにより、**自身の実行ファイルのセクションをディスク上で変更**して、強制的に終了させることができます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)を確認してください。

> [!CAUTION]
> Disable Executable Memory Protection Entitlementは、アプリから基本的なセキュリティ保護を取り除く極めて強力なentitlementです。攻撃者が検知されることなくアプリの実行コードを書き換えられるようになるため、可能であれば、より限定的なentitlementを使用してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

このentitlementにより、nullfsファイルシステムをマウントできます（デフォルトでは禁止されています）。Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

このブログ記事によると、このTCC権限は通常、次の形式で見つかります。
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに **すべての TCC permissions を要求する**ことを許可します。

### **`kTCCServicePostEvent`**

`CGEventPost()` を介して、システム全体に **synthetic keyboard and mouse events を注入**できます。この permission を持つプロセスは、あらゆるアプリケーションで keystrokes、mouse clicks、scroll events をシミュレートでき、事実上デスクトップの **remote control** が可能になります。

これは `kTCCServiceAccessibility` または `kTCCServiceListenEvent` と組み合わせると特に危険です。入力の読み取りと **injecting input** の両方が可能になるためです。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体で**すべてのキーボードおよびマウスイベントをintercept**（input monitoring / keylogging）できます。プロセスは `CGEventTap` を登録して、パスワード、クレジットカード番号、プライベートメッセージを含む、あらゆるアプリケーションで入力されたすべてのキーストロークを取得できます。

詳細なexploit techniquesについては、以下を参照してください。

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**display bufferの読み取り** — あらゆるアプリケーションのスクリーンショット取得や画面動画の録画が可能です。secure text fieldsも対象になります。OCRと組み合わせることで、画面からパスワードやsensitive dataを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma以降では、screen captureを実行するとメニューバーに永続的なインジケーターが表示されます。古いバージョンでは、screen recordingを完全に無音で実行できます。

### **`kTCCServiceCamera`**

内蔵カメラまたは接続されたUSBカメラから、写真や動画を**capture**できます。camera-entitled binaryにcode injectionすることで、密かにvisual surveillanceを実行できます。

### **`kTCCServiceMicrophone`**

すべてのinput devicesから**音声をrecording**できます。マイクアクセスを持つバックグラウンドdaemonにより、表示されるアプリケーションウィンドウなしで、継続的なambient audio surveillanceが可能になります。

### **`kTCCServiceLocation`**

Wi-Fi triangulationまたはBluetooth beaconを介して、デバイスの**physical location**を問い合わせできます。継続的なmonitoringにより、自宅や職場の住所、移動パターン、日々の行動パターンが明らかになります。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（名前、メールアドレス、電話番号 — spear-phishingに有用）、**Calendar**（会議の予定、参加者リスト）、**Photos**（個人写真、credentialsが含まれている可能性のあるスクリーンショット、location metadata）へのアクセスが可能になります。

TCC permissionsを介したcredential theft exploitation techniquesの詳細については、以下を参照してください。

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**は、通常Sandboxがブロックするシステム全体のMach/XPC servicesとの通信を許可することで、App Sandboxを弱体化させます。これは**primary sandbox escape primitive**です — compromised sandboxed appはmach-lookup exceptionsを使用してprivileged daemonsに到達し、そのXPC interfacesをexploitできます。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
詳細なexploit chain（sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape）については、以下を参照してください：

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** により、user-space driver binaryはIOKit interfaceを介してkernelと直接通信できます。DriverKit binaryは、USB、Thunderbolt、PCIe、HID device、audio、networkingなどのhardwareを管理します。

DriverKit binaryをcompromiseすると、以下が可能になります：
- 不正な `IOConnectCallMethod` 呼び出しによる **kernel attack surface**
- **USB device spoofing**（HID injection用のkeyboardをemulate）
- PCIe/Thunderbolt interface経由の **DMA attacks**
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
詳細な IOKit/DriverKit exploitation については、以下を参照してください：

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## 参考文献

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
