# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** で始まる entitlements は third-party では利用できず、Apple のみが付与できます... ただし enterprise certificate を使用している場合は、実際には **`com.apple`** で始まる独自の entitlements を作成し、これに基づく protections を bypass できる可能性があります。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement により **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install.heritable)を確認してください。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement により **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install)を確認してください。

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

この entitlement により、kernel を除く**任意の** process の **task port** を取得できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.get-task-allow`

この entitlement により、**`com.apple.security.cs.debugger`** entitlement を持つ他の processes が、この entitlement を持つ binary によって実行された process の task port を取得し、**その process に code を inject** できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement を持つ apps は `task_for_pid()` を呼び出して、`Get Task Allow` entitlement が `true` に設定された unsigned および third-party apps の有効な task port を取得できます。しかし、debugging tool entitlement があっても、debugger は **`Get Task Allow` entitlement を持たない** process の **task ports を取得できず**、そのため System Integrity Protection によって保護されています。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)を確認してください。<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

この entitlement により、main executable と**同じ Team ID で署名されているか、Apple によって署名されているかに関係なく** frameworks、plug-ins、または libraries を **load** できます。そのため attacker は、任意の library load を abuse して code を inject できる可能性があります。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)を確認してください。<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

この entitlement は **`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、**直接 library validation を disable する**代わりに、process が `csops` system call を呼び出して runtime に disable できるようにします。

entitlement 名は、それを使用する `csops` operation の隣に XNU 内で hardcode されています。<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`（`bsd/kern/kern_proc.c`）の kernel handler は、この primitive がいかに限定的かを正確に示しています。<sup>[[2]](#references)</sup>
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
So the operation:

- **macOS-only**（他のすべての platform では `ENOTSUP`）。
- **自身に対してのみ**動作する（`forself == 1`）—これを使って別の process から library validation を除去することはできません。
- process が実際に **entitlement を保持している**必要があり、process に `CS_INSTALLER` のフラグが設定されている場合、または subsystem root path の配下で実行されている場合は拒否されます。
- process の code-signing flags から **`CS_REQUIRE_LV | CS_FORCED_LV`** をクリアします。

XNU の comment では想定される用途が説明されており、同時に attacker にとって興味深い理由も説明されています。

> この option は、実行中の process から library validation を除去するために使用されます。これは、program が untrusted libraries を load する必要がある plugin architectures で使用されます。[...] process が untrusted library を load した後は、将来 library validation に依存しても有効ではありません。

つまり、**この entitlement を持つ binary は dylib-injection target です**。`CS_REQUIRE_LV` を削除した後に、その中で code を実行する（または plug-in を load させる）ことができれば、host process が信頼されて実行できるあらゆる操作を引き継げます。

### `com.apple.security.cs.allow-dyld-environment-variables`

この entitlement により、library や code の inject に使用できる **DYLD environment variables を使用**できます。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)を確認してください。<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**この blog**](https://objective-see.org/blog/blog_0x4C.html) **および** [**この blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/) **によると**、これらの entitlements により **TCC** database を **modify**できます。<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの entitlements により、user に **permission を求めずに software を install**できます。これは **privilege escalation** に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**kernel に kernel extension の load を要求する**ために必要な entitlement です。

### **`com.apple.private.icloud-account-access`**

entitlement **`com.apple.private.icloud-account-access`** により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** はこの entitlement を持っていました。

この entitlement を利用して **iCloud tokens を取得する** exploit の詳細については、次の talk を確認してください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これで何ができるのかは分かりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、これを使用して reboot 後に SSV-protected contents を update できる可能性があると述べられています。どのように行うのか知っている場合は PR を送ってください！<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、これを使用して reboot 後に SSV-protected contents を update できる可能性があると述べられています。どのように行うのか知っている場合は PR を送ってください！<sup>[[9]](#references)</sup>

### `keychain-access-groups`

この entitlement は、application が access できる **keychain** groups を一覧表示します:
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

**Full Disk Access** 権限を付与します。これは取得可能な TCC 権限の中でも最も強力なものの一つです。

### **`kTCCServiceAppleEvents`**

一般的に **automating tasks** に使用される、他のアプリケーションへイベントを送信することをアプリに許可します。他のアプリを制御できるため、それらのアプリに付与された権限を悪用できます。

例えば、ユーザーにパスワードを尋ねさせることができます。
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
または、それらに**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限に加えて、**ユーザーの TCC データベースに書き込む**ことができます。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの **`NFSHomeDirectory`** 属性を**変更**できます。これによりユーザーのホームフォルダーのパスが変更され、結果として**TCC をバイパス**できます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリバンドル（app.app 内部）のファイルを変更できます。これはデフォルトでは**許可されていません**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つアプリは、_システム設定_ > _プライバシーとセキュリティ_ > _App Management_ で確認できます。

### `kTCCServiceAccessibility`

このプロセスは、**macOS のアクセシビリティ機能を悪用**できるようになります。つまり、たとえばキーストロークを送信できます。そのため、Finder などのアプリを制御するアクセスを要求し、この権限でダイアログを承認できます。

## Trustcache/CDhash 関連のエンタイトルメント

Trustcache/CDhash の保護をバイパスするために使用できるエンタイトルメントがいくつかあります。これらの保護は、Apple バイナリのダウングレードされたバージョンの実行を防止します。

## Medium

### `com.apple.security.cs.allow-jit`

このエンタイトルメントにより、`mmap()` システム関数に `MAP_JIT` フラグを渡すことで、**書き込み可能かつ実行可能なメモリを作成**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)を確認してください。<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

このエンタイトルメントにより、**C コードをオーバーライドまたはパッチ**したり、長期間非推奨となっている **`NSCreateObjectFileImageFromMemory`**（根本的に安全ではありません）を使用したり、**DVDPlayback** framework を使用したりできます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)を確認してください。<sup>[[11]](#references)</sup>

> [!CAUTION]
> このエンタイトルメントを含めると、メモリ安全性のないコード言語における一般的な脆弱性にアプリがさらされます。アプリにこの例外が必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

このエンタイトルメントにより、強制終了させるために、ディスク上にある自身の実行ファイルの**セクションを変更**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)を確認してください。<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は極めて強力なエンタイトルメントであり、アプリから基本的なセキュリティ保護を削除します。これにより、攻撃者が検知されることなくアプリの実行コードを書き換えられるようになります。可能であれば、より範囲の狭いエンタイトルメントを使用してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

このエンタイトルメントにより、nullfs ファイルシステムをマウントできます（デフォルトでは禁止されています）。Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

この blogpost によると、この TCC 権限は通常、次の形式で見つかります。
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに **すべての TCC permissions を要求**させる。

### **`kTCCServicePostEvent`**

`CGEventPost()` を介して、システム全体で **synthetic keyboard and mouse events を inject**できる。これにより、この permission を持つプロセスは、あらゆるアプリケーションで keystrokes、mouse clicks、scroll events を simulate でき、実質的にデスクトップを **remote control** できる。

これは `kTCCServiceAccessibility` または `kTCCServiceListenEvent` と組み合わせると特に危険であり、input の読み取りと **inject** の両方が可能になる。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体の**すべてのキーボードおよびマウスイベントの傍受**（input monitoring / keylogging）を可能にします。プロセスは `CGEventTap` を登録して、パスワード、クレジットカード番号、プライベートメッセージなど、あらゆるアプリケーションで入力されたすべてのキー入力を取得できます。

詳細な exploitation techniques については、以下を参照してください。

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**ディスプレイバッファの読み取り**を可能にします。これにより、secure text fields を含むあらゆるアプリケーションのスクリーンショット取得や画面の動画 recording が可能になります。OCR と組み合わせることで、画面上のパスワードや機密データを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma 以降では、screen capture 中にメニューバーへ常時表示されるインジケーターが表示されます。以前のバージョンでは、screen recording を完全に無音で実行できます。

### **`kTCCServiceCamera`**

内蔵カメラまたは接続された USB カメラからの**写真および動画の取得**を可能にします。camera-entitled binary への code injection により、無音の visual surveillance が可能になります。

### **`kTCCServiceMicrophone`**

すべての入力デバイスからの**音声 recording**を可能にします。マイクへのアクセス権を持つバックグラウンドデーモンは、表示されるアプリケーションウィンドウなしで、永続的な周囲音声の監視を実現します。

### **`kTCCServiceLocation`**

Wi-Fi triangulation または Bluetooth beacon を介して、デバイスの**物理的な位置情報**を照会できます。継続的な監視により、自宅や職場の住所、移動パターン、日々の行動習慣が明らかになります。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（氏名、メールアドレス、電話番号 — spear-phishing に有用）、**Calendar**（会議の予定、参加者一覧）、**Photos**（個人の写真、credentials が含まれている可能性のあるスクリーンショット、位置情報メタデータ）へのアクセスを可能にします。

TCC permissions を介した完全な credential theft exploitation techniques については、以下を参照してください。

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox と Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** は、通常 sandbox がブロックするシステム全体の Mach/XPC services との通信を許可することで、App Sandbox の制限を弱めます。これは**主要な sandbox escape primitive** です。侵害された sandboxed app は、mach-lookup exceptions を使用して特権 daemon に到達し、その XPC interfaces を exploit できます。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
詳細なexploit chain（sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape）については、以下を参照してください。

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** により、user-space driver binaries は IOKit interfaces を介して Kernel と直接通信できます。DriverKit binaries は、USB、Thunderbolt、PCIe、HID devices、audio、networking などのhardwareを管理します。

DriverKit binary をcompromiseすると、以下が可能になります。
- **Kernel attack surface**：不正な `IOConnectCallMethod` calls を介する
- **USB device spoofing**（HID injection 用にkeyboardをemulateする）
- **DMA attacks**：PCIe/Thunderbolt interfaces を介する
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
詳細な IOKit/DriverKit exploitation については、以下を参照してください。

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## 参考資料

- [1] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement（`com.apple.security.cs.debugger`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC の bypass](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 音楽を再生して TCC を bypass、別名 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: 「Mac で起きたことは、Apple の iCloud に留まるのか?!」 - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple の OTA Update の悪夢: Signature Verification を bypass して Kernel を Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement（`com.apple.security.cs.allow-jit`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)

{{#include ../../../banners/hacktricks-training.md}}
