# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements は、オペレーティングシステムが署名済みコードに付与する機能とセキュリティ例外を宣言します。以下の項目では、offensive review 中に特に有用なものに焦点を当てています。<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`** で始まる entitlements は third-parties では利用できず、Apple のみが付与できます。ただし、enterprise certificate を使用している場合は、実際には **`com.apple`** で始まる独自の entitlements を作成し、これに基づく保護を bypass できる可能性があります。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement により、プロセスは **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install.heritable)を確認してください。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement により、プロセスは **SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install)を確認してください。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていた)**

この entitlement により、プロセスは kernel 以外の**任意の**プロセスの **task port** を取得できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.get-task-allow`

この entitlement により、**`com.apple.security.cs.debugger`** entitlement を持つ他のプロセスは、この entitlement を持つ binary によって実行されているプロセスの task port を取得し、**そのプロセスに code を inject** できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement を持つ App は `task_for_pid()` を呼び出し、`Get Task Allow` entitlement が `true` に設定された unsigned および third-party App の有効な task port を取得できます。しかし、Debugging Tool Entitlement があっても、debugger は **`Get Task Allow` entitlement を持たない**プロセス、つまり System Integrity Protection によって保護されているプロセスの **task port を取得できません**。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)を確認してください。<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

この entitlement により、アプリケーションは、Apple による署名、または main executable と同じ Team ID による署名を必要とせずに **framework、plug-in、library を load** できます。そのため、攻撃者は任意の library load を悪用して code を inject できる可能性があります。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)を確認してください。<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

この entitlement は **`com.apple.security.cs.disable-library-validation`** と非常によく似ていますが、**library validation を直接 disable** する代わりに、プロセスが runtime に **`csops` system call を呼び出して disable** できるようにします。

entitlement 名は、これを使用する `csops` operation の隣に XNU 内で hardcode されています。<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`（`bsd/kern/kern_proc.c`）の kernel handler は、この primitive がいかに限定的であるかを正確に示しています。<sup>[[2]](#references)</sup>
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

- **macOS-only**（他のすべてのプラットフォームでは `ENOTSUP`）。
- **自身に対してのみ**動作する（`forself == 1`）—これを使って別のプロセスから library validation を取り除くことはできません。
- プロセスが実際にその entitlement を**保持している**必要があり、プロセスに `CS_INSTALLER` のフラグが設定されている場合、または subsystem root path 配下で実行されている場合は拒否されます。
- プロセスの code-signing flags から **`CS_REQUIRE_LV | CS_FORCED_LV`** をクリアします。

XNU のコメントには想定された利用ケースと、これが攻撃者にとって興味深い理由が説明されています。

> このオプションは、実行中のプロセスから library validation を取り除くために使用される。これは、プログラムが信頼されていない library をロードする必要がある plugin architecture で使用される。[...] プロセスが信頼されていない library をロードした後は、将来 library validation に依存しても有効ではない。

つまり、**この entitlement を持つすべての binary は dylib-injection target です**。その binary 内で code を実行するか、独自の plug-in をロードするよう仕向けた後で `CS_REQUIRE_LV` を解除させれば、host process が信頼されて実行できる操作をそのまま利用できます。

### `com.apple.security.cs.allow-dyld-environment-variables`

この entitlement により、library や code の inject に使用できる **DYLD environment variables** を**使用できます**。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)を確認してください。<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**この blog**](https://objective-see.org/blog/blog_0x4C.html) **および**[**この blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの entitlement により、プロセスは **TCC** database を**変更**できます。<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの entitlement により、プロセスはユーザーに許可を求めずに**ソフトウェアをインストール**できます。これは**privilege escalation**に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**kernel に kernel extension のロードを要求する**ために必要な entitlement です。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement により、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できるようになります。

**iMovie** と **Garageband** にはこの entitlement がありました。

この entitlement から **iCloud tokens を取得する** exploit の詳細については、次の talk を確認してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これで何が可能になるのかはわかりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、この entitlement を使用して、reboot 後に SSV-protected contents を update できる可能性があると述べられています。方法を知っている場合は、PR を送ってください！<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**同じ report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、sealed snapshot を作成することで、reboot 後に SSV-protected contents を update できる可能性があると述べられています。方法を知っている場合は、PR を送ってください！<sup>[[9]](#references)</sup>

### `keychain-access-groups`

この entitlement は、application が access できる **keychain** groups の一覧です：
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

**Full Disk Access** 権限を付与します。これは、TCCで取得できる最も強力な権限の1つです。

### **`kTCCServiceAppleEvents`**

他のアプリケーションにイベントを送信できるようにします。これらのアプリケーションは一般的に**タスクの自動化**に使用されます。他のアプリを制御することで、それらのアプリに付与された権限を悪用できます。

例えば、ユーザーにパスワードを要求させることができます：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
または、**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限に加えて、**ユーザーの TCC database に書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの **`NFSHomeDirectory`** 属性を**変更**し、ホームフォルダーのパスを変更できるようにします。これにより、**TCC を bypass**できます。

### **`kTCCServiceSystemPolicyAppBundles`**

デフォルトでは**禁止されている**、アプリバンドル（app.app 内）のファイル変更を許可します。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つアプリは、_System Settings_ > _Privacy & Security_ > _App Management_ で確認できます。

### `kTCCServiceAccessibility`

プロセスが **macOS のアクセシビリティ機能を abuse**できるようになります。つまり、たとえばキーストロークを送信できるようになります。そのため、この権限を使って Finder などのアプリを制御するアクセスを要求し、ダイアログで承認することが可能です。

## Trustcache/CDhash related entitlements

downgrade されたバージョンの Apple バイナリの実行を防ぐ Trustcache/CDhash protections を bypass するために使用できる entitlements がいくつかあります。

## Medium

### `com.apple.security.cs.allow-jit`

この entitlement により、`mmap()` system function に `MAP_JIT` flag を渡して、**書き込み可能かつ実行可能なメモリを作成**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)を確認してください。<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

この entitlement により、**C code を override または patch**したり、長期間 deprecated となっている **`NSCreateObjectFileImageFromMemory`**（根本的に安全ではありません）を使用したり、**DVDPlayback** framework を使用したりできます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)を確認してください。<sup>[[11]](#references)</sup>

> [!CAUTION]
> この entitlement を含めると、memory-unsafe な code language における一般的な脆弱性にアプリがさらされます。アプリにこの例外が必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

この entitlement により、強制的に終了させるため、ディスク上にある自身の executable files の**セクションを変更**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)を確認してください。<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は、アプリから基本的な security protection を取り除く極端な entitlement であり、攻撃者が検知されることなくアプリの executable code を書き換えられるようになります。可能であれば、より限定的な entitlements を優先してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この entitlement により、nullfs file system（デフォルトでは禁止）を mount できます。Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

この blogpost によると、この TCC permission は通常、次の形式で見つかります:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべての TCC permissions を要求する**ことを許可します。

### **`kTCCServicePostEvent`**

`CGEventPost()` を介して、システム全体で**合成キーボードイベントとマウスイベントを注入**できます。この permission を持つプロセスは、あらゆるアプリケーションでキーストローク、マウスクリック、スクロールイベントをシミュレートでき、事実上デスクトップの**リモートコントロール**が可能になります。

これは `kTCCServiceAccessibility` または `kTCCServiceListenEvent` と組み合わせると、入力の読み取りと**注入**の両方が可能になるため、特に危険です。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体で**すべてのキーボードおよびマウスイベントを傍受**できます（input monitoring / keylogging）。プロセスは `CGEventTap` を登録して、パスワード、クレジットカード番号、プライベートメッセージなど、あらゆるアプリケーションで入力されたすべてのキー入力をキャプチャできます。

詳細なexploit手法については、以下を参照してください。

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**ディスプレイバッファを読み取る**ことができ、secure text fieldを含むあらゆるアプリケーションのスクリーンショット取得や画面録画が可能です。OCRと組み合わせることで、画面からパスワードや機密データを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma以降では、screen capture中にメニューバーへ常時表示されるインジケーターがあります。以前のバージョンでは、screen recordingを完全に気付かれずに実行できます。

### **`kTCCServiceCamera`**

内蔵カメラまたは接続されたUSBカメラから**写真や動画をキャプチャ**できます。camera entitlementを持つバイナリへcode injectionすることで、密かに映像監視を実行できます。

### **`kTCCServiceMicrophone`**

すべての入力デバイスから**音声を録音**できます。マイクアクセスを持つバックグラウンドデーモンは、表示されるアプリケーションウィンドウなしで、継続的な周囲音声の監視を可能にします。

### **`kTCCServiceLocation`**

Wi-Fi triangulationまたはBluetooth beaconを介して、デバイスの**物理的位置**を照会できます。継続的な監視により、自宅や職場の住所、移動パターン、日々の行動パターンが明らかになります。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（氏名、メールアドレス、電話番号 — spear-phishingに有用）、**Calendar**（会議の予定、参加者リスト）、**Photos**（個人の写真、認証情報を含む可能性のあるスクリーンショット、位置情報メタデータ）にアクセスできます。

TCC permissionsを介した完全なcredential theft exploitation techniquesについては、以下を参照してください。

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions**は、通常sandboxがブロックするシステム全体のMach/XPC servicesとの通信を許可することで、App Sandboxの制限を弱めます。これは**主要なsandbox escape primitive**です。侵害されたsandboxed appは、mach-lookup exceptionsを使用して特権daemonへ到達し、そのXPC interfacesをexploitできます。
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
詳細な exploitation chain（sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape）については、以下を参照してください。

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** により、user-space driver binaries は IOKit interfaces を介して kernel と直接通信できます。DriverKit binaries は、USB、Thunderbolt、PCIe、HID devices、audio、networking などの hardware を管理します。

DriverKit binary を compromise すると、以下が可能になります。
- **Kernel attack surface**：不正な `IOConnectCallMethod` calls を介した攻撃
- **USB device spoofing**：HID injection 用の keyboard をエミュレート
- **DMA attacks**：PCIe/Thunderbolt interfaces を介した攻撃
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
詳細な IOKit/DriverKit exploitation については、以下を参照してください。

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations と `CLEAR_LV_ENTITLEMENT）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement（`com.apple.security.cs.debugger`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC の bypass](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 音楽を再生して TCC を bypass、別名 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: 「Mac 上で起きたことは、Apple の iCloud に残る?!」 - Wojciech Regula（YouTube）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple の OTA Update の悪夢: Signature Verification の bypass と Kernel の Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — JIT-compiled Code の Execution を許可する Entitlement（`com.apple.security.cs.allow-jit`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Unsigned Executable Memory の使用を許可する Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Executable Memory Protection を無効化する Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
