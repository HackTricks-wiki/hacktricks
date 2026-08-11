# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements は、OS が署名済みコードに付与する機能と security exception を宣言します。以下では、offensive review で特に有用なものに焦点を当てます。<sup>[[13]](#references)</sup>

> [!WARNING]
> **`com.apple`** で始まる entitlements は third-party では利用できず、Apple だけが付与できます。ただし、enterprise certificate を使用している場合は、実際には **`com.apple`** で始まる独自の entitlements を作成し、これに基づく protection を bypass できる可能性があります。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement により、プロセスは **SIP を bypass** できます。詳しくは [こちら](macos-sip.md#com.apple.rootless.install.heritable) を確認してください。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement により、プロセスは **SIP を bypass** できます。詳しくは [こちら](macos-sip.md#com.apple.rootless.install) を確認してください。

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

この entitlement により、プロセスは kernel 以外の **任意の**プロセスの **task port** を取得できます。詳しくは [**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html) を確認してください。

### `com.apple.security.get-task-allow`

この entitlement により、**`com.apple.security.cs.debugger`** entitlement を持つ他のプロセスは、この entitlement を持つ binary が実行するプロセスの task port を取得し、**そのプロセスに code を inject** できます。詳しくは [**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html) を確認してください。

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement を持つ app は、`task_for_pid()` を呼び出して、`Get Task Allow` entitlement が `true` に設定された unsigned app および third-party app の有効な task port を取得できます。ただし、debugging tool entitlement があっても、debugger は **`Get Task Allow` entitlement を持たず**、そのため System Integrity Protection によって保護されているプロセスの **task port を取得できません**。詳しくは [**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger) を確認してください。<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

この entitlement により、application は、Apple による署名、または main executable と同じ Team ID による署名を要求せずに **framework、plug-in、library を load** できます。そのため、attacker は arbitrary library load を悪用して code を inject できる可能性があります。詳しくは [**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation) を確認してください。<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

この entitlement は **`com.apple.security.cs.disable-library-validation`** と非常によく似ていますが、**library validation を直接 disable** する代わりに、プロセスが runtime で **`csops` system call を呼び出して disable** できるようにします。

entitlement 名は、それを使用する `csops` operation の隣にある XNU に hardcode されています。<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`（`bsd/kern/kern_proc.c`）の kernel handler は、この primitive がいかに限定的なものかを正確に示しています。<sup>[[2]](#references)</sup>
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
その操作は次のとおりです。

- **macOS-only**（他のすべてのプラットフォームでは `ENOTSUP`）。
- **自分自身に対してのみ**動作します（`forself == 1`）。これを使って別のプロセスから library validation を削除することはできません。
- プロセスが実際に **entitlement を保持している**必要があり、プロセスに `CS_INSTALLER` のフラグが設定されている場合、または subsystem root path 配下で実行されている場合は拒否されます。
- プロセスの code-signing flags から **`CS_REQUIRE_LV | CS_FORCED_LV`** をクリアします。

XNU のコメントには想定されている用途と、これが attacker にとって興味深い理由が説明されています。

> このオプションは、実行中のプロセスから library validation を削除するために使用されます。プログラムが untrusted libraries を load する必要がある plugin architectures で使用されます。[...] プロセスが untrusted library を load した後は、将来も library validation に依存することは有効ではありません。

つまり、**この entitlement を持つ binary はすべて dylib-injection target になります**。`CS_REQUIRE_LV` を削除した後に、その内部で code を実行する（または plug-in を load させる）ことができれば、host process が trusted to do するあらゆる操作を引き継げます。

### `com.apple.security.cs.allow-dyld-environment-variables`

この entitlement により、libraries や code の inject に使用される可能性がある **DYLD environment variables** を **use** できます。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)を確認してください。<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**この blog によると**](https://objective-see.org/blog/blog_0x4C.html)、また[**この blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの entitlements により、プロセスは **TCC** database を **modify** できます。<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** および **`system.install.apple-software.standard-user`**

これらの Authorization Services rights は、Apple-provided software の installation を管理します。これらを取得する entitlement を持つプロセスは、通常の authorization flow を bypass でき、**privilege escalation** に役立つ可能性があります。<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

**kernel に kernel extension の load を要求する**ために必要な entitlement。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement により、**iCloud tokens を provide する** **`com.apple.iCloudHelper`** XPC service と communicate できます。

**iMovie** と **Garageband** にはこの entitlement がありました。

この entitlement を利用して **icloud tokens を get する** exploit の詳細については、次の talk を確認してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これで何ができるのかは不明です

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、この entitlement を使用して、reboot 後に SSV-protected contents を update できる可能性があると述べています。方法を知っている場合は、PR を送ってください！<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**同じ report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、sealed snapshot の作成を使用して、reboot 後に SSV-protected contents を update できる可能性があると述べています。方法を知っている場合は、PR を送ってください！<sup>[[9]](#references)</sup>

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

**Full Disk Access** 権限を付与します。これは、TCCで取得できる最も強力な権限の1つです。

### **`kTCCServiceAppleEvents`**

一般的に **タスクの自動化** に使用される他のアプリケーションへ、アプリがイベントを送信できるようにします。他のアプリを制御することで、それらのアプリに付与された権限を悪用できます。

例えば、ユーザーにパスワードを尋ねさせることができます：
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
または、**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

これには、特に、**ユーザーの TCC database に書き込む**権限が含まれます。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの **`NFSHomeDirectory`** 属性を**変更**できます。これによりユーザーのホームフォルダーのパスが変更され、結果として **TCC を bypass** できます。

### **`kTCCServiceSystemPolicyAppBundles`**

app bundle（app.app 内）のファイルを変更できます。これはデフォルトでは**許可されていません**。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

_System Settings_ > _Privacy & Security_ > _App Management_ で、このアクセス権を持つ対象を確認できます。

### `kTCCServiceAccessibility`

このプロセスは、**macOS のアクセシビリティ機能を abuse** できるようになります。つまり、たとえばキーストロークを送信できます。そのため、Finder などの app を制御するアクセス権を要求し、この permission を使ってダイアログを承認できます。

## Trustcache/CDhash 関連の entitlements

Apple バイナリの downgrade されたバージョンの実行を防止する Trustcache/CDhash protections を bypass するために使用できる entitlements がいくつかあります。

## Medium

### `com.apple.security.cs.allow-jit`

この entitlement により、`mmap()` system function に `MAP_JIT` flag を渡して、**書き込み可能かつ実行可能な memory を作成**できます。詳しくは[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)を確認してください。<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

この entitlement により、**C code を override または patch**したり、長期間 deprecated となっている **`NSCreateObjectFileImageFromMemory`**（基本的に insecure）を使用したり、**DVDPlayback** framework を使用したりできます。詳しくは[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)を確認してください。<sup>[[11]](#references)</sup>

> [!CAUTION]
> この entitlement を含めると、memory-unsafe な code language における一般的な vulnerabilities に app がさらされます。この exception が app に必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

この entitlement により、強制的に終了させるために、ディスク上の自身の executable files の**セクションを変更**できます。詳しくは[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)を確認してください。<sup>[[12]](#references)</sup>

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は、app から基本的な security protection を取り除く extreme な entitlement です。これにより、attacker が検知されることなく app の executable code を書き換えられるようになります。可能であれば、より限定的な entitlements を優先してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この entitlement により、nullfs file system を mount できます（デフォルトでは禁止されています）。Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master)。

### `kTCCServiceAll`

この blogpost によると、この TCC permission は通常、次の形式で見つかります。
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべての TCC permissions を要求することを許可します**。

### **`kTCCServicePostEvent`**

`CGEventPost()` を介して、システム全体に**合成キーボードイベントおよびマウスイベントを注入することを許可します**。この permission を持つプロセスは、任意のアプリケーションでキーストローク、マウスクリック、スクロールイベントをシミュレートできます。つまり、デスクトップを**リモート操作**できます。

これは `kTCCServiceAccessibility` または `kTCCServiceListenEvent` と組み合わせると特に危険です。入力の読み取りと**注入**の両方が可能になるためです。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体で**すべてのキーボードおよびマウスイベントを intercepting**（input monitoring / keylogging）できます。プロセスは `CGEventTap` を登録して、あらゆるアプリケーションで入力されたすべてのキーストロークを取得できます。これには、パスワード、クレジットカード番号、プライベートメッセージなども含まれます。

詳細な exploitation techniques については、以下を参照してください。

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**ディスプレイバッファを読み取る**ことができ、secure text fields を含むあらゆるアプリケーションのスクリーンショット取得や画面動画の recording が可能です。OCR と組み合わせることで、画面上のパスワードや機密データを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma 以降では、screen capture の実行中にメニューバーへ永続的なインジケーターが表示されます。旧バージョンでは、screen recording を完全に無音で実行できます。

### **`kTCCServiceCamera`**

内蔵カメラまたは接続された USB カメラから写真や動画を**capture**できます。camera entitlement を持つバイナリへ code injection することで、気付かれない visual surveillance が可能になります。

### **`kTCCServiceMicrophone`**

すべての input devices から音声を**recording**できます。マイクアクセスを持つ background daemons により、表示されるアプリケーションウィンドウなしで、永続的な周囲音声の surveillance が可能になります。

### **`kTCCServiceLocation`**

Wi-Fi triangulation または Bluetooth beacons を介して、デバイスの**物理的な location**を問い合わせることができます。継続的な monitoring により、自宅や職場の住所、移動パターン、日常の行動パターンが明らかになります。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（名前、メールアドレス、電話番号 — spear-phishing に有用）、**Calendar**（会議の予定、参加者リスト）、**Photos**（個人の写真、credentials が含まれる可能性のあるスクリーンショット、location metadata）へのアクセスを提供します。

TCC permissions を介した完全な credential theft exploitation techniques については、以下を参照してください。

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox と Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** は、通常 Sandbox がブロックするシステム全体の Mach/XPC services との通信を許可することで、App Sandbox を弱体化させます。これは**主要な sandbox escape primitive**です。侵害された sandboxed app は mach-lookup exceptions を使用して privileged daemons に到達し、それらの XPC interfaces を exploit できます。
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

**DriverKit entitlements** は、user-space driver binary が IOKit interfaces を介して kernel と直接通信できるようにします。DriverKit binary は、USB、Thunderbolt、PCIe、HID devices、audio、networking などの hardware を管理します。

DriverKit binary を compromise すると、以下が可能になります。
- **Kernel attack surface**（不正な `IOConnectCallMethod` calls 経由）
- **USB device spoofing**（HID injection 用に keyboard をエミュレート）
- **DMA attacks**（PCIe/Thunderbolt interfaces 経由）
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

- [1] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作および `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement（`com.apple.security.cs.debugger`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: TCC の bypass](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — 音楽を再生して TCC を bypass、別名 CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: 「Mac で起きたことは、Apple の iCloud に残る!?」 - Wojciech Regula（YouTube）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Apple の OTA Update の悪夢：Signature Verification を bypass して Kernel を pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement（`com.apple.security.cs.allow-jit`）](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Authorization Services Programming Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
