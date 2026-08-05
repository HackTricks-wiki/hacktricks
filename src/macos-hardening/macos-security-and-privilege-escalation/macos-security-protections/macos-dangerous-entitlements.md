# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> **`com.apple`** で始まる entitlements は third-party では利用できず、Apple だけが付与できます... ただし、enterprise certificate を使用している場合は、実際には **`com.apple`** で始まる独自の entitlements を作成し、これに基づく protections を bypass できる可能性があります。

## High

### `com.apple.rootless.install.heritable`

**`com.apple.rootless.install.heritable`** entitlement により、**SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install.heritable)を確認してください。

### **`com.apple.rootless.install`**

**`com.apple.rootless.install`** entitlement により、**SIP を bypass** できます。詳細は[こちら](macos-sip.md#com.apple.rootless.install)を確認してください。

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

この entitlement により、kernel を除く**任意の** process の **task port** を取得できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.get-task-allow`

この entitlement により、**`com.apple.security.cs.debugger`** entitlement を持つ他の processes が、この entitlement を持つ binary によって実行されている process の task port を取得し、**その process に code を inject** できます。詳細は[**こちら**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html)を確認してください。

### `com.apple.security.cs.debugger`

Debugging Tool Entitlement を持つ apps は、`task_for_pid()` を呼び出して、`Get Task Allow` entitlement が `true` に設定された unsigned および third-party apps の有効な task port を取得できます。ただし、debugging tool entitlement があっても、debugger は **`Get Task Allow` entitlement を持たない** process の **task ports を取得できず**、そのため System Integrity Protection によって保護されています。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)を確認してください。

### `com.apple.security.cs.disable-library-validation`

この entitlement により、main executable と同じ Team ID で署名されているか、Apple によって署名されていなくても、frameworks、plug-ins、または libraries を **load** できます。そのため attacker は、任意の library load を悪用して code を inject できる可能性があります。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)を確認してください。

### `com.apple.private.security.clear-library-validation`

この entitlement は **`com.apple.security.cs.disable-library-validation`** と非常によく似ていますが、library validation を**直接 disable** する**代わりに**、process が runtime に **`csops` system call を呼び出して disable** できるようにします。

entitlement 名は、それを使用する `csops` operation の隣にある XNU に hardcode されています:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
`CS_OPS_CLEAR_LV`（`bsd/kern/kern_proc.c`）のkernel handlerは、このprimitiveがいかに限定的かを正確に示しています:<sup>[3]</sup>
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
つまり、この操作は次のようになります。

- **macOS 専用**です（他のすべてのプラットフォームでは `ENOTSUP`）。
- **自分自身に対してのみ**動作します（`forself == 1`）。この操作で、別のプロセスから library validation を取り除くことはできません。
- プロセスが実際に **entitlement を保持している**必要があり、プロセスに `CS_INSTALLER` のフラグが付いている場合、または subsystem root path 配下で実行されている場合は拒否されます。
- プロセスの code-signing flags から **`CS_REQUIRE_LV | CS_FORCED_LV`** をクリアします。

XNU のコメントには想定されている用途が説明されており、同時に攻撃者にとって興味深い理由も示されています。

> このオプションは、実行中のプロセスから library validation を取り除くために使用されます。これは、プログラムが信頼できない library をロードする必要がある plugin architectures で使用されます。[...] プロセスが信頼できない library をロードした後は、以降も library validation に依存することは有効ではありません。

つまり、**この entitlement を持つバイナリは dylib-injection の標的になります**。`CS_REQUIRE_LV` を解除した後に、そのバイナリ内でコードを実行する（または自分の plug-in をロードさせる）ことができれば、ホストプロセスが信頼されている操作をすべて、その権限で実行できます。

### `com.apple.security.cs.allow-dyld-environment-variables`

この entitlement により、library や code の注入に使用される可能性がある **DYLD environment variables** を**使用できます**。詳細は[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)を確認してください。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**この blog**](https://objective-see.org/blog/blog_0x4C.html) **および** [**この blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)によると、これらの entitlements により **TCC** database を**変更できます**。

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの entitlements により、ユーザーに**権限を求めることなく software をインストール**できます。これは **privilege escalation** に役立つ可能性があります。

### `com.apple.private.security.kext-management`

**kernel に kernel extension のロードを要求する**ために必要な entitlement です。

### **`com.apple.private.icloud-account-access`**

**`com.apple.private.icloud-account-access`** entitlement があれば、**iCloud tokens を提供する** **`com.apple.iCloudHelper`** XPC service と通信できます。

**iMovie** と **Garageband** がこの entitlement を持っていました。

この entitlement を利用して **iCloud tokens を取得する** exploit の詳細については、次の talk を確認してください：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これで何が可能になるのかは分かりません

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、これを使用して reboot 後に SSV-protected contents を update できる可能性があると**言及されています**。方法を知っている場合は PR を送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、これを使用して reboot 後に SSV-protected contents を update できる可能性があると**言及されています**。方法を知っている場合は PR を送ってください！

### `keychain-access-groups`

この entitlement list には、アプリケーションがアクセスできる **keychain** groups が記載されています：
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

通常 **タスクの自動化** に使用される、他のアプリケーションへイベントを送信する権限をアプリに与えます。他のアプリを制御できるため、それらのアプリに付与された権限を悪用できます。

例えば、ユーザーにパスワードを尋ねさせることができます。
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
または、**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

他の権限に加えて、**ユーザーの TCC database に書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの **`NFSHomeDirectory`** 属性を**変更**することを許可します。これによりホームフォルダーのパスが変更され、**TCC を bypass**できます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリバンドル（app.app 内）のファイルを変更することを許可します。これはデフォルトでは**禁止**されています。

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つプロセスは、 _システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_ で確認できます。

### `kTCCServiceAccessibility`

このプロセスは、**macOS のアクセシビリティ機能を abuse**できるようになります。つまり、例えばキーストロークを送信できます。そのため、この権限を使用して Finder などのアプリを制御するアクセスを要求し、ダイアログを承認できます。

## Trustcache/CDhash 関連の entitlements

Apple バイナリの downgrade されたバージョンの実行を防止する Trustcache/CDhash protections を bypass するために使用できる entitlements がいくつかあります。

## Medium

### `com.apple.security.cs.allow-jit`

この entitlement により、`mmap()` system function に `MAP_JIT` flag を渡すことで、**書き込み可能かつ実行可能なメモリを作成**できます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)を確認してください。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この entitlement により、**C code を override または patch**したり、長い間 deprecated になっている **`NSCreateObjectFileImageFromMemory`**（根本的に insecure）を使用したり、**DVDPlayback** framework を使用したりできます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)を確認してください。

> [!CAUTION]
> この entitlement を含めると、memory-unsafe な code language における一般的な vulnerabilities に対してアプリが expose されます。アプリにこの exception が必要かどうかを慎重に検討してください。

### `com.apple.security.cs.disable-executable-page-protection`

この entitlement により、**自身の executable files のセクションをディスク上で変更**して、強制的に終了させることができます。詳細については[**こちら**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)を確認してください。

> [!CAUTION]
> Disable Executable Memory Protection Entitlement は、アプリから基本的な security protection を削除する extreme な entitlement です。これにより、攻撃者が検知されることなくアプリの executable code を書き換えられるようになります。可能であれば、より限定的な entitlements を使用してください。

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この entitlement により、nullfs file system を mount できます（デフォルトでは禁止されています）。Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

この blogpost によると、この TCC permission は通常、次の形式で見つかります：
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに **すべての TCC permissions を要求することを許可します**。

### **`kTCCServicePostEvent`**

`CGEventPost()` を介して、システム全体に **synthetic keyboard and mouse events を inject** することを許可します。この permission を持つプロセスは、あらゆるアプリケーションで keystrokes、mouse clicks、scroll events を simulate でき、事実上、デスクトップを **remote control** できます。

これは、`kTCCServiceAccessibility` または `kTCCServiceListenEvent` と組み合わせると特に危険です。入力の読み取りと **injecting input** の両方が可能になるためです。
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

システム全体で**すべてのキーボードおよびマウスイベントを傍受**できます（input monitoring / keylogging）。プロセスは `CGEventTap` を登録して、パスワード、クレジットカード番号、プライベートメッセージなど、あらゆるアプリケーションで入力されたすべてのキーストロークを取得できます。

詳細なexploit手法については、以下を参照してください。

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

**ディスプレイバッファの読み取り**、つまりsecure text fieldを含む任意のアプリケーションのスクリーンショット取得や画面動画の録画が可能です。OCRと組み合わせることで、画面上のパスワードや機密データを自動的に抽出できます。

> [!WARNING]
> macOS Sonoma以降では、screen captureを実行するとメニューバーに常時表示されるインジケーターが表示されます。旧バージョンでは、screen recordingを完全に無表示で実行できます。

### **`kTCCServiceCamera`**

内蔵カメラまたは接続されたUSBカメラから写真や動画を**取得**できます。camera entitlementを持つバイナリにcode injectionすると、無断で映像監視を実行できます。

### **`kTCCServiceMicrophone`**

すべての入力デバイスから音声を**録音**できます。マイクへのアクセス権を持つバックグラウンドdaemonは、アプリケーションウィンドウを表示せずに、継続的な周囲音声の監視を可能にします。

### **`kTCCServiceLocation`**

Wi-Fi triangulationまたはBluetooth beaconを介して、デバイスの**物理的な位置情報**を照会できます。継続的な監視により、自宅や職場の住所、移動パターン、日々の行動パターンが明らかになります。

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

**Contacts**（氏名、メールアドレス、電話番号 - spear-phishingに有用）、**Calendar**（会議の予定、参加者リスト）、**Photos**（個人写真、credentialが含まれている可能性のあるスクリーンショット、位置情報メタデータ）へのアクセスが可能です。

TCC permissionsを介したcredential theftの完全なexploit手法については、以下を参照してください。

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## SandboxおよびCode Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandboxのtemporary exception**は、通常Sandboxによってブロックされるシステム全体のMach/XPC serviceとの通信を許可することで、App Sandboxの制限を弱めます。これは**主要なSandbox escape primitive**です。侵害されたSandbox appは、mach-lookup exceptionを使用してprivileged daemonに到達し、そのXPC interfaceをexploitできます。
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
- **kernel attack surface**: 不正な `IOConnectCallMethod` calls を介した攻撃
- **USB device spoofing**（HID injection 用に keyboard をエミュレート）
- **DMA attacks**: PCIe/Thunderbolt interfaces を介した攻撃
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

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
