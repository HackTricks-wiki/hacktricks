# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements declare capabilities and security exceptions that the operating system grants to signed code. The entries below focus on those that are especially useful during offensive review.<sup>[[13]](#references)</sup>

> [!WARNING]
> Note that entitlements starting with **`com.apple`** are not available to third-parties, only Apple can grant them... Or if you are using an enterprise certificate you could create your own entitlements starting with **`com.apple`** actually and bypass protections based on this.

## High

### `com.apple.rootless.install.heritable`

The entitlement **`com.apple.rootless.install.heritable`** allows a process to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

The entitlement **`com.apple.rootless.install`** allows a process to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

This entitlement allows a process to get the **task port for any** process except the kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

This entitlement allows other processes with the **`com.apple.security.cs.debugger`** entitlement to get the task port of the process run by the binary with this entitlement and **inject code on it**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps with the Debugging Tool Entitlement can call `task_for_pid()` to retrieve a valid task port for unsigned and third-party apps with the `Get Task Allow` entitlement set to `true`. However, even with the debugging tool entitlement, a debugger **can’t get the task ports** of processes that **don’t have the `Get Task Allow` entitlement**, and that are therefore protected by System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

This entitlement allows an application to **load frameworks, plug-ins, or libraries without requiring them to be signed by Apple or with the same Team ID** as the main executable, so an attacker could abuse an arbitrary library load to inject code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

This entitlement is very similar to **`com.apple.security.cs.disable-library-validation`** but **instead** of **directly disabling** library validation, it allows the process to **call a `csops` system call to disable it** at runtime.

The entitlement name is hardcoded in XNU next to the `csops` operation that consumes it:<sup>[[1]](#references)</sup>

```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```

The kernel handler for `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) shows exactly how narrow the primitive is:<sup>[[2]](#references)</sup>

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

- Is **macOS-only** (`ENOTSUP` on every other platform).
- Only works on **itself** (`forself == 1`) — you cannot strip library validation off another process with it.
- Requires the process to actually **hold the entitlement**, and refuses if the process is flagged `CS_INSTALLER` or is running under a subsystem root path.
- Clears **`CS_REQUIRE_LV | CS_FORCED_LV`** from the process' code-signing flags.

The XNU comment explains the intended use case, and also why it is interesting to an attacker:

> This option is used to remove library validation from a running process. This is used in plugin architectures when a program needs to load untrusted libraries. [...] Once a process has loaded the untrusted library, relying on library validation in the future will not be effective.

In other words, **any binary carrying this entitlement is a dylib-injection target**: get code running inside it (or convince it to load your plug-in) after it has dropped `CS_REQUIRE_LV`, and you inherit whatever the host process is trusted to do.

### `com.apple.security.cs.allow-dyld-environment-variables`

This entitlement allows to **use DYLD environment variables** that could be used to inject libraries and code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), these entitlements allow a process to **modify** the **TCC** database.<sup>[[6]](#references)[[7]](#references)</sup>

### Authorization rights **`system.install.apple-software`** and **`system.install.apple-software.standard-user`**

These Authorization Services rights govern the installation of Apple-provided software. A process entitled to obtain them may bypass the usual authorization flow, which can be helpful for **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement needed to ask the **kernel to load a kernel extension**.

### **`com.apple.private.icloud-account-access`**

The entitlement **`com.apple.private.icloud-account-access`** makes it possible to communicate with the **`com.apple.iCloudHelper`** XPC service, which will **provide iCloud tokens**.

**iMovie** and **Garageband** had this entitlement.

For more **information** about the exploit to **get icloud tokens** from that entitlement check the talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: I don't know what this allows to do

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**This report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) mentions that this entitlement could be used to update SSV-protected contents after a reboot. If you know how, please send a PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**The same report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) mentions that creating a sealed snapshot could be used to update SSV-protected contents after a reboot. If you know how, please send a PR!<sup>[[9]](#references)</sup>

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

Gives **Full Disk Access** permissions, one of the TCC highest permissions you can have.

### **`kTCCServiceAppleEvents`**

Allows the app to send events to other applications that are commonly used for **automating tasks**. Controlling other apps, it can abuse the permissions granted to these other apps.

Like making them ask the user for its password:

```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```

Or making them perform **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Allows, among other permissions, to **write the users TCC database**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Allows to **change** the **`NFSHomeDirectory`** attribute of a user that changes his home folder path and therefore allows to **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Allow to modify files inside apps bundle (inside app.app), which is **disallowed by default**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

It's possible to check who has this access in _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

The process will be able to **abuse the macOS accessibility features**, Which means that for example he will be able to press keystrokes. SO he could request access to control an app like Finder and approve the dialog with this permission.

## Trustcache/CDhash related entitlements

There are some entitlements that could be used to bypass Trustcache/CDhash protections, which prevent the execution of downgraded versions of Apple binaries.

## Medium

### `com.apple.security.cs.allow-jit`

This entitlement allows a process to **create memory that is writable and executable** by passing the `MAP_JIT` flag to the `mmap()` system function. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

This entitlement allows to **override or patch C code**, use the long-deprecated **`NSCreateObjectFileImageFromMemory`** (which is fundamentally insecure), or use the **DVDPlayback** framework. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Including this entitlement exposes your app to common vulnerabilities in memory-unsafe code languages. Carefully consider whether your app needs this exception.

### `com.apple.security.cs.disable-executable-page-protection`

This entitlement allows to **modify sections of its own executable files** on disk to forcefully exit. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement is an extreme entitlement that removes a fundamental security protection from your app, making it possible for an attacker to rewrite your app’s executable code without detection. Prefer narrower entitlements if possible.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

This entitlement allows to mount a nullfs file system (forbidden by default). Tool: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

According to this blogpost, this TCC permission usually found in the form:

```
[Key] com.apple.private.tcc.allow-prompting
	[Value]
		[Array]
			[String] kTCCServiceAll
```

Allow the process to **ask for all the TCC permissions**.

### **`kTCCServicePostEvent`**

Allows **injecting synthetic keyboard and mouse events** system-wide via `CGEventPost()`. A process with this permission can simulate keystrokes, mouse clicks, and scroll events in any application — effectively providing **remote control** of the desktop.

This is especially dangerous combined with `kTCCServiceAccessibility` or `kTCCServiceListenEvent`, as it allows both reading AND injecting input.

```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```

### **`kTCCServiceListenEvent`**

Allows **intercepting all keyboard and mouse events** system-wide (input monitoring / keylogging). A process can register a `CGEventTap` to capture every keystroke typed in any application, including passwords, credit card numbers, and private messages.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Allows **reading the display buffer** — taking screenshots and recording screen video of any application, including secure text fields. Combined with OCR, this can automatically extract passwords and sensitive data from the screen.

> [!WARNING]
> Starting with macOS Sonoma, screen capture shows a persistent menu bar indicator. On older versions, screen recording can be completely silent.

### **`kTCCServiceCamera`**

Allows **capturing photos and video** from the built-in camera or connected USB cameras. Code injection into a camera-entitled binary enables silent visual surveillance.

### **`kTCCServiceMicrophone`**

Allows **recording audio** from all input devices. Background daemons with mic access provide persistent ambient audio surveillance with no visible application window.

### **`kTCCServiceLocation`**

Allows querying the device's **physical location** via Wi-Fi triangulation or Bluetooth beacons. Continuous monitoring reveals home/work addresses, travel patterns, and daily routines.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Access to **Contacts** (names, emails, phones — useful for spear-phishing), **Calendar** (meeting schedules, attendee lists), and **Photos** (personal photos, screenshots that may contain credentials, location metadata).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** weaken the App Sandbox by allowing communication with system-wide Mach/XPC services that the sandbox normally blocks. This is the **primary sandbox escape primitive** — a compromised sandboxed app can use mach-lookup exceptions to reach privileged daemons and exploit their XPC interfaces.

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

**DriverKit entitlements** allow user-space driver binaries to communicate directly with the kernel through IOKit interfaces. DriverKit binaries manage hardware: USB, Thunderbolt, PCIe, HID devices, audio, and networking.

Compromising a DriverKit binary enables:
- **Kernel attack surface** via malformed `IOConnectCallMethod` calls
- **USB device spoofing** (emulate keyboard for HID injection)
- **DMA attacks** through PCIe/Thunderbolt interfaces

```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```

For detailed IOKit/DriverKit exploitation, see:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Debugging Tool Entitlement (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Disable Library Validation Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Allow DYLD Environment Variables Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Play the music and bypass TCC aka CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [The Nightmare of Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Allow Execution of JIT-compiled Code Entitlement (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Allow Unsigned Executable Memory Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Disable Executable Memory Protection Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Authorization Services Programming Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
