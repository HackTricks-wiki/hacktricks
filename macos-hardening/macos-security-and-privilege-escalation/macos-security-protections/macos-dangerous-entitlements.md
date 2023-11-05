# macOS Dangerous Entitlements & TCC perms

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
Note that entitlements starting with **`com.apple`** are not available to third-parties, only Apple can grant them.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

The entitlement **`com.apple.rootless.install.heritable`** allows to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

The entitlement **`com.apple.rootless.install`** allows to **bypass SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

This entitlement allows to get the **task port for any** process, except the kernel. Check [**this for more info**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

This entitlement allows other processes with the **`com.apple.security.cs.debugger`** entitlement to get the task port of the process run by the binary with this entitlement and **inject code on it**. Check [**this for more info**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps with the Debugging Tool Entitlement can call `task_for_pid()` to retrieve a valid task port for unsigned and third-party apps with the `Get Task Allow` entitlement set to `true`. However, even with the debugging tool entitlement, a debugger **can’t get the task ports** of processes that **don’t have the `Get Task Allow` entitlement**, and that are therefore protected by System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

This entitlement allows to **load frameworks, plug-ins, or libraries without being either signed by Apple or signed with the same Team ID** as the main executable, so an attacker could abuse some arbitrary library load to inject code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

This entitlement is very similar to **`com.apple.security.cs.disable-library-validation`** but **instead** of **directly disabling** library validation, it allows the process to **call a `csops` system call to disable it**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

This entitlement allows to **use DYLD environment variables** that could be used to inject libraries and code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` and `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog\_0x4C.html), these entitlements allows to **modify** the **TCC** database.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

These entitlements allows to **install software without asking for permissions** to the user, which can be helpful for a **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement needed to ask the **kernel to load a kernel extension**.

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

Gives **Full Disk Access** permissions, one of the TCC highest permissions you can have.

### **`kTCCServiceAppleEvents`**

Allows the app to send events to other applications that are commonly used for **automating tasks**. Controlling other apps, it can abuse the permissions granted to these other apps.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Allows to **change** the **`NFSHomeDirectory`** attribute of a user that changes his home folder and therefore allows to **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Allow to modify files inside apps bundle (inside app.app), which is **disallowed by default**.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

## Medium

### `com.apple.security.cs.allow-jit`

This entitlement allows to **create memory that is writable and executable** by passing the `MAP_JIT` flag to the `mmap()` system function. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

This entitlement allows to **override or patch C code**, use the long-deprecated **`NSCreateObjectFileImageFromMemory`** (which is fundamentally insecure), or use the **DVDPlayback** framework. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Including this entitlement exposes your app to common vulnerabilities in memory-unsafe code languages. Carefully consider whether your app needs this exception.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

This entitlement allows to **modify sections of its own executable files** on disk to forcefully exit. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
The Disable Executable Memory Protection Entitlement is an extreme entitlement that removes a fundamental security protection from your app, making it possible for an attacker to rewrite your app’s executable code without detection. Prefer narrower entitlements if possible.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
