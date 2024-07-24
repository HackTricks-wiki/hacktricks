# macOS Dangerous Entitlements & TCC perms

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="warning" %}
Note that entitlements starting with **`com.apple`** are not available to third-parties, only Apple can grant them.
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

The entitlement **`com.apple.rootless.install.heritable`** allows to **bypass SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

The entitlement **`com.apple.rootless.install`** allows to **bypass SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

This entitlement allows to get the **task port for any** process, except the kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

This entitlement allows other processes with the **`com.apple.security.cs.debugger`** entitlement to get the task port of the process run by the binary with this entitlement and **inject code on it**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Apps with the Debugging Tool Entitlement can call `task_for_pid()` to retrieve a valid task port for unsigned and third-party apps with the `Get Task Allow` entitlement set to `true`. However, even with the debugging tool entitlement, a debugger **can’t get the task ports** of processes that **don’t have the `Get Task Allow` entitlement**, and that are therefore protected by System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

This entitlement allows to **load frameworks, plug-ins, or libraries without being either signed by Apple or signed with the same Team ID** as the main executable, so an attacker could abuse some arbitrary library load to inject code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

This entitlement is very similar to **`com.apple.security.cs.disable-library-validation`** but **instead** of **directly disabling** library validation, it allows the process to **call a `csops` system call to disable it**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

This entitlement allows to **use DYLD environment variables** that could be used to inject libraries and code. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog\_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), these entitlements allows to **modify** the **TCC** database.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

These entitlements allows to **install software without asking for permissions** to the user, which can be helpful for a **privilege escalation**.

### `com.apple.private.security.kext-management`

Entitlement needed to ask the **kernel to load a kernel extension**.

### **`com.apple.private.icloud-account-access`**

The entitlement **`com.apple.private.icloud-account-access`** it's possible to communicate with **`com.apple.iCloudHelper`** XPC service which will **provide iCloud tokens**.

**iMovie** and **Garageband** had this entitlement.

For more **information** about the exploit to **get icloud tokens** from that entitlement check the talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

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

Like making them ask the user for its password:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Or making them perform **arbitrary actions**.

### **`kTCCServiceEndpointSecurityClient`**

Allows, among other permissions, to **write the users TCC database**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Allows to **change** the **`NFSHomeDirectory`** attribute of a user that changes his home folder path and therefore allows to **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Allow to modify files inside apps bundle (inside app.app), which is **disallowed by default**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

It's possible to check who has this access in _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

The process will be able to **abuse the macOS accessibility features**, Which means that for example he will be able to press keystrokes. SO he could request access to control an app like Finder and approve the dialog with this permission.

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

### `com.apple.private.nullfs_allow`

This entitlement allows to mount a nullfs file system (forbidden by default). Tool: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

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
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
