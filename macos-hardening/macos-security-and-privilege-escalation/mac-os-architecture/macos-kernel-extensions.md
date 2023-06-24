# macOS Kernel Extensions

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

Kernel extensions (Kexts) are **bundles** using **`.kext` extension** that are **loaded directly into the kernel space** of macOS, providing additional functionality to the core operating system.

### Requirements

Obviously, this is so powerful, it's complicated to load a kernel extension. These are the requirements of a kernel extension to be loaded:

* Going into **recovery mode** Kexts need to be **allowed to be loaded**:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

* The Kext must be **signed with a kernel code signing certificate**, which can only be granted by **Apple**. Who will be **reviewing** in detail the **company** and the **reasons** why this is needed.
* The Kext also needs to be **notarized**, Apple will be able to check it for malware.
* Then, the **root user** is the one that can load the Kext and the files inside the bundle must belong to root.
* During the loading process the bundle must be staged to a rootless protected location: /`Library/StagedExtensions` (requires entitlement `com.apple.rootless.storage.KernelExtensionManagement`)
* Finally, once trying to load it, the [**user will be prompted for confirmation**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) and if accepted, the computer must **reboot** to load it.

### Loading Process

Back in Catalina it was like this: It's interesting to note that the **verification** process occurs on **userland**. However, only applications with the entitlement **`com.apple.private.security.kext-management`** can **ask the kernel** to **load an extension:** kextcache, kextload, kextutil, kextd, syspolicyd

1. **`kextutil`** cli **starts** the verification process to load an extension
   * It'll talk to **`kextd`** sending using a Mach service
2. **`kextd`** will check several things, such as the signature
   * It'll talk to **`syspolicyd`** to check if the extension can be loaded
3. **`syspolicyd`** **asks** the **user** if the extension hasn't be loaded previously
   * **`syspolicyd`** will indicate the result to **`kextd`**
4. **`kextd`** will finally be able to indicate the **kernel to load the extension**

If kextd is not available, kextutil can perform the same checks.

## References

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
