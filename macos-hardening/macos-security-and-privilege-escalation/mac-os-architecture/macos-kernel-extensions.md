# macOS Kernel Extensions

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

## Basic Information

Kernel extensions (Kexts) are **packages** with a **`.kext`** extension that are **loaded directly into the macOS kernel space**, providing additional functionality to the main operating system.

### Requirements

Obviously, this is so powerful that it is **complicated to load a kernel extension**. These are the **requirements** that a kernel extension must meet to be loaded:

* When **entering recovery mode**, kernel **extensions must be allowed** to be loaded:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* The kernel extension must be **signed with a kernel code signing certificate**, which can only be **granted by Apple**. Who will review in detail the company and the reasons why it is needed.
* The kernel extension must also be **notarized**, Apple will be able to check it for malware.
* Then, the **root** user is the one who can **load the kernel extension** and the files inside the package must **belong to root**.
* During the upload process, the package must be prepared in a **protected non-root location**: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
* Finally, when attempting to load it, the user will [**receive a confirmation request**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) and, if accepted, the computer must be **restarted** to load it.

### Loading process

In Catalina it was like this: It is interesting to note that the **verification** process occurs in **userland**. However, only applications with the **`com.apple.private.security.kext-management`** grant can **request the kernel to load an extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **starts** the **verification** process for loading an extension
   * It will talk to **`kextd`** by sending using a **Mach service**.
2. **`kextd`** will check several things, such as the **signature**
   * It will talk to **`syspolicyd`** to **check** if the extension can be **loaded**.
3. **`syspolicyd`** will **prompt** the **user** if the extension has not been previously loaded.
   * **`syspolicyd`** will report the result to **`kextd`**
4. **`kextd`** will finally be able to **tell the kernel to load** the extension

If **`kextd`** is not available, **`kextutil`** can perform the same checks.

## Referencias

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
