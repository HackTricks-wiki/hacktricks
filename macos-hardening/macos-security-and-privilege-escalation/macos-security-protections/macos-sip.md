# macOS SIP

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Basic Information**

**System Integrity Protection (SIP)** in macOS is a mechanism designed to prevent even the most privileged users from making unauthorized changes to key system folders. This feature plays a crucial role in maintaining the integrity of the system by restricting actions like adding, modifying, or deleting files in protected areas. The primary folders shielded by SIP include:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

The rules that govern SIP's behavior are defined in the configuration file located at **`/System/Library/Sandbox/rootless.conf`**. Within this file, paths that are prefixed with an asterisk (\*) are denoted as exceptions to the otherwise stringent SIP restrictions.

Consider the example below:

```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```

This snippet implies that while SIP generally secures the **`/usr`** directory, there are specific subdirectories (`/usr/libexec/cups`, `/usr/local`, and `/usr/share/man`) where modifications are permissible, as indicated by the asterisk (\*) preceding their paths.

To verify whether a directory or file is protected by SIP, you can use the **`ls -lOd`** command to check for the presence of the **`restricted`** or **`sunlnk`** flag. For example:

```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```

In this case, the **`sunlnk`** flag signifies that the `/usr/libexec/cups` directory itself **cannot be deleted**, though files within it can be created, modified, or deleted.

On the other hand:

```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```

Here, the **`restricted`** flag indicates that the `/usr/libexec` directory is protected by SIP. In a SIP-protected directory, files cannot be created, modified, or deleted.

Moreover, if a file contains the attribute **`com.apple.rootless`** extended **attribute**, that file will also be **protected by SIP**.

{% hint style="success" %}
Note that **Sandbox** hook **`hook_vnode_check_setextattr`** prevents any attempt to modify the extended attribute **`com.apple.rootless`.**
{% endhint %}

**SIP also limits other root actions** like:

* Loading untrusted kernel extensions
* Getting task-ports for Apple-signed processes
* Modifying NVRAM variables
* Allowing kernel debugging

Options are maintained in nvram variable as a bitflag (`csr-active-config` on Intel and `lp-sip0` is read from the booted Device Tree for ARM). You can find the flags in the XNU source code in `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Status

You can check if SIP is enabled on your system with the following command:

```bash
csrutil status
```

If you need to disable SIP, you must restart your computer in recovery mode (by pressing Command+R during startup), then execute the following command:

```bash
csrutil disable
```

If you wish to keep SIP enabled but remove debugging protections, you can do so with:

```bash
csrutil enable --without debug
```

### Other Restrictions

* **Disallows loading of unsigned kernel extensions** (kexts), ensuring only verified extensions interact with the system kernel.
* **Prevents the debugging** of macOS system processes, safeguarding core system components from unauthorized access and modification.
* **Inhibits tools** like dtrace from inspecting system processes, further protecting the integrity of the system's operation.

[**Learn more about SIP info in this talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP related Entitlements**

* `com.apple.rootless.xpc.bootstrap`: Control launchd
* `com.apple.rootless.install[.heritable]`: Access file system
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: Manage UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
* `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
* `com.apple.rootless.restricted-block-devices`: Access to raw block devices
* `com.apple.rootless.internal.installer-equivalent`: Unfettered filesystem access
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: Full access to NVRAM
* `com.apple.rootless.storage.label`: Modify files restricted by com.apple.rootless xattr with the corresponding label
* `com.apple.rootless.volume.VM.label`: Maintain VM swap on volume

## SIP Bypasses

Bypassing SIP enables an attacker to:

* **Access User Data**: Read sensitive user data like mail, messages, and Safari history from all user accounts.
* **TCC Bypass**: Directly manipulate the TCC (Transparency, Consent, and Control) database to grant unauthorized access to the webcam, microphone, and other resources.
* **Establish Persistence**: Place malware in SIP-protected locations, making it resistant to removal, even by root privileges. This also includes the potential to tamper with the Malware Removal Tool (MRT).
* **Load Kernel Extensions**: Although there are additional safeguards, bypassing SIP simplifies the process of loading unsigned kernel extensions.

### Installer Packages

**Installer packages signed with Apple's certificate** can bypass its protections. This means that even packages signed by standard developers will be blocked if they attempt to modify SIP-protected directories.

### Inexistent SIP file

One potential loophole is that if a file is specified in **`rootless.conf` but does not currently exist**, it can be created. Malware could exploit this to **establish persistence** on the system. For example, a malicious program could create a .plist file in `/System/Library/LaunchDaemons` if it is listed in `rootless.conf` but not present.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
The entitlement **`com.apple.rootless.install.heritable`** allows to bypass SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

It was discovered that it was possible to **swap the installer package after the system verified its code** signature and then, the system would install the malicious package instead of the original. As these actions were performed by **`system_installd`**, it would allow to bypass SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

If a package was installed from a mounted image or external drive the **installer** would **execute** the binary from **that file system** (instead from a SIP protected location), making **`system_installd`** execute an arbitrary binary.

#### CVE-2021-30892 - Shrootless

[**Researchers from this blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) discovered a vulnerability in macOS's System Integrity Protection (SIP) mechanism, dubbed the 'Shrootless' vulnerability. This vulnerability centers around the **`system_installd`** daemon, which has an entitlement, **`com.apple.rootless.install.heritable`**, that allows any of its child processes to bypass SIP's file system restrictions.

**`system_installd`** daemon will install packages that have been signed by **Apple**.

Researchers found that during the installation of an Apple-signed package (.pkg file), **`system_installd`** **runs** any **post-install** scripts included in the package. These scripts are executed by the default shell, **`zsh`**, which automatically **runs** commands from the **`/etc/zshenv`** file, if it exists, even in non-interactive mode. This behaviour could be exploited by attackers: by creating a malicious `/etc/zshenv` file and waiting for **`system_installd` to invoke `zsh`**, they could perform arbitrary operations on the device.

Moreover, it was discovered that **`/etc/zshenv` could be used as a general attack technique**, not just for a SIP bypass. Each user profile has a `~/.zshenv` file, which behaves the same way as `/etc/zshenv` but doesn't require root permissions. This file could be used as a persistence mechanism, triggering every time `zsh` starts, or as an elevation of privilege mechanism. If an admin user elevates to root using `sudo -s` or `sudo <command>`, the `~/.zshenv` file would be triggered, effectively elevating to root.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) it was discovered that the same **`system_installd`** process could still be abused because it was putting the **post-install script inside a random named folder protected by SIP inside `/tmp`**. The thing is that **`/tmp` itself isn't protected by SIP**, so it was possible to **mount** a **virtual image on it**, then the **installer** would put in there the **post-install script**, **unmount** the virtual image, **recreate** all the **folders** and **add** the **post installation** script with the **payload** to execute.

#### [fsck\_cs utility](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

A vulnerability was identified where **`fsck_cs`** was misled into corrupting a crucial file, due to its ability to follow **symbolic links**. Specifically, attackers crafted a link from _`/dev/diskX`_ to the file `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Executing **`fsck_cs`** on _`/dev/diskX`_ led to the corruption of `Info.plist`. This file's integrity is vital for the operating system's SIP (System Integrity Protection), which controls the loading of kernel extensions. Once corrupted, SIP's ability to manage kernel exclusions is compromised.

The commands to exploit this vulnerability are:

```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```

The exploitation of this vulnerability has severe implications. The `Info.plist` file, normally responsible for managing permissions for kernel extensions, becomes ineffective. This includes the inability to blacklist certain extensions, such as `AppleHWAccess.kext`. Consequently, with the SIP's control mechanism out of order, this extension can be loaded, granting unauthorized read and write access to the system's RAM.

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

It was possible to mount a new file system over **SIP protected folders to bypass the protection**.

```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```

#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

The system is set to boot from an embedded installer disk image within the `Install macOS Sierra.app` to upgrade the OS, utilizing the `bless` utility. The command used is as follows:

```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```

The security of this process can be compromised if an attacker alters the upgrade image (`InstallESD.dmg`) before booting. The strategy involves substituting a dynamic loader (dyld) with a malicious version (`libBaseIA.dylib`). This replacement results in the execution of the attacker's code when the installer is initiated.

The attacker's code gains control during the upgrade process, exploiting the system's trust in the installer. The attack proceeds by altering the `InstallESD.dmg` image via method swizzling, particularly targeting the `extractBootBits` method. This allows the injection of malicious code before the disk image is employed.

Moreover, within the `InstallESD.dmg`, there's a `BaseSystem.dmg`, which serves as the upgrade code's root file system. Injecting a dynamic library into this allows the malicious code to operate within a process capable of altering OS-level files, significantly increasing the potential for system compromise.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In this talk from [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), it's shown how **`systemmigrationd`** (which can bypass SIP) executes a **bash** and a **perl** script, which can be abused via env variables **`BASH_ENV`** and **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

As [**detailed in this blog post**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), a `postinstall` script from `InstallAssistant.pkg` packages allowed was executing:

```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```

and it was possible to crate a symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` that would allow a user to **unrestrict any file, bypassing SIP protection**.

### **com.apple.rootless.install**

{% hint style="danger" %}
The entitlement **`com.apple.rootless.install`** allows to bypass SIP
{% endhint %}

The entitlement `com.apple.rootless.install` is known to bypass System Integrity Protection (SIP) on macOS. This was notably mentioned in relation to [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In this specific case, the system XPC service located at `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` possesses this entitlement. This allows the related process to circumvent SIP constraints. Furthermore, this service notably presents a method that permits the movement of files without enforcing any security measures.

## Sealed System Snapshots

Sealed System Snapshots are a feature introduced by Apple in **macOS Big Sur (macOS 11)** as a part of its **System Integrity Protection (SIP)** mechanism to provide an additional layer of security and system stability. They are essentially read-only versions of the system volume.

Here's a more detailed look:

1. **Immutable System**: Sealed System Snapshots make the macOS system volume "immutable", meaning that it cannot be modified. This prevents any unauthorised or accidental changes to the system that could compromise security or system stability.
2. **System Software Updates**: When you install macOS updates or upgrades, macOS creates a new system snapshot. The macOS startup volume then uses **APFS (Apple File System)** to switch to this new snapshot. The entire process of applying updates becomes safer and more reliable as the system can always revert to the previous snapshot if something goes wrong during the update.
3. **Data Separation**: In conjunction with the concept of Data and System volume separation introduced in macOS Catalina, the Sealed System Snapshot feature makes sure that all your data and settings are stored on a separate "**Data**" volume. This separation makes your data independent from the system, which simplifies the process of system updates and enhances system security.

Remember that these snapshots are automatically managed by macOS and don't take up additional space on your disk, thanks to the space sharing capabilities of APFS. It’s also important to note that these snapshots are different from **Time Machine snapshots**, which are user-accessible backups of the entire system.

### Check Snapshots

The command **`diskutil apfs list`** lists the **details of the APFS volumes** and their layout:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
    |   ---------------------------------------------------
    |   APFS Volume Disk (Role):   disk3s5 (Data)
    |   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
    |   FileVault:                 Yes (Unlocked)
</code></pre>

In the previous output it's possible to see that **user-accessible locations** are mounted under `/System/Volumes/Data`.

Moreover, **macOS System volume snapshot** is mounted in `/` and it's **sealed** (cryptographically signed by the OS). So, if SIP is bypassed and modifies it, the **OS won't boot anymore**.

It's also possible to **verify that seal is enabled** by running:

```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```

Moreover, the snapshot disk is also mounted as **read-only**:

```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
