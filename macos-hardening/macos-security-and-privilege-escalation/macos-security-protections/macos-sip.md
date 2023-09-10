# macOS SIP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Basic Information**

**System Integrity Protection (SIP)** is a security technology in macOS that safeguards certain system directories from unauthorized access, even for the root user. It prevents modifications to these directories, including creation, alteration, or deletion of files. The main directories that SIP protects are:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

The protection rules for these directories and their subdirectories are specified in the **`/System/Library/Sandbox/rootless.conf`** file. In this file, paths starting with an asterisk (\*) represent exceptions to SIP's restrictions.

For instance, the following configuration:

```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```

indicates that the **`/usr`** directory is generally protected by SIP. However, modifications are allowed in the three subdirectories specified (`/usr/libexec/cups`, `/usr/local`, and `/usr/share/man`), as they are listed with a leading asterisk (\*).

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

SIP also imposes several other restrictions. For instance, it disallows the **loading of unsigned kernel extensions** (kexts) and prevents the **debugging** of macOS system processes. It also inhibits tools like dtrace from inspecting system processes.

## SIP Bypasses

### Prices

If an attacker manages to bypass SIP this is what he will earn:

* Read mail, messages, Safari history... of all users
* Grant permissions for webcam, microphone or anything (by directly writing over the SIP protected TCC database)
* Persistence: He could save a malware in a SIP protected location and not even toot will be able to delete it. Also he could tamper with MRT.
* Easiness to load kernel extensions (still other hardcore protections in place for this).

### Installer Packages

**Installer packages signed with Apple's certificate** can bypass its protections. This means that even packages signed by standard developers will be blocked if they attempt to modify SIP-protected directories.

### Unexistent SIP file

One potential loophole is that if a file is specified in **`rootless.conf` but does not currently exist**, it can be created. Malware could exploit this to **establish persistence** on the system. For example, a malicious program could create a .plist file in `/System/Library/LaunchDaemons` if it is listed in `rootless.conf` but not present.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
The entitlement **`com.apple.rootless.install.heritable`** allows to bypass SIP
{% endhint %}

[**Researchers from this blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) discovered a vulnerability in macOS's System Integrity Protection (SIP) mechanism, dubbed the 'Shrootless' vulnerability. This vulnerability centers around the `system_installd` daemon, which has an entitlement, **`com.apple.rootless.install.heritable`**, that allows any of its child processes to bypass SIP's file system restrictions.

Researchers found that during the installation of an Apple-signed package (.pkg file), **`system_installd`** **runs** any **post-install** scripts included in the package. These scripts are executed by the default shell, **`zsh`**, which automatically **runs** commands from the **`/etc/zshenv`** file, if it exists, even in non-interactive mode. This behavior could be exploited by attackers: by creating a malicious `/etc/zshenv` file and waiting for `system_installd` to invoke `zsh`, they could perform arbitrary operations on the device.

Moreover, it was discovered that **`/etc/zshenv` could be used as a general attack technique**, not just for a SIP bypass. Each user profile has a `~/.zshenv` file, which behaves the same way as `/etc/zshenv` but doesn't require root permissions. This file could be used as a persistence mechanism, triggering every time `zsh` starts, or as an elevation of privilege mechanism. If an admin user elevates to root using `sudo -s` or `sudo <command>`, the `~/.zshenv` file would be triggered, effectively elevating to root.

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) it was discovered that the same **`system_installd`** process could still be abused because it was putting the **post-install script inside a random named folder protected by SIP inside `/tmp`**. The thing is that **`/tmp` itself isn't protected by SIP**, so it was possible to **mount** a **virtual image on it**, then the **installer** would put in there the **post-install script**, **unmount** the virtual image, **recreate** all the **folders** and **add** the **post installation** script with the **payload** to execute.

### **com.apple.rootless.install**

{% hint style="danger" %}
The entitlement **`com.apple.rootless.install`** allows to bypass SIP
{% endhint %}

From [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) The system XPC service `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` has the entitlement **`com.apple.rootless.install`**, which grants the process permission to bypass SIP restrictions. It also **exposes a method to move files without any security check.**

## Sealed System Snapshots

Sealed System Snapshots are a feature introduced by Apple in **macOS Big Sur (macOS 11)** as a part of its **System Integrity Protection (SIP)** mechanism to provide an additional layer of security and system stability. They are essentially read-only versions of the system volume.

Here's a more detailed look:

1. **Immutable System**: Sealed System Snapshots make the macOS system volume "immutable", meaning that it cannot be modified. This prevents any unauthorized or accidental changes to the system that could compromise security or system stability.
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

```
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
