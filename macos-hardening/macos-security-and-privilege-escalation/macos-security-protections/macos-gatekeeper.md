# macOS Gatekeeper / Quarantine / XProtect

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Gatekeeper

**Gatekeeper** is a security feature developed for Mac operating systems, designed to ensure that users **run only trusted software** on their systems. It functions by **validating software** that a user downloads and attempts to open from **sources outside the App Store**, such as an app, a plug-in, or an installer package.

The key mechanism of Gatekeeper lies in its **verification** process. It checks if the downloaded software is **signed by a recognized developer**, ensuring the software's authenticity. Further, it ascertains whether the software is **notarised by Apple**, confirming that it is devoid of known malicious content and has not been tampered with after notarisation.

Additionally, Gatekeeper reinforces user control and security by **prompting users to approve the opening** of downloaded software for the first time. This safeguard helps prevent users from inadvertently running potentially harmful executable code that they may have mistaken for a harmless data file.

### Application Signatures

Application signatures, also known as code signatures, are a critical component of Apple's security infrastructure. They're used to **verify the identity of the software author** (the developer) and to ensure that the code hasn't been tampered with since it was last signed.

Here's how it works:

1. **Signing the Application:** When a developer is ready to distribute their application, they **sign the application using a private key**. This private key is associated with a **certificate that Apple issues to the developer** when they enrol in the Apple Developer Program. The signing process involves creating a cryptographic hash of all parts of the app and encrypting this hash with the developer's private key.
2. **Distributing the Application:** The signed application is then distributed to users along with the developer's certificate, which contains the corresponding public key.
3. **Verifying the Application:** When a user downloads and attempts to run the application, their Mac operating system uses the public key from the developer's certificate to decrypt the hash. It then recalculates the hash based on the current state of the application and compares this with the decrypted hash. If they match, it means **the application hasn't been modified** since the developer signed it, and the system permits the application to run.

Application signatures are an essential part of Apple's Gatekeeper technology. When a user attempts to **open an application downloaded from the internet**, Gatekeeper verifies the application signature. If it's signed with a certificate issued by Apple to a known developer and the code hasn't been tampered with, Gatekeeper permits the application to run. Otherwise, it blocks the application and alerts the user.

Starting from macOS Catalina, **Gatekeeper also checks whether the application has been notarized** by Apple, adding an extra layer of security. The notarization process checks the application for known security issues and malicious code, and if these checks pass, Apple adds a ticket to the application that Gatekeeper can verify.

#### Check Signatures

When checking some **malware sample** you should always **check the signature** of the binary as the **developer** that signed it may be already **related** with **malware.**

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```

### Notarization

Apple's notarization process serves as an additional safeguard to protect users from potentially harmful software. It involves the **developer submitting their application for examination** by **Apple's Notary Service**, which should not be confused with App Review. This service is an **automated system** that scrutinizes the submitted software for the presence of **malicious content** and any potential issues with code-signing.

If the software **passes** this inspection without raising any concerns, the Notary Service generates a notarization ticket. The developer is then required to **attach this ticket to their software**, a process known as 'stapling.' Furthermore, the notarization ticket is also published online where Gatekeeper, Apple's security technology, can access it.

Upon the user's first installation or execution of the software, the existence of the notarization ticket - whether stapled to the executable or found online - **informs Gatekeeper that the software has been notarized by Apple**. As a result, Gatekeeper displays a descriptive message in the initial launch dialog, indicating that the software has undergone checks for malicious content by Apple. This process thereby enhances user confidence in the security of the software they install or run on their systems.

### spctl & syspolicyd

{% hint style="danger" %}
Note that from Sequoia version, **`spctl`** doesn't allow to modify Gatekeeper configuration anymore.
{% endhint %}

**`spctl`** is the CLI tool to enumerate and interact with Gatekeeper (with the `syspolicyd` daemon via XPC messages). For example, it's possible to see the **status** of GateKeeper with:

```bash
# Check the status
spctl --status
```

{% hint style="danger" %}
Note that GateKeeper signature checks are performed only to **files with the Quarantine attribute**, not to every file.
{% endhint %}

GateKeeper will check if according to the **preferences & the signature** a binary can be executed:

<figure><img src="../../../.gitbook/assets/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** is the main daemon responsible to enforcing Gatekeeper. It maintains a database located in `/var/db/SystemPolicy` and it's possible to find the code to support the [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity\_codesigning/lib/policydb.cpp) and the [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity\_codesigning/lib/syspolicy.sql). Note that the database is unrestricted by SIP and writable by root and the database `/var/db/.SystemPolicy-default` is used as an original backup in case the other gets corrupted.

Moreover, the bundles **`/var/db/gke.bundle`** and **`/var/db/gkopaque.bundle`** contains files with rules that are inserted in the database. You can check this database as root with:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

**`syspolicyd`** also exposes a XPC server with different operations like `assess`, `update`, `record` and `cancel` which are also reachable using **`Security.framework`'s `SecAssessment*`** APIs and **`xpctl`** actually talks to **`syspolicyd`** via XPC.

Note how the first rule ended in "**App Store**" and the second one in "**Developer ID**" and that in the previous imaged it was **enabled to execute apps from the App Store and identified developers**.\
If you **modify** that setting to App Store, the "**Notarized Developer ID" rules will disappear**.

There are also thousands of rules of **type GKE** :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

These are hashes that from:

* `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
* `/var/db/gke.bundle/Contents/Resources/gk.db`
* `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Or you could list the previous info with:

```bash
sudo spctl --list
```

The options **`--master-disable`** and **`--global-disable`** of **`spctl`** will completely **disable** these signature checks:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

When completely enabled, a new option will appear:

<figure><img src="../../../.gitbook/assets/image (1151).png" alt=""><figcaption></figcaption></figure>

It's possible to **check if an App will be allowed by GateKeeper** with:

```bash
spctl --assess -v /Applications/App.app
```

It's possible to add new rules in GateKeeper to allow the execution of certain apps with:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app          
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app            
/Applications/App.app: accepted
```

Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of  adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

### Quarantine Files

Upon **downloading** an application or file, specific macOS **applications** such as web browsers or email clients **attach an extended file attribute**, commonly known as the "**quarantine flag**," to the downloaded file. This attribute acts as a security measure to **mark the file** as coming from an untrusted source (the internet), and potentially carrying risks. However, not all applications attach this attribute, for instance, common BitTorrent client software usually bypasses this process.

**The presence of a quarantine flag signals macOS's Gatekeeper security feature when a user attempts to execute the file**.

In the case where the **quarantine flag is not present** (as with files downloaded via some BitTorrent clients), Gatekeeper's **checks may not be performed**. Thus, users should exercise caution when opening files downloaded from less secure or unknown sources.

{% hint style="info" %}
**Checking** the **validity** of code signatures is a **resource-intensive** process that includes generating cryptographic **hashes** of the code and all its bundled resources. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.

Therefore, these checks are **only run when executing apps with the quarantined attribute.**
{% endhint %}

{% hint style="warning" %}
This attribute must be **set by the application creating/downloading** the file.

However, files that are sandboxed will have this attribute set to every file they create. And non sandboxed apps can set it themselves, or specify the [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) key in the **Info.plist** which will make the system set the `com.apple.quarantine` extended attribute on the files created,
{% endhint %}

Moreover, all files created by a process calling **`qtn_proc_apply_to_self`** are quarantined. Or the API **`qtn_file_apply_to_path`** adds the quarantine attribute to a specified file path.

It's possible to **check it's status and enable/disable** (root required) with:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

You can also **find if a file has the quarantine extended attribute** with:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Check the **value** of the **extended** **attributes** and find out the app that wrote the quarantine attr with:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

Actually a process "could set quarantine flags to the files it creates" (I already tried to apply the USER\_APPROVED flag in a created file but it won't apply it):

<details>

<summary>Source Code apply quarantine flags</summary>

```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

  qtn_proc_t qp = qtn_proc_alloc();
  qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
  qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
  qtn_proc_apply_to_self(qp);
  qtn_proc_free(qp);

  FILE *fp;
  fp = fopen("thisisquarantined.txt", "w+");
  fprintf(fp, "Hello Quarantine\n");
  fclose(fp);

  return 0;
  
}
```

</details>

And **remove** that attribute with:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

And find all the quarantined files with:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylb**

This library exports several functions that allow to manipulate the extended attribute fields.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

* `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
* `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

### XProtect

XProtect is a built-in **anti-malware** feature in macOS. XProtect **checks any application when it's first launched or modified against its database** of known malware and unsafe file types. When you download a file through certain apps, such as Safari, Mail, or Messages, XProtect automatically scans the file. If it matches any known malware in its database, XProtect will **prevent the file from running** and alert you to the threat.

The XProtect database is **updated regularly** by Apple with new malware definitions, and these updates are automatically downloaded and installed on your Mac. This ensures that XProtect is always up-to-date with the latest known threats.

However, it's worth noting that **XProtect isn't a full-featured antivirus solution**. It only checks for a specific list of known threats and doesn't perform on-access scanning like most antivirus software.

You can get information about the latest XProtect update running:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect is located on. SIP protected location at **/Library/Apple/System/Library/CoreServices/XProtect.bundle** and inside the bundle you can find information XProtect uses:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Allows code with those cdhashes to use legacy entitlements.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: List of plugins and extensions that are disallowed to load via BundleID and TeamID or indicating a minimum version.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Yara rules to detect malware.
* **`XProtect.bundle/Contents/Resources/gk.db`**: SQLite3 database with hashes of blocked applications and TeamIDs.

Note that there is another App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** related to XProtect that isn't involved with the Gatekeeper process.

### Not Gatekeeper

{% hint style="danger" %}
Note that Gatekeeper **isn't executed every time** you execute an application, just _**AppleMobileFileIntegrity**_ (AMFI) will only **verify executable code signatures** when you execute an app that has been already executed and verified by Gatekeeper.
{% endhint %}

Therefore, previously it was possible to execute an app to cache it with Gatekeeper, then **modify not executables files of the application** (like Electron asar or NIB files) and if no other protections were in place, the application was **executed** with the **malicious** additions.

However, now this is not possible because macOS **prevents modifying files** inside applications bundles. So, if you try the [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, you will find that it's not longer possible to abuse it because after executing the app to cache it with Gatekeeper, you won't be able to modify the bundle. And if you change for example the name of the Contents directory to NotCon (as indicated in the exploit), and then execute the main binary of the app to cache it with Gatekeeper, it will trigger an error and won't execute.

## Gatekeeper Bypasses

Any way to bypass Gatekeeper (manage to make the user download something and execute it when Gatekeeper should disallow it) is considered a vulnerability in macOS. These are some CVEs assigned to techniques that allowed to bypass Gatekeeper in the past:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

It was observed that if the **Archive Utility** is used for extraction, files with **paths exceeding 886 characters** do not receive the com.apple.quarantine extended attribute. This situation inadvertently allows those files to **circumvent Gatekeeper's** security checks.

Check the [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) for more information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

When an application is created with **Automator**, the information about what it needs to execute is inside `application.app/Contents/document.wflow` not in the executable. The executable is just a generic Automator binary called **Automator Application Stub**.

Therefore, you could make `application.app/Contents/MacOS/Automator\ Application\ Stub` **point with a symbolic link to another Automator Application Stub inside the system** and it will execute what is inside `document.wflow` (you script) **without triggering Gatekeeper** because the actual executable doesn't have the quarantine xattr.

Example os expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Check the [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) for more information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In this bypass a zip file was created with an application starting to compress from `application.app/Contents` instead of `application.app`. Therefore, the **quarantine attr** was applied to all the **files from `application.app/Contents`** but **not to `application.app`**, which is was Gatekeeper was checking, so Gatekeeper was bypassed because when `application.app` was triggered it **didn't have the quarantine attribute.**

```bash
zip -r test.app/Contents test.zip
```

Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Even if the components are different the exploitation of this vulnerability is very similar to the previous one. In this case with will generate an Apple Archive from **`application.app/Contents`** so **`application.app` won't get the quarantine attr** when decompressed by **Archive Utility**.

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) for more information.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

The ACL **`writeextattr`** can be used to prevent anyone from writing an attribute in a file:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Moreover, **AppleDouble** file format copies a file including its ACEs.

In the [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) it's possible to see that the ACL text representation stored inside the xattr called **`com.apple.acl.text`** is going to be set as ACL in the decompressed file. So, if you compressed an application into a zip file with **AppleDouble** file format with an ACL that prevents other xattrs to be written to it... the quarantine xattr wasn't set into de application:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Check the [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) for more information.

Note that this could also be be exploited with AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

It was discovered that **Google Chrome wasn't setting the quarantine attribute** to downloaded files because of some macOS internal problems.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats store the attributes of a file in a separate file starting by `._`, this helps to copy dile attributes **across macOS machines**. However, it was noticed that after decompressing an AppleDouble file, the file starting with `._` **wasn't given the quarantine attribute**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Being able to create a file that won't have the quarantine attribute set, it was **possible to bypass Gatekeeper.** The trick was to **create a DMG file application** using the AppleDouble name convention (start it with `._`) and create a **visible file as a sym link to this hidden** file without the quarantine attribute.\
When the **dmg file is executed**, as it doesn't have a quarantine attribute it'll **bypass Gatekeeper**.

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir 
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

* Create a directory containing an app.
* Add uchg to the app.
* Compress the app to a tar.gz file.
* Send the tar.gz file to a victim.
* The victim opens the tar.gz file and runs the app.
* Gatekeeper does not check the app.

### Prevent Quarantine xattr

In an ".app" bundle if the quarantine xattr is not added to it, when executing it **Gatekeeper won't be triggered**.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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

