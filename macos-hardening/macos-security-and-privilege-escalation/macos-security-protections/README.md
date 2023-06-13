# macOS Security Protections

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Gatekeeper

**Gatekeeper** is a security feature developed for Mac operating systems, designed to ensure that users **run only trusted software** on their systems. It functions by **validating software** that a user downloads and attempts to open from **sources outside the App Store**, such as an app, a plug-in, or an installer package.

The key mechanism of Gatekeeper lies in its **verification** process. It checks if the downloaded software is **signed by a recognized developer**, ensuring the software's authenticity. Further, it ascertains whether the software is **notarised by Apple**, confirming that it is devoid of known malicious content and has not been tampered with after notarisation.

Additionally, Gatekeeper reinforces user control and security by **prompting users to approve the opening** of downloaded software for the first time. This safeguard helps prevent users from inadvertently running potentially harmful executable code that they may have mistaken for a harmless data file.

```bash
# Check the status
spctl --status
# Enable Gatekeeper
sudo spctl --master-enable
# Disable Gatekeeper
sudo spctl --master-disable
```

### Application Signatures

Application signatures, also known as code signatures, are a critical component of Apple's security infrastructure. They're used to **verify the identity of the software author** (the developer) and to ensure that the code hasn't been tampered with since it was last signed.

Here's how it works:

1. **Signing the Application:** When a developer is ready to distribute their application, they **sign the application using a private key**. This private key is associated with a **certificate that Apple issues to the developer** when they enroll in the Apple Developer Program. The signing process involves creating a cryptographic hash of all parts of the app and encrypting this hash with the developer's private key.
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

### Quarentine Files

Upon **downloading** an application or file, specific macOS **applications** such as web browsers or email clients **attach an extended file attribute**, commonly known as the "**quarantine flag**," to the downloaded file. This attribute acts as a security measure to **mark the file** as coming from an untrusted source (the internet), and potentially carrying risks. However, not all applications attach this attribute, for instance, common BitTorrent client software usually bypasses this process.

**The presence of a quarantine flag signals macOS's Gatekeeper security feature when a user attempts to execute the file**.

In the case where the **quarantine flag is not present** (as with files downloaded via some BitTorrent clients), Gatekeeper's **checks may not be performed**. Thus, users should exercise caution when opening files downloaded from less secure or unknown sources.

{% hint style="info" %}
**Checking** the **validity** of code signatures is a **resource-intensive** process that includes generating cryptographic **hashes** of the code and all its bundled resources. Furthermore, checking certificate validity involves doing an **online check** to Apple's servers to see if it has been revoked after it was issued. For these reasons, a full code signature and notarization check is **impractical to run every time an app is launched**.

Therefore, these checks are **only run when executing apps with the quarantined attribute.**
{% endhint %}

{% hint style="warning" %}
**Note that Safari and other web browsers and applications are the ones that need to mark the downloaded files**

Moreover, **files created by sandboxed processes** are also appended this attribute to prevent sandbox escaped.
{% endhint %}

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
xattr portada.png
com.apple.macl
com.apple.quarantine
```

Check the **value** of the **extended** **attributes** with:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```

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

## XProtect

XProtect is a built-in **anti-malware** feature in macOS. It is part of Apple's security system that works silently in the background to keep your Mac safe from known malware and malicious plug-ins.

XProtect functions by **checking any downloaded files against its database** of known malware and unsafe file types. When you download a file through certain apps, such as Safari, Mail, or Messages, XProtect automatically scans the file. If it matches any known malware in its database, XProtect will **prevent the file from running** and alert you to the threat.

The XProtect database is **updated regularly** by Apple with new malware definitions, and these updates are automatically downloaded and installed on your Mac. This ensures that XProtect is always up-to-date with the latest known threats.

However, it's worth noting that **XProtect isn't a full-featured antivirus solution**. It only checks for a specific list of known threats and doesn't perform on-access scanning like most antivirus software. Therefore, while XProtect provides a layer of protection against known malware, it's still recommended to exercise caution when downloading files from the internet or opening email attachments.

You can get information about the latest XProtect update running:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

## MRT - Malware Removal Tool

The Malware Removal Tool (MRT) is another part of macOS's security infrastructure. As the name suggests, MRT's main function is to **remove known malware from infected systems**.

Once malware is detected on a Mac (either by XProtect or by some other means), MRT can be used to automatically **remove the malware**. MRT operates silently in the background and typically runs whenever the system is updated or when a new malware definition is downloaded (it looks like the rules MRT has to detect malware are inside the binary).

While both XProtect and MRT are part of macOS's security measures, they perform different functions:

* **XProtect** is a preventative tool. It **checks files as they're downloaded** (via certain applications), and if it detects any known types of malware, it **prevents the file from opening**, thereby preventing the malware from infecting your system in the first place.
* **MRT**, on the other hand, is a **reactive tool**. It operates after malware has been detected on a system, with the goal of removing the offending software to clean up the system.

## Processes Limitants

### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **limits applications** running inside the sandbox to the **allowed actions specified in the Sandbox profile** the app is running with. This helps to ensure that **the application will be accessing only expected resources**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** is a mechanism in macOS to **limit and control application access to certain features**, usually from a privacy perspective. This can include things such as location services, contacts, photos, microphone, camera, accessibility, full disk access, and a bunch more.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## Trust Cache

The Apple macOS trust cache, sometimes also referred to as the AMFI (Apple Mobile File Integrity) cache, is a security mechanism in macOS designed to **prevent unauthorized or malicious software from running**. Essentially, it is a list of cryptographic hashes that the operating system uses to v**erify the integrity and authenticity of the software**.

When an application or executable file tries to run on macOS, the operating system checks the AMFI trust cache. If the **hash of the file is found in the trust cache**, the system **allows** the program to run because it recognises it as trusted.

## Launch Constraints

It controls from where and what can launch an Apple signed binary:

* You can't launch an app directly if should be run by launchd
* You can't run an app outside of the trusted location (like /System/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
