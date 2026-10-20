# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Abusing MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

If you manage to **compromise admin credentials** to access the management platform, you can **potentially compromise all the computers** by distributing your malware in the machines.

For red teaming in MacOS environments it's highly recommended to have some understanding of how the MDMs work:


{{#ref}}
macos-mdm/
{{#endref}}

### Using MDM as a C2

A MDM will have permission to install, query or remove profiles, install applications, create local admin accounts, set firmware password, change the FileVault key...

In order to run your own MDM you need to **your CSR signed by a vendor** which you could try to get with [**https://mdmcert.download/**](https://mdmcert.download/). And to run your own MDM for Apple devices you could use [**MicroMDM**](https://github.com/micromdm/micromdm).

MDM enrollment does **not** automatically make the management server's TLS certificate a trusted CA or grant an app-signing identity. If the server uses a private CA, its root and intermediate certificates must be supplied in the enrollment profile or a separate trust profile. The client identity used for MDM authentication is a different certificate.<sup>[[7]](#references)</sup>

A downloaded MDM enrollment profile (`.mobileconfig`) must be opened and approved in **System Settings → General → Device Management**. Merely placing it in a root-installed `.pkg` or Safari-opened ZIP does not silently enroll a current Mac. See [configuration profile behavior](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automated Device Enrollment during Setup Assistant is a separate flow. See [rogue enrollment of another organization's device](macos-mdm/enrolling-devices-in-other-organisations.md) for its different prerequisites.<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** uses this technique.

### Deploying a package through a controlled MDM

On a **supervised Mac running macOS 26 or later**, control of the MDM service permits a `com.apple.configuration.package` declaration in the system scope.<sup>[[10]](#references)</sup> The package must have a signature the device can verify, but its app does not need a separate Developer ID signature: Gatekeeper does not check apps installed through device management.<sup>[[11]](#references)</sup> A trusted server TLS certificate alone does not give the operator the private key or signing usage needed for that package signature.<sup>[[11]](#references)[[12]](#references)</sup>

Build a signed test package, compute its digest, and publish both the package and a `ManifestURL` plist over HTTPS. The manifest needs one `software-package` asset with its URL and SHA-256, plus a unique `bundle-identifier` and `bundle-version`.<sup>[[11]](#references)</sup> Then send a package declaration with that manifest URL and `InstallBehavior.Install` set to `Required`; check the `package.list` status item for installation or errors.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

A minimal required-install declaration, submitted through the MDM service, looks like this (replace the URL and both UUIDs).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Abusing JAMF PRO

JAMF can run **custom scripts** (scripts developed by the sysadmin), **native payloads** (local account creation, set EFI password, file/process monitoring...) and **MDM** (device configurations, device certificates...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Go to a page such as `https://<company-name>.jamfcloud.com/enroll/` to see if they have **self-enrolment enabled**. If they have it might **ask for credentials to access**.

You could use the script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) to perform a password spraying attack.

Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form:

![Abusing JAMF PRO - JAMF self-enrolment: Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

The **`jamf`** binary contained the secret to open the keychain which at the time of the discovery was **shared** among everybody and it was: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Moreover, jamf **persist** as a **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

The **JSS** (Jamf Software Server) **URL** that **`jamf`** will use is located in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
This file basically contains the URL:

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://subdomain-company.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```

So, an attacker could drop a malicious package (`pkg`) that **overwrites this file** when installed setting the **URL to a Mythic C2 listener from a Typhon agent** to now be able to abuse JAMF as C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

In order to **impersonate the communication** between a device and JMF you need:

- The **UUID** of the device: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- The **JAMF keychain** from: `/Library/Application\ Support/Jamf/JAMF.keychain` which contains the device certificate

With this information, **create a VM** with the **stolen** Hardware **UUID** and with **SIP disabled**, drop the **JAMF keychain,** **hook** the Jamf **agent** and steal its information.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

You could also monitor the location `/Library/Application Support/Jamf/tmp/` for the **custom scripts** admins might want to execute via Jamf as they are **placed here, executed and removed**. These scripts **might contain credentials**.

However, **credentials** might be passed tho these scripts as **parameters**, so you would need to monitor `ps aux | grep -i jamf` (without even being root).

The script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) can listen for new files being added and new process arguments.

### macOS Remote Access

And also about **MacOS** "special" **network** **protocols**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

In some occasions you will find that the **MacOS computer is connected to an AD**. In this scenario you should try to **enumerate** the active directory as you are use to it. Find some **help** in the following pages:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Some **local MacOS tool** that may also help you is `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Also there are some tools prepared for MacOS to automatically enumerate the AD and play with kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is an Objective-C project designed to interact with the Heimdal krb5 APIs on macOS. The goal of the project is to enable better security testing around Kerberos on macOS devices using native APIs without requiring any other framework or packages on the target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) tool to do Active Directory enumeration.

### Domain Information

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Users

The three types of MacOS users are:

- **Local Users** — Managed by the local OpenDirectory service, they aren’t connected in any way to the Active Directory.
- **Network Users** — Volatile Active Directory users who require a connection to the DC server to authenticate.
- **Mobile Users** — Active Directory users with a local backup for their credentials and files.

The local information about users and groups is stored in in the folder _/var/db/dslocal/nodes/Default._\
For example, the info about user called _mark_ is stored in _/var/db/dslocal/nodes/Default/users/mark.plist_ and the info about the group _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

In addition to using the HasSession and AdminTo edges, **MacHound adds three new edges** to the Bloodhound database:<sup>[[2]](#references)</sup>

- **CanSSH** - entity allowed to SSH to host
- **CanVNC** - entity allowed to VNC to host
- **CanAE** - entity allowed to execute AppleEvent scripts on host

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

More info in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

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


{{#ref}}
macos-keychain.md
{{#endref}}

## External Services

MacOS Red Teaming is different from a regular Windows Red Teaming as usually **MacOS is integrated with several external platforms directly**. A common configuration of MacOS is to access to the computer using **OneLogin synchronised credentials, and accessing several external services** (like github, aws...) via OneLogin.

## Misc Red Team techniques

### Safari

When a file is downloaded in Safari, if its a "safe" file, it will be **automatically opened**. So for example, if you **download a zip**, it will be automatically decompressed:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Managing certificates for device management services and devices](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Use configuration profiles on Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Deploying device management enrollment profiles](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Package declaration](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Installing packages](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identities](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
