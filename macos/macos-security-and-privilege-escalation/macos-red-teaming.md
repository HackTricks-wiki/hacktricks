# MacOS Red Teaming

## Common management methods

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

If you manage to **compromise admin credentials** to access the management platform, you can **potentially compromise all the computers** by distributing your malware in the machines.

## Active Directory

In some occasions you will find that the **MacOS computer is connected to an AD**. In this scenario you should try to **enumerate** the active directory as you are use to it. Find some **help** in the following pages:

{% page-ref page="../../pentesting/pentesting-ldap.md" %}

{% page-ref page="../../windows/active-directory-methodology/" %}

{% page-ref page="../../pentesting/pentesting-kerberos-88/" %}

Some **local MacOS tool** that may also help you is `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Also there are some tools prepared for MacOS to automatically enumerate the AD and play with kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts.
* \*\*\*\*[**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is an Objective-C project designed to interact with the Heimdal krb5 APIs on macOS. The goal of the project is to enable better security testing around Kerberos on macOS devices using native APIs without requiring any other framework or packages on the target.
* \*\*\*\*[**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation \(JXA\) tool to do Active Directory enumeration.

### Domain Information

```text
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Users

The three types of MacOS users are:

* **Local Users** — Managed by the local OpenDirectory service, they aren’t connected in any way to the Active Directory.
* **Network Users** — Volatile Active Directory users who require a connection to the DC server to authenticate.
* **Mobile Users** — Active Directory users with a local backup for their credentials and files.

The local information about users and groups is stored in in the folder _/var/db/dslocal/nodes/Default._  
For example, the info about user called _mark_ is stored in _/var/db/dslocal/nodes/Default/users/mark.plist_ and the info about the group _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

In addition to using the HasSession and AdminTo edges, **MacHound adds three new edges** to the Bloodhound database:

* **CanSSH** - entity allowed to SSH to host
* **CanVNC** - entity allowed to VNC to host
* **CanAE** - entity allowed to execute AppleEvent scripts on host

## External Services

MacOS Red Teaming is different from a regular Windows Red Teaming as usually **MacOS is integrated with several external platforms directly**. A common configuration of MacOS is to access to the computer using **OneLogin synchronised credentials, and accessing several external services** \(like github, aws...\) via OneLogin:

![](../../.gitbook/assets/image%20%28562%29.png)

### 

## References

* [https://www.youtube.com/watch?v=IiMladUbL6E](https://www.youtube.com/watch?v=IiMladUbL6E)
* [https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)

