# MacOS Red Teaming

## Common management methods

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

If you manage to** compromise admin credentials** to access the management platform, you can **potentially compromise all the computers** by distributing your malware in the machines.

For red teaming in MacOS environments it's highly recommended to have some understanding of how the MDMs work:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

And also about **MacOS** "special" **network** **protocols**:

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In some occasions you will find that the **MacOS computer is connected to an AD**. In this scenario you should try to **enumerate** the active directory as you are use to it. Find some **help** in the following pages:

{% content-ref url="../../pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows/active-directory-methodology/" %}
[active-directory-methodology](../../windows/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Some **local MacOS tool **that may also help you is `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Also there are some tools prepared for MacOS to automatically enumerate the AD and play with kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound is an extension to the Bloodhound audting tool allowing collecting and ingesting of Active Directory relationships on MacOS hosts.
* ****[**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is an Objective-C project designed to interact with the Heimdal krb5 APIs on macOS. The goal of the project is to enable better security testing around Kerberos on macOS devices using native APIs without requiring any other framework or packages on the target.
* ****[**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) tool to do Active Directory enumeration.

### Domain Information

```
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Users

The three types of MacOS users are:

* **Local Users** — Managed by the local OpenDirectory service, they aren’t connected in any way to the Active Directory.
* **Network Users** — Volatile Active Directory users who require a connection to the DC server to authenticate.
* **Mobile Users** — Active Directory users with a local backup for their credentials and files.

The local information about users and groups is stored in in the folder _/var/db/dslocal/nodes/Default._\
__For example, the info about user called _mark_ is stored in _/var/db/dslocal/nodes/Default/users/mark.plist_ and the info about the group _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

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

## External Services

MacOS Red Teaming is different from a regular Windows Red Teaming as usually **MacOS is integrated with several external platforms directly**. A common configuration of MacOS is to access to the computer using **OneLogin synchronised credentials, and accessing several external services** (like github, aws...) via OneLogin:

![](<../../.gitbook/assets/image (563).png>)

###

## References

* [https://www.youtube.com/watch?v=IiMladUbL6E](https://www.youtube.com/watch?v=IiMladUbL6E)
* [https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
