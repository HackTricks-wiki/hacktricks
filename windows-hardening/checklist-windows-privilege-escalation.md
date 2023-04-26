# Checklist - Local Windows Privilege Escalation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/#system-info)

* [ ] Obtain [**System information**](windows-local-privilege-escalation/#system-info)
* [ ] Search for **kernel** [**exploits using scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Use **Google to search** for kernel **exploits**
* [ ] Use **searchsploit to search** for kernel **exploits**
* [ ] Interesting info in [**env vars**](windows-local-privilege-escalation/#environment)?
* [ ] Passwords in [**PowerShell history**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interesting info in [**Internet settings**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Drives**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS exploit**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/#enumeration)

* [ ] Check [**Audit** ](windows-local-privilege-escalation/#audit-settings)and [**WEF** ](windows-local-privilege-escalation/#wef)settings
* [ ] Check [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Check if [**WDigest** ](windows-local-privilege-escalation/#wdigest)is active
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Cached Credentials**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Check if any [**AV**](windows-av-bypass)
* [ ] [**AppLocker Policy**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**User Privileges**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Check [**current** user **privileges**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Are you [**member of any privileged group**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Check if you have [any of these tokens enabled](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Users Sessions**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Check[ **users homes**](windows-local-privilege-escalation/#home-folders) (access?)
* [ ] Check [**Password Policy**](windows-local-privilege-escalation/#password-policy)
* [ ] What is[ **inside the Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/#network)

* [ ] Check **current** [**network** **information**](windows-local-privilege-escalation/#network)
* [ ] Check **hidden local services** restricted to the outside

### [Running Processes](windows-local-privilege-escalation/#running-processes)

* [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Memory Password mining**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Services](windows-local-privilege-escalation/#services)

* [ ] [Can you **modify any service**?](windows-local-privilege-escalation#permissions)
* [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/#applications)

* [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Startup Applications**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Can you **write in any folder inside PATH**?
* [ ] Is there any known service binary that **tries to load any non-existant DLL**?
* [ ] Can you **write** in any **binaries folder**?

### [Network](windows-local-privilege-escalation/#network)

* [ ] Enumerate the network (shares, interfaces, routes, neighbours, ...)
* [ ] Take a special look at network services listening on localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)credentials
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) credentials that you could use?
* [ ] Interesting [**DPAPI credentials**](windows-local-privilege-escalation/#dpapi)?
* [ ] Passwords of saved [**Wifi networks**](windows-local-privilege-escalation/#wifi)?
* [ ] Interesting info in [**saved RDP Connections**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Passwords in [**recently run commands**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) passwords?
* [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/#appcmd-exe)? Credentials?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH keys in registry**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Passwords in [**unattended files**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Any [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) backup?
* [ ] [**Cloud credentials**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) file?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Password in [**IIS Web config file**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interesting info in [**web** **logs**](windows-local-privilege-escalation/#logs)?
* [ ] Do you want to [**ask for credentials**](windows-local-privilege-escalation/#ask-for-credentials) to the user?
* [ ] Interesting [**files inside the Recycle Bin**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Other [**registry containing credentials**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Inside [**Browser data**](windows-local-privilege-escalation/#browsers-history) (dbs, history, bookmarks, ...)?
* [ ] [**Generic password search**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in files and registry
* [ ] [**Tools**](windows-local-privilege-escalation/#tools-that-search-for-passwords) to automatically search for passwords

### [Leaked Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Have you access to any handler of a process run by administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Check if you can abuse it

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
