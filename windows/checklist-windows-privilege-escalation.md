# Checklist - Local Windows Privilege Escalation

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)\*\*\*\*

### [System Info](windows-local-privilege-escalation/#system-info)

* [ ] Obtain [**System information**](windows-local-privilege-escalation/#system-info)\*\*\*\*
* [ ] Search for **kernel** [**exploits using scripts**](windows-local-privilege-escalation/#version-exploits)\*\*\*\*
* [ ] Use **Google to search** for kernel **exploits**
* [ ] Use **searchsploit to search** for kernel **exploits**
* [ ] Interesting info in [**env vars**](windows-local-privilege-escalation/#environment)?
* [ ] Passwords in [**PowerShell history**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interesting info in [**Internet settings**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Drives**](windows-local-privilege-escalation/#drives)?
* [ ] \*\*\*\*[**WSUS exploit**](windows-local-privilege-escalation/#wsus)?
* [ ] \*\*\*\*[**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/#enumeration)

* [ ] Check [**Audit** ](windows-local-privilege-escalation/#audit-settings)and [**WEF** ](windows-local-privilege-escalation/#wef)settings
* [ ] Check [**LAPS**](windows-local-privilege-escalation/#laps)\*\*\*\*
* [ ] Check if [**WDigest** ](windows-local-privilege-escalation/#wdigest)is active
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] \*\*\*\*[**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Cached Credentials**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Check if any [**AV**](windows-local-privilege-escalation/#av)\*\*\*\*
* [ ] \*\*\*\*[**AppLocker Policy**](windows-local-privilege-escalation/#applocker-policy)?
* [ ] [**UAC**](windows-local-privilege-escalation/#uac)?

### \*\*\*\*[**User Privileges**](windows-local-privilege-escalation/#users-and-groups)

* [ ] Check [**current** user **privileges**](windows-local-privilege-escalation/#users-and-groups)\*\*\*\*
* [ ] Are you [**member of any privileged group**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Check if you have [any of these tokens enabled](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ? 
* [ ] [**Users Sessions**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Check[ **users homes**](windows-local-privilege-escalation/#home-folders) \(access?\)
* [ ] Check [**Password Policy**](windows-local-privilege-escalation/#password-policy)\*\*\*\*
* [ ] What is[ **inside the Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/#network)

* [ ] Check **current** [network **information**](windows-local-privilege-escalation/#network)\*\*\*\*
* [ ] Check **hidden local services** restricted to the outside

### [Running Processes](windows-local-privilege-escalation/#running-processes)

* [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/#file-and-folder-permissions)\*\*\*\*
* [ ] \*\*\*\*[**Memory Password mining**](windows-local-privilege-escalation/#memory-password-mining)\*\*\*\*
* [ ] \*\*\*\*[**Insecure GUI apps**](windows-local-privilege-escalation/#insecure-gui-apps)\*\*\*\*

### [Services](windows-local-privilege-escalation/#services)

* [ ] [Can you **modify any service**?](windows-local-privilege-escalation/#permissions)
* [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/#services-registry-permissions)
* [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/#unquoted-service-paths)

### \*\*\*\*[**Applications**](windows-local-privilege-escalation/#applications)\*\*\*\*

* [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/#write-permissions)\*\*\*\*
* [ ] \*\*\*\*[**Startup Applications**](windows-local-privilege-escalation/#run-at-startup)\*\*\*\*
* [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/#drivers)\*\*\*\*

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Can you **write in any folder inside PATH**?
* [ ] Is there any known service binary that **tries to load any non-existant DLL**?
* [ ] Can you **write** in any **binaries folder**?

### [Credentials](windows-local-privilege-escalation/#credentials)

* [ ] [**Windows Vault**](windows-local-privilege-escalation/#windows-vault) credentials that you could use?
* [ ] Interesting [**DPAPI credentials**](windows-local-privilege-escalation/#dpapi)?
* [ ] [**Wifi netoworks**](windows-local-privilege-escalation/#wifi)?
* [ ] \*\*\*\*[**SSH keys in registry**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] [**Credentials inside "known files"**](windows-local-privilege-escalation/#credentials-inside-files)? Inside the Recycle Bin? At home?
* [ ] [**Registry with credentials**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Inside [**Browser data**](windows-local-privilege-escalation/#browsers-history) \(dbs, history, bookmarks....\)?
* [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/#appcmd-exe)? Credentials?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?
* [ ] [**Cloud credentials**](windows-local-privilege-escalation/#cloud-credentials)?

### [AlwaysInstallElevated](windows-local-privilege-escalation/#alwaysinstallelevated)

* [ ] Is this **enabled**?

### [Is vulnerable WSUS?](windows-local-privilege-escalation/#wsus)

* [ ] Is it **vulnerable**?

### [Write Permissions](windows-local-privilege-escalation/#write-permissions)

* [ ] Are you able to **write files that could grant you more privileges**?

### Any [open handler of a privileged process or thread](windows-local-privilege-escalation/#leaked-handlers)?

* [ ] Maybe the compromised process is vulnerable.

### [UAC Bypass](windows-local-privilege-escalation/#check-uac)

* [ ] There are several ways to bypass the UAC



If you want to **know** about my **latest modifications**/**additions or you have any suggestion for HackTricks or PEASS**, **join the** [**PEASS & HackTricks telegram group here**](https://t.me/peass)**.**  
If you want to **share some tricks with the community** you can also submit **pull requests** to ****[**https://github.com/carlospolop/hacktricks**](https://github.com/carlospolop/hacktricks) ****that will be reflected in this book.  
Don't forget to **give ⭐ on the github** to motivate me to continue developing this book.

![](../.gitbook/assets/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67%20%283%29.png)

​[**Buy me a coffee here**](https://www.buymeacoffee.com/carlospolop)\*\*\*\*

