# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Найкращий tool для пошуку векторів Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Отримати [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Шукати **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Використати **Google to search** для пошуку **kernel** **exploits**
- [ ] Використати **searchsploit to search** для пошуку **kernel** **exploits**
- [ ] Цікава інформація в [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwords в [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Цікава інформація в [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Перевірити налаштування [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)та [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Перевірити, чи активний [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Перевірити, чи є будь-який [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Перевірити [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Чи є ви [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Перевірити, чи ввімкнено будь-які з цих token: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Перевірити, чи маєте [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), щоб читати raw volumes і bypass file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Перевірити [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Перевірити [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Що [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Перевірити **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Перевірити приховані local services, обмежені доступом ззовні

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Викрасти credentials з **interesting processes** через `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Чи можете ви **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Чи можете ви **modify** **binary**, який **executed** будь-яким **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Чи можете ви **modify** **registry** будь-якого **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Чи можете ви скористатися будь-яким **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Чи можете ви **write in any folder inside PATH**?
- [ ] Чи є відомий service binary, який **tries to load any non-existant DLL**?
- [ ] Чи можете ви **write** в будь-яку папку з **binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Перерахувати мережу (shares, interfaces, routes, neighbours, ...)
- [ ] Особливо зверніть увагу на network services, що слухають на localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] credentials з [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), які можна використати?
- [ ] Цікаві [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwords з збережених [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Цікава інформація в [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwords у [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] Чи існує [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwords у [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Будь-який backup [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Якщо присутній [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), спробуйте raw-volume reads для `SAM`, `SYSTEM`, DPAPI material і `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password у [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Цікава інформація в [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Чи хочете ви [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) у користувача?
- [ ] Цікаві [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Інший [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Усередині [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) у файлах і registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) для автоматичного пошуку passwords

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Чи маєте ви доступ до будь-якого handler процесу, запущеного administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Перевірити, чи можна це abuse



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
