# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vector를 찾는 데 가장 좋은 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) 획득
- [ ] [**scripts를 사용해 kernel exploits 검색**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Google을 사용해 kernel **exploits 검색**
- [ ] searchsploit을 사용해 kernel **exploits 검색**
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 passwords가 있는가?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)가 있는가?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)이 가능한가?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)이 가능한가?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) settings 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)가 active인지 확인
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)이 적용되어 있는가?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)이 있는가?
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)가 있는가?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)이 가능한가?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)이 가능한가?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current**] user의 **privileges** 확인 (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**privileged group의 member**](windows-local-privilege-escalation/index.html#privileged-groups)인가?
- [ ] 다음 [token 중 활성화된 것이 있는지 확인](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있어 raw volumes를 읽고 file ACLs를 우회할 수 있는가?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)이 있는가?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) 확인 (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**Clipboard 안에 있는 내용**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)은 무엇인가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **current** [**network** **information**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부로 제한된 **hidden local services** 확인

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries의 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`를 통해 **interesting processes**에서 credentials를 탈취할 수 있는가? (firefox, chrome 등 ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [**any service를 modify할 수 있는가?**](windows-local-privilege-escalation/index.html#permissions)
- [ ] [어떤 **service**에서 **executed**되는 **binary**를 **modify할 수 있는가?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [어떤 **service**의 **registry**를 **modify할 수 있는가?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [어떤 **unquoted service** binary **path**를 이용할 수 있는가?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged services 열거 및 trigger](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **installed applications에 대한** [**Write** **permissions**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] **PATH 내부의 폴더에 write할 수 있는가?**
- [ ] **non-existant DLL을 load하려는** 알려진 service binary가 있는가?
- [ ] **binaries folder에 write할 수 있는가?**

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network 열거 (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1)에서 listening 중인 network services를 특히 확인

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 사용할 수 있는 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials가 있는가?
- [ ] 흥미로운 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)가 있는가?
- [ ] 저장된 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)의 passwords
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있는가?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)에 passwords가 있는가?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) 및 [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)가 있는가?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)에 passwords가 있는가?
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup이 있는가?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있으면 `SAM`, `SYSTEM`, DPAPI material 및 `MachineKeys`에 대해 raw-volume reads 시도
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)이 있는가?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file이 있는가?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)이 있는가?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)에 Password가 있는가?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] user에게 [**credentials를 요청**](windows-local-privilege-escalation/index.html#ask-for-credentials)할 것인가?
- [ ] [**Recycle Bin 내부의 files**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)에 흥미로운 정보가 있는가?
- [ ] [**credentials를 포함하는 다른 registry**](windows-local-privilege-escalation/index.html#inside-the-registry)가 있는가?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 내부 (dbs, history, bookmarks, ...)?
- [ ] files 및 registry에서 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] passwords를 자동으로 검색하는 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator가 실행한 process의 handler에 access할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 abuse할 수 있는지 확인

## References

- [1] [Project Zero - UI Access를 abuse하여 Administrator Protection 우회](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
