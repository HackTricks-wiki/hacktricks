# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors를 찾는 데 가장 좋은 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) 획득
- [ ] 스크립트를 사용해 **kernel** [**exploits**](windows-local-privilege-escalation/index.html#version-exploits) 검색
- [ ] Google을 사용해 kernel **exploits** 검색
- [ ] searchsploit를 사용해 kernel **exploits** 검색
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 Passwords가 있는가?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)와 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)가 활성화되어 있는지 확인
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] 어떤 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] 현재 user의 [**privileges**](windows-local-privilege-escalation/index.html#users-and-groups) 확인
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)에 속해 있는가?
- [ ] [이러한 토큰들](windows-local-privilege-escalation/index.html#token-manipulation) 중 활성화된 것이 있는지 확인: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] **SeManageVolumePrivilege**([**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md))가 있는지 확인하여 raw volumes를 읽고 file ACLs를 우회
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) 확인 (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard) 안에 무엇이 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 현재 [**network** **information**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부에서만 제한된 hidden local services 확인

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries의 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`를 통해 **interesting processes**에서 credentials 탈취 ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [**modify any service**](windows-local-privilege-escalation/index.html#permissions)할 수 있는가?
- [ ] 어떤 [**service**](windows-local-privilege-escalation/index.html#modify-service-binary-path)가 실행하는 [**binary**](windows-local-privilege-escalation/index.html#modify-service-binary-path)를 [**modify**](windows-local-privilege-escalation/index.html#modify-service-binary-path)할 수 있는가?
- [ ] 어떤 [**service**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)의 [**registry**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)를 [**modify**](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)할 수 있는가?
- [ ] [**unquoted service**](windows-local-privilege-escalation/index.html#unquoted-service-paths) binary [**path**](windows-local-privilege-escalation/index.html#unquoted-service-paths)를 활용할 수 있는가?
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 설치된 applications에 대한 [**Write**](windows-local-privilege-escalation/index.html#write-permissions) 권한
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] 취약한 [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 내부의 어떤 folder에든 **write**할 수 있는가?
- [ ] 알려진 service binary 중 **non-existant DLL**을 load하려고 시도하는 것이 있는가?
- [ ] 어떤 **binaries folder**에든 **write**할 수 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network를 열거 (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1)에서 listen 중인 network services를 특별히 살펴볼 것

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 사용할 수 있는 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials?
- [ ] 흥미로운 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 저장된 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)의 Passwords?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있는가?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)에 Passwords가 있는가?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)에 Passwords가 있는가?
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup이 있는가?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있으면 `SAM`, `SYSTEM`, DPAPI material, `MachineKeys`에 대해 raw-volume reads를 시도
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)에 Password가 있는가?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] 사용자에게 [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)할 것인가?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 안의 흥미로운 file들?
- [ ] credentials를 포함하는 다른 [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 안에 (dbs, history, bookmarks, ...)?
- [ ] 파일과 registry에서의 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] Passwords를 자동으로 찾는 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator가 실행한 process의 handler에 접근할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 악용할 수 있는지 확인



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
