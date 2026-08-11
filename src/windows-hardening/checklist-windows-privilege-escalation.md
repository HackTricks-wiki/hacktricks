# 체크리스트 - 로컬 Windows 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾는 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**시스템 정보**](windows-local-privilege-escalation/index.html#system-info) 수집
- [ ] [**스크립트를 사용하여 kernel exploit 검색**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Google을 사용하여 kernel **exploit 검색**
- [ ] searchsploit을 사용하여 kernel **exploit 검색**
- [ ] [**환경 변수**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 password가 있는가?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**드라이브**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [로깅/AV 열거](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)가 활성화되어 있는지 확인
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**사용자 권한**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**현재** 사용자의 [**권한**](windows-local-privilege-escalation/index.html#users-and-groups) 확인
- [ ] [**권한이 있는 그룹의 구성원**](windows-local-privilege-escalation/index.html#privileged-groups)인가?
- [ ] 다음 [토큰이 활성화되어 있는지 확인](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] raw volume을 읽고 file ACL을 우회할 수 있는 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있는지 확인
- [ ] [**사용자 세션**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**사용자 홈 디렉터리**](windows-local-privilege-escalation/index.html#home-folders) 확인 (access?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**Clipboard 내부**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)에 무엇이 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] **현재** [**network** **정보**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부에서 제한된 **숨겨진 로컬 서비스** 확인

### [실행 중인 프로세스](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 프로세스 binary의 [**file 및 folder permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`를 통해 **흥미로운 프로세스**에서 credentials 탈취? (firefox, chrome 등 ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [**서비스를 수정**할 수 있는가?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [서비스에서 **실행되는** **binary**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [서비스의 **registry**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [인용되지 않은 서비스 binary **path**를 이용할 수 있는가?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: 권한 있는 서비스 열거 및 trigger](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 설치된 application에 대한 [**쓰기** [**권한**](windows-local-privilege-escalation/index.html#write-permissions)]
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **취약한** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 내부의 folder에 **write**할 수 있는가?
- [ ] 존재하지 않는 DLL을 **load하려는** 알려진 service binary가 있는가?
- [ ] **binaries folder**에 **write**할 수 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] network 열거 (shares, interfaces, routes, neighbours, ...)
- [ ] localhost (127.0.0.1)에서 listening 중인 network services를 특히 확인

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] 사용할 수 있는 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials가 있는가?
- [ ] 흥미로운 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 저장된 [Wifi networks](windows-local-privilege-escalation/index.html#wifi)의 password?
- [ ] [저장된 RDP Connections](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있는가?
- [ ] [**최근 실행된 commands**](windows-local-privilege-escalation/index.html#recently-run-commands)에 password가 있는가?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) passwords?
- [ ] [**AppCmd.exe exists**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) 및 [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**registry의 SSH keys**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)에 password가 있는가?
- [ ] [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup이 있는가?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있으면 `SAM`, `SYSTEM`, DPAPI material 및 `MachineKeys`에 대해 raw-volume reads 시도
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)에 password가 있는가?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] 사용자에게 [**credentials 요청**](windows-local-privilege-escalation/index.html#ask-for-credentials)하기
- [ ] [**Recycle Bin 내부의 files**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)에 흥미로운 정보가 있는가?
- [ ] [**credentials를 포함하는 기타 registry**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 내부 (dbs, history, bookmarks, ...)?
- [ ] files 및 registry에서 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] password를 자동으로 검색하는 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] administrator가 실행한 process의 handler에 access할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 abuse할 수 있는지 확인

## References

- [1] [Project Zero - UI Access를 abuse하여 Administrator Protection 우회](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RegPwn의 종말](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
