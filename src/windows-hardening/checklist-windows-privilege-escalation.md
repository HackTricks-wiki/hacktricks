# 체크리스트 - 로컬 Windows 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] 수집 [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) 검색
- [ ] kernel **exploits**를 찾기 위해 **Google** 사용
- [ ] kernel **exploits**를 찾기 위해 **searchsploit** 사용
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있나?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 비밀번호가 있나?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있나?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives) 확인?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus) 확인?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md) 확인
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated) 사용 가능한가?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) 활성화되어 있는가?
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection) 적용 여부?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard) 적용 여부(또는 관련 [캐시된 자격증명](windows-local-privilege-escalation/index.html#cached-credentials) 확인)?
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials) 여부?
- [ ] 어떤 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy) 확인?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) 설정 확인
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) 확인
- [ ] 현재 사용자 **privileges** 확인 (windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)인지 확인?
- [ ] [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** 가 활성화되어 있는가?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions) 확인?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) 접근 여부 확인
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)에는 무엇이 있나?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 현재 [**network** **information**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부에서 접근이 제한된 숨겨진 로컬 서비스 확인

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 프로세스 바이너리의 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) 확인
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining) 확인
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps) 확인
- [ ] `ProcDump.exe`을 사용하여 **interesting processes**에서 자격증명 탈취? (firefox, chrome 등 ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 설치된 애플리케이션에 대한 [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)에 **Write** 권한이 있는가?
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup) 확인?
- [ ] 취약한 [**Drivers**](windows-local-privilege-escalation/index.html#drivers) 확인

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 내부의 어떤 폴더에도 쓸 수 있는가?
- [ ] 존재하지 않는 DLL을 로드하려고 시도하는 알려진 서비스 바이너리가 있는가?
- [ ] 어떤 **binaries folder**에 쓸 수 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 네트워크 열거 (공유, 인터페이스, 라우트, 이웃, ...)
- [ ] localhost(127.0.0.1)에서 리스닝하는 네트워크 서비스에 특히 주목

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) 자격증명
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)에서 사용할 수 있는 자격증명?
- [ ] 흥미로운 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) 여부?
- [ ] 저장된 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)의 비밀번호?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있나?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)에 비밀번호가 있나?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)의 비밀번호?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe) 존재? 자격증명?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) 존재? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) 및 [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry) 확인?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)에 비밀번호가 있는가?
- [ ] 어떤 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 백업이 있는가?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)가 있는가?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 파일 확인?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword) 확인?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)에 비밀번호가 있는가?
- [ ] [**web** **logs**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있나?
- [ ] 사용자에게 [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) 요청할 것인가?
- [ ] 휴지통 안의 흥미로운 [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] 자격증명을 포함한 다른 [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry) 확인
- [ ] 브라우저 데이터(데이터베이스, 히스토리, 즐겨찾기 등) 내부 확인: [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history)
- [ ] 파일 및 레지스트리에서의 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 비밀번호를 자동으로 검색하는 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 관리자 권한으로 실행된 프로세스의 핸들러에 접근할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 악용할 수 있는지 확인

{{#include ../banners/hacktricks-training.md}}
