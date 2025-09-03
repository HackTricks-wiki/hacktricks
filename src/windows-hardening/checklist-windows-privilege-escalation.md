# 체크리스트 - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) 얻기
- [ ] **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) 검색
- [ ] **Google**로 kernel **exploits** 검색
- [ ] **searchsploit**로 kernel **exploits** 검색
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 비밀번호가 있는가?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)가 활성화되어 있는가?
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] 어떤 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는가 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) 확인
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups) 확인
- [ ] 현재 사용자 **privileges** 확인 (권한)
- [ ] [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups) 인가?
- [ ] 다음 토큰들 중 활성화된 것이 있는가: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) 확인 (접근 가능?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)에 무엇이 들어있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 현재 **network information** 확인
- [ ] 외부에 제한된 **hidden local services** 확인

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries의 [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) 확인
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`를 이용해 **흥미로운 프로세스**에서 자격증명 탈취? (firefox, chrome 등 ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **쓰기** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup) 확인
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 내부의 폴더에 쓸 수 있는가?
- [ ] 알려진 서비스 바이너리 중 존재하지 않는 DLL을 로드하려고 하는 것이 있는가?
- [ ] 어떤 **binaries folder**에 쓸 수 있는가?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] 네트워크 열거 (shares, interfaces, routes, neighbours, ...) 수행
- [ ] localhost(127.0.0.1)에서 수신 중인 네트워크 서비스에 특히 주의

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) 자격증명
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 사용 가능한 자격증명?
- [ ] 흥미로운 [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 저장된 [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)의 비밀번호?
- [ ] [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보?
- [ ] [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)에 비밀번호가 있는가?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 비밀번호?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? 자격증명?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)에 비밀번호가 있는가?
- [ ] 어떤 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 백업이 있는가?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 파일?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)에 비밀번호가 있는가?
- [ ] [**web logs**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] 사용자에게 [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) 요청할 것인가?
- [ ] [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)에 있는 흥미로운 파일들?
- [ ] 자격증명을 포함한 다른 [**registry**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) 내부 (dbs, history, bookmarks, ...)?
- [ ] 파일과 레지스트리에서의 [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 비밀번호를 자동으로 검색하는 [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 관리자 권한으로 실행된 프로세스의 핸들러에 접근할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 악용할 수 있는지 확인

{{#include ../banners/hacktricks-training.md}}
