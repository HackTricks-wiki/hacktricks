# 체크리스트 - 로컬 Windows 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **로컬 Windows 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**시스템 정보**](windows-local-privilege-escalation/index.html#system-info) 획득
- [ ] **커널** [**익스플로잇을 스크립트로 검색**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] **Google**을 사용해 커널 **익스플로잇** 검색
- [ ] **searchsploit**로 커널 **익스플로잇** 검색
- [ ] [**env vars**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)에 비밀번호가 있는가?
- [ ] [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [로깅/AV 열거](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)이 활성화되어 있는가?
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] 어떤 [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md) 확인
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] **현재** 사용자 **권한** 확인( windows-local-privilege-escalation/index.html#users-and-groups )
- [ ] [**특권 그룹의 구성원인가?**](windows-local-privilege-escalation/index.html#privileged-groups)
- [ ] 다음 토큰들 중 활성화되어 있는지 확인(windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**사용자 홈**](windows-local-privilege-escalation/index.html#home-folders) 확인(접근 가능한가?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**클립보드 내부**는 무엇인가?](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)

### [네트워크](windows-local-privilege-escalation/index.html#network)

- [ ] **현재** [**네트워크 정보**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부로부터 제한된 **숨겨진 로컬 서비스** 확인

### [실행 중인 프로세스](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 프로세스 바이너리의 [**파일 및 폴더 권한**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**메모리 비밀번호 추출**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**안전하지 않은 GUI 앱**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`로 흥미로운 프로세스에서 자격 증명 탈취 가능? (firefox, chrome 등)

### [서비스](windows-local-privilege-escalation/index.html#services)

- [ ] [어떤 서비스라도 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [어떤 서비스가 실행하는 **바이너리**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [어떤 서비스의 **레지스트리**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**인용되지 않은 서비스 바이너리 경로**를 악용할 수 있는가?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: 권한 있는 서비스를 열거하고 트리거하기](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] 설치된 애플리케이션에 대한 **쓰기** 권한(windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**시작 시 실행 애플리케이션**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **취약한 드라이버**(windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH 내부의 어떤 폴더에도 **쓰기**할 수 있는가?
- [ ] 존재하지 않는 DLL을 로드하려 시도하는 알려진 서비스 바이너리가 있는가?
- [ ] 어떤 **바이너리 폴더**에도 **쓰기**할 수 있는가?

### [네트워크](windows-local-privilege-escalation/index.html#network)

- [ ] 네트워크 열거(공유, 인터페이스, 라우트, 이웃 등)
- [ ] localhost(127.0.0.1)에서 리스닝하는 네트워크 서비스에 특히 주의

### [Windows 자격 증명](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) 자격 증명
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)에서 사용 가능한 자격 증명?
- [ ] 흥미로운 [**DPAPI 자격 증명**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] 저장된 [**Wifi 네트워크**](windows-local-privilege-escalation/index.html#wifi)의 비밀번호?
- [ ] 저장된 [**RDP 연결**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있는가?
- [ ] [**최근에 실행된 명령**](windows-local-privilege-escalation/index.html#recently-run-commands)에 비밀번호가 있는가?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) 비밀번호?
- [ ] [**AppCmd.exe** 존재](windows-local-privilege-escalation/index.html#appcmd-exe)? 자격 증명?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [파일 및 레지스트리 (자격 증명)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**자격증명**](windows-local-privilege-escalation/index.html#putty-creds) **및** [**SSH 호스트 키**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**레지스트리의 SSH 키**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] [**무인 설정 파일**](windows-local-privilege-escalation/index.html#unattended-files)에 비밀번호가 있는가?
- [ ] 어떤 [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 백업이 있는가?
- [ ] [**클라우드 자격 증명**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 파일?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] [**IIS Web config 파일**](windows-local-privilege-escalation/index.html#iis-web-config)의 비밀번호?
- [ ] [**웹 로그**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] 사용자에게 [**자격 증명 요청**](windows-local-privilege-escalation/index.html#ask-for-credentials) 하시겠는가?
- [ ] [**휴지통(Recycle Bin)**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) 내부의 흥미로운 파일?
- [ ] 자격 증명을 포함하는 [**다른 레지스트리**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**브라우저 데이터**](windows-local-privilege-escalation/index.html#browsers-history) 내부(DB, 기록, 북마크 등)?
- [ ] 파일 및 레지스트리에서의 [**일반 비밀번호 검색**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 비밀번호를 자동으로 검색하는 [**도구들**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 관리자 권한으로 실행된 프로세스의 어떤 핸들(handler)에 접근할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 악용할 수 있는지 확인

{{#include ../banners/hacktricks-training.md}}
