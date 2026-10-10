# 체크리스트 - 로컬 Windows 권한 상승

{{#include ../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾는 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [시스템 정보](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**시스템 정보**](windows-local-privilege-escalation/index.html#system-info) 수집
- [ ] 스크립트를 사용해 **kernel** [**exploit**](windows-local-privilege-escalation/index.html#version-exploits) 검색
- [ ] Google에서 kernel **exploit** 검색
- [ ] searchsploit에서 kernel **exploit** 검색
- [ ] [**환경 변수**](windows-local-privilege-escalation/index.html#environment)에 흥미로운 정보가 있는가?
- [ ] [**PowerShell 기록**](windows-local-privilege-escalation/index.html#powershell-history)에 비밀번호가 있는가?
- [ ] [**인터넷 설정**](windows-local-privilege-escalation/index.html#internet-settings)에 흥미로운 정보가 있는가?
- [ ] [**드라이브**](windows-local-privilege-escalation/index.html#drives)는?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)는?
- [ ] [**타사 에이전트 자동 업데이트 도구 / IPC 악용**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)는?

### [로깅/AV 열거](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) 및 [**WEF** ](windows-local-privilege-escalation/index.html#wef) 설정 확인
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) 확인
- [ ] [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)이 활성화되어 있는지 확인
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)은?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**캐시된 자격 증명**](windows-local-privilege-escalation/index.html#cached-credentials)은?
- [ ] [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)가 있는지 확인
- [ ] [**AppLocker 정책**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)은?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**관리자 보호 / UIAccess 자동 권한 상승**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)은?<sup>[[1]](#references)</sup>
- [ ] [**보안 데스크톱 접근성 레지스트리 전파(RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)는?<sup>[[2]](#references)</sup>
- [ ] [**사용자 권한**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**현재** 사용자 **권한**](windows-local-privilege-escalation/index.html#users-and-groups) 확인
- [ ] [**특권 그룹의 구성원**](windows-local-privilege-escalation/index.html#privileged-groups)인가?
- [ ] [다음 토큰 중 활성화된 것이 있는지](windows-local-privilege-escalation/index.html#token-manipulation) 확인: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
- [ ] 원시 볼륨을 읽고 파일 ACL을 우회할 수 있는 [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있는지 확인
- [ ] [**사용자 세션**](windows-local-privilege-escalation/index.html#logged-users-sessions)은?
- [ ] [**사용자 홈 디렉터리**](windows-local-privilege-escalation/index.html#home-folders) 확인 (접근 가능한가?)
- [ ] [**비밀번호 정책**](windows-local-privilege-escalation/index.html#password-policy) 확인
- [ ] [**클립보드 내용**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)은 무엇인가?

### [네트워크](windows-local-privilege-escalation/index.html#network)

- [ ] **현재** [**네트워크** **정보**](windows-local-privilege-escalation/index.html#network) 확인
- [ ] 외부에서 접근이 제한된 **숨겨진 로컬 서비스** 확인

### [실행 중인 프로세스](windows-local-privilege-escalation/index.html#running-processes)

- [ ] 프로세스 바이너리 [**파일 및 폴더 권한**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**메모리에서 비밀번호 마이닝**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**안전하지 않은 GUI 앱**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] `ProcDump.exe`를 통해 **흥미로운 프로세스**(firefox, chrome 등)에서 자격 증명 탈취?

### [서비스](windows-local-privilege-escalation/index.html#services)

- [ ] [**서비스를 수정**할 수 있는가?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [서비스에서 **실행하는** **바이너리**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [서비스의 **레지스트리**를 **수정**할 수 있는가?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [**따옴표가 없는 서비스** 바이너리 **경로**를 악용할 수 있는가?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [서비스 트리거: 특권 서비스 열거 및 트리거](windows-local-privilege-escalation/service-triggers.md)

### [**애플리케이션**](windows-local-privilege-escalation/index.html#applications)

- [ ] [설치된 애플리케이션에 대한 **쓰기 권한**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**시작 애플리케이션**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **취약한** [**드라이버**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] PATH의 폴더에 **쓰기**가 가능한가?
- [ ] **존재하지 않는 DLL을 로드하려는** 것으로 알려진 서비스 바이너리가 있는가?
- [ ] **바이너리 폴더**에 **쓰기**가 가능한가?

### [네트워크](windows-local-privilege-escalation/index.html#network)

- [ ] 네트워크 열거 (공유, 인터페이스, 경로, 이웃 등)
- [ ] localhost(127.0.0.1)에서 수신 대기 중인 네트워크 서비스를 특히 확인

### [Windows 자격 증명](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)자격 증명
- [ ] 사용할 수 있는 [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) 자격 증명이 있는가?
- [ ] 흥미로운 [**DPAPI 자격 증명**](windows-local-privilege-escalation/index.html#dpapi)이 있는가?
- [ ] 저장된 [**Wi-Fi 네트워크**](windows-local-privilege-escalation/index.html#wifi)의 비밀번호가 있는가?
- [ ] [**저장된 RDP 연결**](windows-local-privilege-escalation/index.html#saved-rdp-connections)에 흥미로운 정보가 있는가?
- [ ] [**최근 실행한 명령**](windows-local-privilege-escalation/index.html#recently-run-commands)에 비밀번호가 있는가?
- [ ] [**원격 데스크톱 자격 증명 관리자**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)의 비밀번호는?
- [ ] [**AppCmd.exe**가 있는가](windows-local-privilege-escalation/index.html#appcmd-exe)? 자격 증명은?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)는? DLL Side Loading이 가능한가?

### [파일 및 레지스트리 (자격 증명)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**자격 증명**](windows-local-privilege-escalation/index.html#putty-creds) 및 [**SSH 호스트 키**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**레지스트리의 SSH 키**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)는?
- [ ] [**무인 설치 파일**](windows-local-privilege-escalation/index.html#unattended-files)에 비밀번호가 있는가?
- [ ] [**SAM 및 SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) 백업이 있는가?
- [ ] [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md)가 있으면 원시 볼륨을 읽어 `SAM`, `SYSTEM`, DPAPI 자료 및 `MachineKeys`를 확인
- [ ] [**클라우드 자격 증명**](windows-local-privilege-escalation/index.html#cloud-credentials)은?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) 파일이 있는가?
- [ ] [**캐시된 GPP 비밀번호**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)는?
- [ ] [**IIS 웹 구성 파일**](windows-local-privilege-escalation/index.html#iis-web-config)에 비밀번호가 있는가?
- [ ] [**웹** **로그**](windows-local-privilege-escalation/index.html#logs)에 흥미로운 정보가 있는가?
- [ ] 사용자에게 [**자격 증명을 요청**](windows-local-privilege-escalation/index.html#ask-for-credentials)할 것인가?
- [ ] [**휴지통에 있는 파일**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)이 흥미로운가?
- [ ] 자격 증명이 포함된 다른 [**레지스트리 항목**](windows-local-privilege-escalation/index.html#inside-the-registry)은?
- [ ] [**브라우저 데이터**](windows-local-privilege-escalation/index.html#browsers-history) (DB, 기록, 북마크 등)는?
- [ ] 파일 및 레지스트리에서 [**일반적인 비밀번호 검색**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry)
- [ ] 비밀번호를 자동으로 검색하는 [**도구**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords)

### [Leaked 핸들러](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] 관리자가 실행한 프로세스의 핸들러에 접근할 수 있는가?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] 이를 악용할 수 있는지 확인

## References

- [1] [Project Zero - UI Access를 악용해 Administrator Protection 우회하기](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RegPwn의 종말](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
