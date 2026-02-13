# BloodHound 및 기타 Active Directory 열거 도구

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> 참고: 이 페이지에는 Active Directory 관계를 **열거**하고 **시각화**하는 데 유용한 유틸리티들이 정리되어 있습니다. 은밀한 **Active Directory Web Services (ADWS)** 채널을 통한 수집은 위의 참조를 확인하세요.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals)은 고급 **AD viewer & editor**로 다음을 제공합니다:

* 디렉터리 트리를 GUI로 탐색
* 객체 속성 및 보안 설명자 편집
* 오프라인 분석을 위한 스냅샷 생성/비교

### 빠른 사용법

1. 도구를 시작하고 임의의 도메인 자격증명으로 `dc01.corp.local`에 연결합니다.
2. `File ➜ Create Snapshot`로 오프라인 스냅샷을 생성합니다.
3. 권한 변화(permission drifts)를 확인하기 위해 두 스냅샷을 `File ➜ Compare`로 비교합니다.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon)은 도메인에서 많은 수의 아티팩트(ACLs, GPOs, trusts, CA templates …)를 추출하고 **Excel report**를 생성합니다.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (그래프 시각화)

[BloodHound](https://github.com/BloodHoundAD/BloodHound)는 그래프 이론과 Neo4j를 사용하여 온프레미스 AD 및 Azure AD 내부의 숨겨진 권한 관계를 드러냅니다.

### 배포 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 수집기

* `SharpHound.exe` / `Invoke-BloodHound` – 네이티브 또는 PowerShell 변형
* `AzureHound` – Azure AD 열거
* **SoaPy + BOFHound** – ADWS 수집 (상단의 링크 참조)

#### SharpHound의 공통 모드
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
The collectors generate JSON which is ingested via the BloodHound GUI.

### 권한 및 로그온 권한 수집

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) 은 DACL 검사를 우회할 수 있으므로, 도메인 전역으로 매핑하면 ACL 전용 그래프가 놓치는 로컬 LPE 엣지들을 드러낸다. **로그온 권한** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` 및 대응되는 `SeDeny*`) 은 토큰이 생성되기 전에 LSA에 의해 강제되며, 거부가 우선하므로 횡적 이동(RDP/SMB/예약 작업·서비스 로그온)을 실질적으로 제약한다.

가능하면 수집기를 권한 상승된 상태로 실행하라: UAC는 인터랙티브 관리자에게 필터된 토큰을 생성(`NtFilterToken` 사용)해 민감한 권한을 제거하고 관리자 SIDs를 deny-only로 표시한다. 비권한 상승 셸에서 권한을 열거하면 고가치 권한이 보이지 않아 BloodHound가 해당 엣지를 수집하지 못한다.

현재 상호보완적인 두 가지 SharpHound 수집 전략이 있다:

- **GPO/SYSVOL 파싱 (stealthy, low-privilege):**
1. LDAP로 GPO를 열거(`(objectCategory=groupPolicyContainer)`)하고 각 `gPCFileSysPath`를 읽는다.
2. SYSVOL에서 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`를 가져와 `[Privilege Rights]` 섹션을 파싱해 권한/로그온 권한 이름을 SID에 매핑한다.
3. OUs/sites/domains의 `gPLink`를 통해 GPO 링크를 해석하고 링크된 컨테이너의 컴퓨터를 나열한 뒤 해당 권한을 그 머신들에 귀속시킨다.
4. 장점: 일반 사용자로도 동작하며 조용함. 단점: GPO로 배포된 권한만 확인할 수 있어 로컬 설정은 놓친다.

- **LSA RPC 열거 (noisy, accurate):**
- 대상에서 로컬 관리자 권한이 있는 컨텍스트에서 로컬 보안 정책을 열고 각 권한/로그온 권한마다 `LsaEnumerateAccountsWithUserRight`를 호출해 RPC로 할당된 주체를 열거한다.
- 장점: 로컬에 설정되었거나 GPO 외부에서 설정된 권한까지 캡처한다. 단점: 네트워크 트래픽이 눈에 띄며 각 호스트에서 관리자 권한이 필요하다.

예시 악용 경로(이 엣지들로 드러남): `CanRDP` ➜ 사용자가 `SeBackupPrivilege`도 가진 호스트 ➜ 필터된 토큰을 피하기 위해 권한 상승된 셸 시작 ➜ 백업 동작을 이용해 엄격한 DACL에도 불구하고 `SAM` 및 `SYSTEM` 하이브 읽기 ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### BloodHound로 Kerberoasting 우선순위 지정

그래프 컨텍스트를 사용해 Kerberoasting을 목표에 맞게 유지하라:

1. ADWS-compatible collector로 한 번 수집하고 오프라인에서 작업:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP을 임포트하고 손상된 principal을 owned로 표시한 뒤 내장 쿼리(*Kerberoastable Users*, *Shortest Paths to Domain Admins*)를 실행해 관리자/인프라 권한을 가진 SPN 계정을 드러낸다.
3. SPN을 blast radius로 우선순위화하라; 크래킹 전에 `pwdLastSet`, `lastLogon`, 및 허용된 암호화 유형을 검토한다.
4. 선택한 티켓만 요청해 오프라인에서 크랙한 뒤, 새 접근권으로 BloodHound를 다시 쿼리하라:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) 는 **Group Policy Objects** 를 열거하고 구성 오류를 강조한다.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/)는 Active Directory의 **상태 점검**을 수행하고 위험 점수화가 포함된 HTML 보고서를 생성합니다.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 참고 문헌

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
