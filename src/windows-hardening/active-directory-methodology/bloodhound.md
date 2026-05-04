# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: 이 페이지는 **enumerate**하고 Active Directory 관계를 **visualise**하는 데 가장 유용한 몇 가지 유틸리티를 모아둡니다. 스텔스한 **Active Directory Web Services (ADWS)** 채널을 통한 수집은 위의 reference를 확인하세요.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals)는 다음을 가능하게 하는 고급 **AD viewer & editor**입니다:

* 디렉터리 트리의 GUI browsing
* object attributes 및 security descriptors 편집
* 오프라인 분석을 위한 snapshot 생성 / 비교

### Quick usage

1. 툴을 시작하고 어떤 domain credentials로든 `dc01.corp.local`에 connect합니다.
2. `File ➜ Create Snapshot`을 통해 offline snapshot을 생성합니다.
3. `File ➜ Compare`로 두 snapshot을 비교하여 permission drift를 찾습니다.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon)은 domain에서 ACLs, GPOs, trusts, CA templates … 등 많은 artefacts를 추출하고 **Excel report**를 생성합니다.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (graph visualisation)

[BloodHound](https://github.com/SpecterOps/BloodHound)는 graph theory를 사용하여 on-prem AD, Entra ID, 그리고 OpenGraph를 통해 ingest한 추가 attack-surface data 안에 숨겨진 privilege relationships를 드러냅니다.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Collectors

* `SharpHound.exe` / `Invoke-BloodHound` – 네이티브 또는 PowerShell 변형
* `RustHound-CE` – Linux, macOS, Windows용 크로스플랫폼 CE collector
* `NetExec --bloodhound` – Linux에서 빠른 LDAP 기반 수집
* `AzureHound` – Entra ID 열거
* **SoaPy + BOFHound** – ADWS 수집 (상단 링크 참조)

> BloodHound CE `v8+`는 OpenGraph 도입 시 collector 출력 형식을 변경했습니다. legacy BloodHound 또는 이전 CE 설치에서 업그레이드한 후에는, 데이터를 import하기 전에 현재 collector로 discovery를 다시 실행하세요.

#### Common SharpHound modes
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
The collectors는 BloodHound GUI를 통해 수집되는 JSON을 생성합니다.

#### 도메인에 가입되지 않은 Windows 호스트에서의 SharpHound

operator VM이 대상 도메인에 joined되어 있지 않다면, DNS를 DC로 지정하고, **network-only** shell을 시작한 뒤, DC에서 `SYSVOL`/`NETLOGON`이 보이는지 확인한 다음, 원격 도메인을 대상으로 수집합니다:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
이는 도메인에 가입되지 않아야 하는 일회용 jump box 또는 operator workstation에 유용합니다.

#### Linux/macOS에서의 크로스 플랫폼 수집
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE` is a good default when you want CE-compatible output from a non-Windows host. `NetExec` is convenient when you are already using it for LDAP validation or spraying and want a quick graph import. For non-AD datasets, BloodHound OpenGraph can be extended with collectors such as [ShareHound](../../network-services-pentesting/pentesting-smb/README.md).

### Privilege & logon-right collection

Windows **token privileges** (e.g., `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`) can bypass DACL checks, so mapping them domain-wide exposes local LPE edges that ACL-only graphs miss. **Logon rights** (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` and their `SeDeny*` counterparts) are enforced by LSA before a token even exists, and denies take precedence, so they materially gate lateral movement (RDP/SMB/scheduled task/service logon).

**Run collectors elevated** when possible: UAC creates a filtered token for interactive admins (via `NtFilterToken`), stripping sensitive privileges and marking admin SIDs as deny-only. If you enumerate privileges from a non-elevated shell, high-value privileges will be invisible and BloodHound won’t ingest the edges.

Two complementary SharpHound collection strategies now exist:

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP를 통해 GPO를 열거하고 (`(objectCategory=groupPolicyContainer)`) 각 `gPCFileSysPath`를 읽는다.
2. SYSVOL에서 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`를 가져와 privilege/logon-right 이름을 SIDs에 매핑하는 `[Privilege Rights]` 섹션을 파싱한다.
3. `gPLink`를 통해 OUs/sites/domains의 GPO 링크를 확인하고, 연결된 컨테이너의 컴퓨터를 나열한 뒤, 해당 권한을 그 머신에 귀속시킨다.
4. 장점: 일반 사용자로 동작하며 조용하다; 단점: GPO로 푸시된 권한만 보이며(로컬 변경은 놓친다).

- **LSA RPC enumeration (noisy, accurate):**
- 대상에서 local admin 권한이 있는 context에서 Local Security Policy를 열고, 각 privilege/logon right마다 `LsaEnumerateAccountsWithUserRight`를 호출해 RPC로 할당된 principals를 열거한다.
- 장점: 로컬 또는 GPO 외부에서 설정된 권한까지 잡아낸다; 단점: 네트워크 트래픽이 시끄럽고 각 호스트마다 admin이 필요하다.

**이 에지들로 드러나는 abuse path 예시:** `CanRDP` ➜ host where your user also has `SeBackupPrivilege` ➜ start an elevated shell to avoid filtered tokens ➜ use backup semantics to read `SAM` and `SYSTEM` hives despite restrictive DACLs ➜ exfiltrate and run `secretsdump.py` offline to recover the local Administrator NT hash for lateral movement/privilege escalation.

### Prioritising Kerberoasting with BloodHound

Use graph context to keep roasting targeted:

1. ADWS-compatible collector로 한 번 수집하고 오프라인으로 작업한다:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP을 import하고, compromise된 principal을 owned로 표시한 뒤, 내장 쿼리(*Kerberoastable Users*, *Shortest Paths to Domain Admins*)를 실행해 admin/infra 권한이 있는 SPN 계정을 드러낸다.
3. SPN을 blast radius 기준으로 우선순위화하고; cracking 전에 `pwdLastSet`, `lastLogon`, 허용된 encryption types를 검토한다.
4. 선택한 ticket만 요청해 offline으로 crack한 뒤, 새 access로 BloodHound를 다시 쿼리한다:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r) enumerates **Group Policy Objects** and highlights misconfigurations.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/)는 Active Directory의 **health-check**를 수행하고 risk scoring이 포함된 HTML report를 생성합니다.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8 Launches with OpenGraph: Identity Attack Paths Beyond Active Directory & Entra ID](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [Beyond ACLs: Mapping Windows Privilege Escalation Paths with BloodHound](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)

{{#include ../../banners/hacktricks-training.md}}
