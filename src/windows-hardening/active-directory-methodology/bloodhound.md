# BloodHound 및 기타 Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> 참고: 이 페이지에서는 Active Directory 관계를 **enumerate**하고 **visualise**하는 데 유용한 몇 가지 utility를 정리합니다. 은밀한 **Active Directory Web Services (ADWS)** channel을 통한 collection은 위의 reference를 확인하세요.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals)는 다음 기능을 제공하는 고급 **AD viewer & editor**입니다.

* directory tree의 GUI browsing
* object attributes 및 security descriptors 편집
* offline analysis를 위한 snapshot 생성 / 비교

### Quick usage

1. 도구를 시작하고 모든 domain credentials를 사용해 `dc01.corp.local`에 연결합니다.
2. `File ➜ Create Snapshot`을 통해 offline snapshot을 생성합니다.
3. `File ➜ Compare`를 사용해 두 snapshot을 비교하고 permission drift를 확인합니다.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon)은 domain에서 다양한 artefacts(ACLs, GPOs, trusts, CA templates …)를 추출하고 **Excel report**를 생성합니다.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (그래프 시각화)

[BloodHound](https://github.com/SpecterOps/BloodHound)은 graph theory를 사용하여 온프레미스 AD, Entra ID 내부의 숨겨진 privilege 관계와 OpenGraph를 통해 수집한 추가 attack-surface 데이터를 드러냅니다.

### Deployment (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 수집기

* `SharpHound.exe` / `Invoke-BloodHound` – native 또는 PowerShell variant
* `RustHound-CE` – Linux, macOS 및 Windows용 cross-platform CE collector
* `NetExec --bloodhound` – Linux에서 빠른 LDAP-driven collection
* `AzureHound` – Entra ID enumeration
* **SoaPy + BOFHound** – ADWS collection (상단 link 참조)

> BloodHound CE `v8+`는 OpenGraph가 도입되면서 collector output format을 변경했습니다. legacy BloodHound 또는 이전 CE install에서 upgrade한 후에는 data를 import하기 전에 current collectors를 사용해 discovery를 다시 실행하세요.

#### 일반적인 SharpHound 모드
```powershell
SharpHound.exe --CollectionMethods All               # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 03:09:41
```
Collector는 BloodHound GUI를 통해 수집되는 JSON을 생성합니다.

#### 도메인에 가입되지 않은 Windows 호스트에서 SharpHound 실행

operator VM이 대상 domain에 가입되어 있지 않다면 DNS를 DC로 지정하고, **network-only** shell을 시작한 다음, DC에서 `SYSVOL`/`NETLOGON`을 확인할 수 있는지 검증한 후 원격 domain을 대상으로 수집을 수행합니다:
```cmd
runas /netonly /user:CORP\svc_bh cmd.exe
net view \\dc01.corp.local
SharpHound.exe -d corp.local --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
```
이는 domain-joined되지 않아야 하는 disposable jump box 또는 operator workstation에 유용합니다.

#### Linux/macOS에서의 Cross-platform collection
```bash
# CE-compatible ZIP from Linux/macOS/Windows
rusthound-ce -d corp.local -u svc.collector@corp.local -p 'Passw0rd!' -z

# Quick LDAP-driven BloodHound dump from Linux
nxc ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --bloodhound --collection All
```
`RustHound-CE`는 non-Windows host에서 CE-compatible output이 필요할 때 좋은 기본 선택입니다. `NetExec`는 LDAP validation 또는 spraying에 이미 사용 중이며 빠르게 graph import를 수행하려는 경우 편리합니다. non-AD datasets의 경우 BloodHound OpenGraph는 [ShareHound](../../network-services-pentesting/pentesting-smb/README.md)와 같은 collectors로 확장할 수 있습니다.

### ADPathFinder (OpenGraph 경로 우선순위 지정)

[ADPathFinder](https://github.com/NetSPI/AD-PathFinder)는 graph가 너무 커서 수동으로 pivot하기 어려울 때 BloodHound CE/OpenGraph 위에서 동작합니다. 하나의 principal이 하나의 target에 도달할 수 있는지만 확인하는 대신, 다수의 low-privileged users와 computers에서 high-value objects까지의 shortest paths를 계산하고, 동일한 edges를 재사용하는 paths를 그룹화하며, 먼저 remediation해야 할 shared choke point를 보여 줍니다.
```bash
adpathfinder --setup-bloodhound-api
adpathfinder -i SharpHound.zip --ad
adpathfinder -i SharpHound.zip MSSQLHound.zip ConfigManBearPig.zip --ad --pwd Contoso,ContosoIT --ntds ntds.txt -p hashcat.potfile
```
`MSSQLHound` 및 `ConfigManBearPig` 데이터를 가져오면 하나의 finding이 [AD CS](ad-certificates.md), [MSSQL AD abuse](abusing-ad-mssql.md), [SCCM attack paths](sccm-management-point-relay-sql-policy-secrets.md)를 가로지를 수 있으므로, 이를 별도의 단서로 남겨 둘 필요가 없습니다. 공유 경로 예시:
```text
J.REPORTER > MSSQL_HasLogin > j.reporter > MSSQL_ExecuteAs > ReportSvc >
MSSQL_Connect > lab-sql01.training.local > MSSQL_LinkedAsAdmin > sccmdb.training.local >
MSSQL_ExecuteOnHost (as DA@TRAINING.LOCAL) > SCCMDB.TRAINING.LOCAL >
SCCM_AssignAllPermissions > SCCM_Site(TRN)
```
- 모든 edge에서 **effective security context**를 추적합니다. 일반 사용자에서 시작했더라도 하나의 transition이 privileged domain identity로 실행되는 순간 해당 경로는 domain-critical이 됩니다.
- 그룹화된 결과는 **choke-point remediation**에 적합합니다. 하나의 SQL impersonation permission, linked-server trust, certificate-template abuse path 또는 SCCM assignment를 제거하면 여러 shortest path를 한 번에 끊을 수 있습니다.
- **graph context**를 사용해 "medium" 결과의 우선순위를 다시 지정합니다. SMB signing 비활성화, WebClient 노출, delegation 실수 또는 NTLM-relayable SQL server는 침해된 노드에서 Domain Admins, Domain Controllers, CAs 또는 SCCM site servers로 이어지는 경로가 있을 때 더 높은 우선순위를 부여해야 합니다.
- `NTDS.dit` output과 hashcat potfile도 있다면 `--pwd`를 사용해 cracked password와 BloodHound properties를 상호 연관시킬 수 있습니다. 이를 통해 일반적인 password reuse와 privileged, Kerberoastable, AS-REP roastable 또는 path-relevant account에서 crack된 creds를 빠르게 구분할 수 있습니다.

### Privilege & logon-right collection

Windows **token privileges**(예: `SeBackupPrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`)는 DACL 검사를 우회할 수 있으므로, 이를 domain-wide로 매핑하면 ACL-only graph에서 놓치는 local LPE edge를 확인할 수 있습니다. **Logon rights**(`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeServiceLogonRight`, `SeBatchLogonRight` 및 이에 대응하는 `SeDeny*`)는 token이 생성되기도 전에 LSA에 의해 적용되며 deny가 우선하므로, lateral movement(RDP/SMB/scheduled task/service logon)을 실질적으로 제한합니다.

가능하면 **collectors를 elevated 상태로 실행**합니다. UAC는 interactive admin을 위해(`NtFilterToken`을 통해) filtered token을 생성하며, 이 과정에서 민감한 privileges를 제거하고 admin SID를 deny-only로 표시합니다. non-elevated shell에서 privileges를 열거하면 high-value privilege가 보이지 않으며 BloodHound도 해당 edge를 수집하지 못합니다.

이제 두 가지 상호 보완적인 SharpHound collection strategy를 사용할 수 있습니다.

- **GPO/SYSVOL parsing (stealthy, low-privilege):**
1. LDAP(`(objectCategory=groupPolicyContainer)`)를 통해 GPO를 열거하고 각 `gPCFileSysPath`를 읽습니다.
2. SYSVOL에서 `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`를 가져와 privilege/logon-right 이름을 SID에 매핑하는 `[Privilege Rights]` section을 parsing합니다.
3. OUs/sites/domains의 `gPLink`를 통해 GPO link를 resolve하고, linked container에 포함된 computers를 나열한 뒤 해당 rights를 해당 machines에 할당합니다.
4. 장점: normal user로도 동작하며 조용합니다. 단점: GPO를 통해 적용된 rights만 확인하므로 local tweak은 누락됩니다.

- **LSA RPC enumeration (noisy, accurate):**
- target에 local admin 권한이 있는 context에서 Local Security Policy를 열고, 각 privilege/logon right에 대해 `LsaEnumerateAccountsWithUserRight`를 호출하여 RPC를 통해 할당된 principals를 열거합니다.
- 장점: local 또는 GPO 외부에서 설정된 rights도 수집합니다. 단점: noisy network traffic이 발생하고 모든 host에서 admin 권한이 필요합니다.

**이러한 edge로 확인되는 abuse path 예시:** `CanRDP` ➜ 사용자가 `SeBackupPrivilege`도 보유한 host ➜ filtered token을 피하기 위해 elevated shell 시작 ➜ backup semantics를 사용해 restrictive DACL에도 불구하고 `SAM` 및 `SYSTEM` hive 읽기 ➜ 이를 exfiltrate한 뒤 `secretsdump.py`를 offline으로 실행하여 lateral movement/privilege escalation에 사용할 local Administrator NT hash 복구.

### Prioritising Kerberoasting with BloodHound

graph context를 사용해 roasting 대상을 좁힙니다.

1. ADWS-compatible collector로 한 번 수집한 뒤 offline에서 작업합니다.
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. ZIP을 import하고 compromised principal을 owned로 표시한 뒤, built-in query(*Kerberoastable Users*, *Shortest Paths to Domain Admins*)를 실행하여 admin/infra rights를 가진 SPN account를 확인합니다.
3. blast radius에 따라 SPN의 우선순위를 정합니다. crack하기 전에 `pwdLastSet`, `lastLogon` 및 허용된 encryption type을 검토합니다.
4. 선택한 ticket만 요청하고 offline에서 crack한 다음, 새 access 권한으로 BloodHound를 다시 query합니다.
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```

## Group3r

[Group3r](https://github.com/Group3r/Group3r)는 **Group Policy Objects**를 열거하고 misconfiguration을 강조합니다.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/)은 Active Directory의 **상태 점검**을 수행하고 위험 점수가 포함된 HTML 보고서를 생성합니다.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## References

- [BloodHound Community Edition v8, OpenGraph와 함께 출시: Active Directory 및 Entra ID를 넘어선 Identity Attack Paths](https://specterops.io/blog/2025/07/29/bloodhound-community-edition-v8-launches-with-opengraph-identity-attack-paths-beyond-active-directory-entra-id/)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
- [ACL을 넘어: BloodHound를 사용한 Windows 권한 상승 경로 매핑](https://www.synacktiv.com/en/publications/beyond-acls-mapping-windows-privilege-escalation-paths-with-bloodhound.html)
- [ADPathFinder: BloodHound CE에서 OpenGraph Attack Path 매핑](https://www.netspi.com/blog/technical-blog/network-pentesting/adpathfinder-opengraph-attack-path-mapping-in-bloodhound-ce/)

{{#include ../../banners/hacktricks-training.md}}
