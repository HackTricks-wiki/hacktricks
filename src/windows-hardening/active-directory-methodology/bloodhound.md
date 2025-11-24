# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: 이 페이지는 Active Directory 관계를 **enumerate** 및 **visualise** 하기 위한 가장 유용한 유틸리티들을 모아둔 것입니다. 은밀한 **Active Directory Web Services (ADWS)** 채널을 통한 수집은 위의 레퍼런스를 확인하세요.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals)는 다음을 제공하는 고급 **AD viewer & editor** 입니다:

* 디렉터리 트리를 GUI로 탐색
* 개체 속성 및 보안 디스크립터 편집
* 오프라인 분석을 위한 스냅샷 생성/비교

### Quick usage

1. 도구를 시작하고 임의의 도메인 자격증명으로 `dc01.corp.local`에 연결합니다.
2. `File ➜ Create Snapshot`를 통해 오프라인 스냅샷을 만듭니다.
3. 권한 변화를 찾으려면 `File ➜ Compare`로 두 스냅샷을 비교하세요.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon)은 도메인에서 많은 아티팩트(ACLs, GPOs, trusts, CA templates …)를 추출하여 **Excel 보고서**를 생성합니다.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (그래프 시각화)

[BloodHound](https://github.com/BloodHoundAD/BloodHound)은 그래프 이론 + Neo4j를 사용하여 온프레미스 AD 및 Azure AD 내부의 숨겨진 권한 관계를 드러냅니다.

### 배포 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 수집기

* `SharpHound.exe` / `Invoke-BloodHound` – 네이티브 또는 PowerShell 변형
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (상단의 링크 참조)

#### 일반적인 SharpHound 모드
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
수집기들은 JSON을 생성하며, 이는 BloodHound GUI를 통해 로드됩니다.

---

## BloodHound로 Kerberoasting 우선순위 지정

그래프 컨텍스트는 소음이 많고 무차별적인 roasting을 피하는 데 필수적입니다. 간단한 워크플로:

1. **한 번만 모두 수집** using an ADWS-compatible collector (e.g. RustHound-CE) so you can work offline and rehearse paths without touching the DC again:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **ZIP을 임포트하고 침해된 principal을 owned로 표시한 다음**, *Kerberoastable Users* 및 *Shortest Paths to Domain Admins* 같은 내장 쿼리를 실행하세요. 이는 Exchange, IT, tier0 service accounts 등 유용한 그룹 멤버십을 가진 SPN 보유 계정을 즉시 강조합니다.
3. **Prioritise by blast radius** – 공유 인프라를 제어하거나 관리자 권한을 가진 SPN에 집중하고, cracking cycles을 들이기 전에 `pwdLastSet`, `lastLogon`, 및 허용된 암호화 유형을 확인하세요.
4. **Request only the tickets you care about**. Tools like NetExec can target selected `sAMAccountName`s so that each LDAP ROAST request has a clear justification:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, 그런 다음 즉시 BloodHound를 다시 쿼리하여 새로운 권한으로 post-exploitation을 계획하세요.

이 접근법은 신호 대 잡음비를 높게 유지하고, 탐지 가능한 트래픽 양을 줄이며(대규모 SPN 요청 없음), 크랙된 각 티켓이 의미 있는 권한 상승 단계로 이어지도록 보장합니다.

## Group3r

[Group3r](https://github.com/Group3r/Group3r)은 **Group Policy Objects**를 열거하고 잘못된 구성을 강조합니다.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/)는 Active Directory의 상태를 검사하는 **health-check**를 수행하고 위험 점수로 평가된 HTML 보고서를 생성합니다.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## 참고 문헌

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
