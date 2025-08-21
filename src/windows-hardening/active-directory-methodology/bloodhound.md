# BloodHound & Other Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
adws-enumeration.md
{{#endref}}

> NOTE: 이 페이지는 **열거**하고 **시각화**하는 데 유용한 도구들을 그룹화합니다. 스텔스 **Active Directory Web Services (ADWS)** 채널을 통한 수집에 대한 내용은 위의 참조를 확인하세요.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals)는 다음을 허용하는 고급 **AD 뷰어 및 편집기**입니다:

* 디렉토리 트리의 GUI 탐색
* 객체 속성 및 보안 설명자 편집
* 오프라인 분석을 위한 스냅샷 생성 / 비교

### Quick usage

1. 도구를 시작하고 도메인 자격 증명을 사용하여 `dc01.corp.local`에 연결합니다.
2. `File ➜ Create Snapshot`을 통해 오프라인 스냅샷을 생성합니다.
3. `File ➜ Compare`를 사용하여 두 스냅샷을 비교하여 권한 변화를 확인합니다.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon)은 도메인에서 대량의 아티팩트(ACL, GPO, 신뢰, CA 템플릿 등)를 추출하고 **Excel 보고서**를 생성합니다.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (그래프 시각화)

[BloodHound](https://github.com/BloodHoundAD/BloodHound)는 그래프 이론 + Neo4j를 사용하여 온프레미스 AD 및 Azure AD 내의 숨겨진 권한 관계를 드러냅니다.

### 배포 (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### 수집기

* `SharpHound.exe` / `Invoke-BloodHound` – 네이티브 또는 PowerShell 변형
* `AzureHound` – Azure AD 열거
* **SoaPy + BOFHound** – ADWS 수집 (상단의 링크 참조)

#### 일반 SharpHound 모드
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
수집기는 BloodHound GUI를 통해 수집된 JSON을 생성합니다.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r)은 **그룹 정책 개체**를 열거하고 잘못된 구성을 강조합니다.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/)는 Active Directory의 **건강 점검**을 수행하고 위험 점수를 포함한 HTML 보고서를 생성합니다.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
{{#include ../../banners/hacktricks-training.md}}
