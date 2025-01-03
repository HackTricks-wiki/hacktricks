# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **주체(Subject)**는 인증서의 소유자를 나타냅니다.
- **공개 키(Public Key)**는 개인 키와 쌍을 이루어 인증서를 정당한 소유자와 연결합니다.
- **유효 기간(Validity Period)**은 **NotBefore** 및 **NotAfter** 날짜로 정의되며, 인증서의 유효 기간을 표시합니다.
- 고유한 **일련 번호(Serial Number)**는 인증 기관(CA)에서 제공하며 각 인증서를 식별합니다.
- **발급자(Issuer)**는 인증서를 발급한 CA를 나타냅니다.
- **주체 대체 이름(SubjectAlternativeName)**은 주체에 대한 추가 이름을 허용하여 식별 유연성을 향상시킵니다.
- **기본 제약 조건(Basic Constraints)**은 인증서가 CA용인지 최종 엔티티용인지 식별하고 사용 제한을 정의합니다.
- **확장 키 사용(Extended Key Usages, EKUs)**은 객체 식별자(OIDs)를 통해 코드 서명 또는 이메일 암호화와 같은 인증서의 특정 목적을 구분합니다.
- **서명 알고리즘(Signature Algorithm)**은 인증서 서명 방법을 지정합니다.
- **서명(Signature)**은 발급자의 개인 키로 생성되어 인증서의 진위를 보장합니다.

### Special Considerations

- **주체 대체 이름(SANs)**은 인증서의 적용 범위를 여러 신원으로 확장하여 여러 도메인을 가진 서버에 중요합니다. 안전한 발급 프로세스는 SAN 사양을 조작하는 공격자에 의한 사칭 위험을 피하는 데 필수적입니다.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS는 AD 포리스트 내에서 지정된 컨테이너를 통해 CA 인증서를 인식하며, 각 컨테이너는 고유한 역할을 수행합니다:

- **인증 기관(Certification Authorities)** 컨테이너는 신뢰할 수 있는 루트 CA 인증서를 보유합니다.
- **등록 서비스(Enrolment Services)** 컨테이너는 엔터프라이즈 CA 및 해당 인증서 템플릿을 자세히 설명합니다.
- **NTAuthCertificates** 객체는 AD 인증을 위해 승인된 CA 인증서를 포함합니다.
- **AIA(Authority Information Access)** 컨테이너는 중간 및 교차 CA 인증서를 통해 인증서 체인 검증을 용이하게 합니다.

### Certificate Acquisition: Client Certificate Request Flow

1. 요청 프로세스는 클라이언트가 엔터프라이즈 CA를 찾는 것으로 시작됩니다.
2. 공개-개인 키 쌍을 생성한 후, 공개 키 및 기타 세부 정보를 포함하는 CSR이 생성됩니다.
3. CA는 사용 가능한 인증서 템플릿에 대해 CSR을 평가하고 템플릿의 권한에 따라 인증서를 발급합니다.
4. 승인 후, CA는 개인 키로 인증서에 서명하고 클라이언트에게 반환합니다.

### Certificate Templates

AD 내에서 정의된 이러한 템플릿은 인증서 발급을 위한 설정 및 권한을 개요하며, 허용된 EKU 및 등록 또는 수정 권한을 포함하여 인증서 서비스에 대한 접근 관리를 위해 중요합니다.

## Certificate Enrollment

인증서 등록 프로세스는 관리자가 **인증서 템플릿을 생성**함으로써 시작되며, 이후 **엔터프라이즈 인증 기관(CA)**에 의해 **게시**됩니다. 이는 템플릿을 클라이언트 등록을 위해 사용할 수 있게 하며, 이는 Active Directory 객체의 `certificatetemplates` 필드에 템플릿 이름을 추가하여 달성됩니다.

클라이언트가 인증서를 요청하려면 **등록 권한**이 부여되어야 합니다. 이러한 권한은 인증서 템플릿 및 엔터프라이즈 CA 자체의 보안 설명자에 의해 정의됩니다. 요청이 성공적으로 이루어지려면 두 위치 모두에서 권한이 부여되어야 합니다.

### Template Enrollment Rights

이러한 권한은 접근 제어 항목(ACE)을 통해 지정되며, 다음과 같은 권한을 자세히 설명합니다:

- **인증서 등록(Certificate-Enrollment)** 및 **인증서 자동 등록(Certificate-AutoEnrollment)** 권한, 각각 특정 GUID와 연결됩니다.
- **확장 권한(ExtendedRights)**, 모든 확장 권한을 허용합니다.
- **전체 제어/일반 모든 권한(FullControl/GenericAll)**, 템플릿에 대한 완전한 제어를 제공합니다.

### Enterprise CA Enrollment Rights

CA의 권한은 보안 설명서에 명시되어 있으며, 인증 기관 관리 콘솔을 통해 접근할 수 있습니다. 일부 설정은 낮은 권한의 사용자에게 원격 접근을 허용할 수 있으며, 이는 보안 문제를 일으킬 수 있습니다.

### Additional Issuance Controls

특정 제어가 적용될 수 있습니다, 예를 들어:

- **관리자 승인(Manager Approval)**: 요청을 인증서 관리자가 승인할 때까지 보류 상태로 둡니다.
- **등록 에이전트 및 승인 서명(Enrolment Agents and Authorized Signatures)**: CSR에 필요한 서명의 수와 필요한 애플리케이션 정책 OID를 지정합니다.

### Methods to Request Certificates

인증서는 다음을 통해 요청할 수 있습니다:

1. **Windows 클라이언트 인증서 등록 프로토콜** (MS-WCCE), DCOM 인터페이스를 사용합니다.
2. **ICertPassage 원격 프로토콜** (MS-ICPR), 명명된 파이프 또는 TCP/IP를 통해.
3. **인증서 등록 웹 인터페이스**, 인증 기관 웹 등록 역할이 설치된 경우.
4. **인증서 등록 서비스** (CES), 인증서 등록 정책(CEP) 서비스와 함께.
5. **네트워크 장치 등록 서비스** (NDES) 네트워크 장치를 위한, 간단한 인증서 등록 프로토콜(SCEP)을 사용합니다.

Windows 사용자는 GUI(`certmgr.msc` 또는 `certlm.msc`) 또는 명령줄 도구(`certreq.exe` 또는 PowerShell의 `Get-Certificate` 명령)를 통해 인증서를 요청할 수도 있습니다.
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 인증서 인증

Active Directory (AD)는 인증서 인증을 지원하며, 주로 **Kerberos** 및 **Secure Channel (Schannel)** 프로토콜을 활용합니다.

### Kerberos 인증 프로세스

Kerberos 인증 프로세스에서 사용자의 Ticket Granting Ticket (TGT) 요청은 사용자의 인증서의 **개인 키**를 사용하여 서명됩니다. 이 요청은 도메인 컨트롤러에 의해 여러 검증을 거치며, 여기에는 인증서의 **유효성**, **경로**, 및 **폐기 상태**가 포함됩니다. 검증에는 인증서가 신뢰할 수 있는 출처에서 왔는지 확인하고 발급자의 존재를 **NTAUTH 인증서 저장소**에서 확인하는 것도 포함됩니다. 검증이 성공적으로 완료되면 TGT가 발급됩니다. AD의 **`NTAuthCertificates`** 객체는 다음 위치에 있습니다:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
신뢰를 구축하는 데 중앙 역할을 합니다.

### 보안 채널 (Schannel) 인증

Schannel은 안전한 TLS/SSL 연결을 용이하게 하며, 핸드셰이크 중 클라이언트는 인증서를 제시하고, 성공적으로 검증되면 접근을 허가합니다. 인증서를 AD 계정에 매핑하는 과정은 Kerberos의 **S4U2Self** 기능이나 인증서의 **주체 대체 이름 (SAN)** 등을 포함할 수 있습니다.

### AD 인증서 서비스 열거

AD의 인증서 서비스는 LDAP 쿼리를 통해 열거할 수 있으며, **엔터프라이즈 인증 기관 (CAs)** 및 그 구성에 대한 정보를 드러냅니다. 이는 특별한 권한 없이 도메인 인증된 모든 사용자가 접근할 수 있습니다. **[Certify](https://github.com/GhostPack/Certify)** 및 **[Certipy](https://github.com/ly4k/Certipy)**와 같은 도구는 AD CS 환경에서 열거 및 취약성 평가에 사용됩니다.

이 도구를 사용하는 명령어는 다음과 같습니다:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 참고문헌

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../banners/hacktricks-training.md}}
