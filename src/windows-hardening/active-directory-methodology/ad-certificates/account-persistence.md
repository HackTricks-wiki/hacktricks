# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**이것은 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)에서의 멋진 연구의 머신 지속성 장에 대한 간단한 요약입니다.**

## **인증서를 통한 활성 사용자 자격 증명 도난 이해 – PERSIST1**

사용자가 도메인 인증을 허용하는 인증서를 요청할 수 있는 시나리오에서, 공격자는 이 인증서를 **요청**하고 **탈취**하여 네트워크에서 **지속성**을 유지할 기회를 갖습니다. 기본적으로 Active Directory의 `User` 템플릿은 이러한 요청을 허용하지만, 때때로 비활성화될 수 있습니다.

[**Certify**](https://github.com/GhostPack/Certify)라는 도구를 사용하여 지속적인 액세스를 가능하게 하는 유효한 인증서를 검색할 수 있습니다:
```bash
Certify.exe find /clientauth
```
인증서의 힘은 인증서가 **소속된 사용자로서 인증할 수 있는 능력**에 있으며, 인증서가 **유효**한 한 비밀번호 변경과 관계없이 그렇습니다.

인증서는 `certmgr.msc`를 사용하여 그래픽 인터페이스를 통해 요청하거나 `certreq.exe`를 사용하여 명령줄을 통해 요청할 수 있습니다. **Certify**를 사용하면 인증서를 요청하는 과정이 다음과 같이 간소화됩니다:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
성공적인 요청 후, 인증서와 그 개인 키가 `.pem` 형식으로 생성됩니다. 이를 Windows 시스템에서 사용할 수 있는 `.pfx` 파일로 변환하기 위해 다음 명령이 사용됩니다:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` 파일은 대상 시스템에 업로드된 후 [**Rubeus**](https://github.com/GhostPack/Rubeus)라는 도구와 함께 사용되어 사용자의 티켓 부여 티켓(TGT)을 요청할 수 있으며, 공격자의 접근 권한을 인증서가 **유효**한 동안(일반적으로 1년) 연장합니다.
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
중요한 경고는 이 기술이 **THEFT5** 섹션에 설명된 다른 방법과 결합되어 공격자가 Local Security Authority Subsystem Service (LSASS)와 상호작용하지 않고도 계정의 **NTLM 해시**를 지속적으로 얻을 수 있게 한다는 점입니다. 이는 비승격된 컨텍스트에서 이루어지며, 장기적인 자격 증명 도용을 위한 더 은밀한 방법을 제공합니다.

## **인증서를 통한 머신 지속성 확보 - PERSIST2**

또 다른 방법은 손상된 시스템의 머신 계정을 인증서에 등록하는 것으로, 이러한 작업을 허용하는 기본 `Machine` 템플릿을 활용합니다. 공격자가 시스템에서 상승된 권한을 얻으면 **SYSTEM** 계정을 사용하여 인증서를 요청할 수 있으며, 이는 일종의 **지속성**을 제공합니다:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
이 접근 방식은 공격자가 머신 계정으로 **Kerberos**에 인증하고 **S4U2Self**를 활용하여 호스트의 모든 서비스에 대한 Kerberos 서비스 티켓을 얻을 수 있게 하여, 공격자에게 머신에 대한 지속적인 접근을 효과적으로 부여합니다.

## **인증서 갱신을 통한 지속성 연장 - PERSIST3**

논의된 마지막 방법은 인증서 템플릿의 **유효성** 및 **갱신 기간**을 활용하는 것입니다. 공격자는 인증서가 만료되기 전에 **갱신**함으로써 추가 티켓 등록 없이 Active Directory에 대한 인증을 유지할 수 있으며, 이는 인증서 기관(CA) 서버에 흔적을 남길 수 있습니다.

이 접근 방식은 CA 서버와의 상호작용을 최소화하여 탐지 위험을 줄이고, 관리자가 침입을 경고할 수 있는 아티팩트 생성을 피함으로써 **지속성 연장** 방법을 허용합니다.

{{#include ../../../banners/hacktricks-training.md}}
