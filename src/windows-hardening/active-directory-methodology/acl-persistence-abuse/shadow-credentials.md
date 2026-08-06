# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#3f17" id="3f17"></a>

**[이 기법에 관한 모든 정보는 원문 게시물](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)을 확인하세요.**<sup>[[1]](#references)</sup>

**요약**하면, 사용자의 컴퓨터의 **msDS-KeyCredentialLink** 속성에 쓸 수 있다면 해당 **객체의 NT hash**를 가져올 수 있습니다.<sup>[[1]](#references)</sup>

게시물에서는 대상의 NTLM hash가 포함된 고유한 **Service Ticket**을 획득하기 위해 **public-private key authentication credentials**를 설정하는 방법을 설명합니다. 이 과정에는 Privilege Attribute Certificate (PAC) 내부의 암호화된 NTLM_SUPPLEMENTAL_CREDENTIAL이 포함되며, 이를 복호화할 수 있습니다.<sup>[[1]](#references)</sup>

### 요구 사항

이 기법을 적용하려면 다음 조건을 충족해야 합니다.<sup>[[1]](#references)</sup>

- 최소 하나의 Windows Server 2016 Domain Controller가 필요합니다.
- Domain Controller에 server authentication digital certificate가 설치되어 있어야 합니다.
- Active Directory가 Windows Server 2016 Functional Level이어야 합니다.
- 대상 객체의 msDS-KeyCredentialLink attribute를 수정할 수 있도록 위임된 권한이 있는 계정이 필요합니다.

## Abuse

컴퓨터 객체에 대한 Key Trust abuse에는 Ticket Granting Ticket (TGT)과 NTLM hash를 획득하는 것 이상의 단계가 포함됩니다. 사용할 수 있는 옵션은 다음과 같습니다.<sup>[[1]](#references)</sup>

1. 대상 호스트에서 privileged users로 동작하기 위한 **RC4 silver ticket**을 생성합니다.
2. TGT를 **S4U2Self**와 함께 사용하여 **privileged users**를 impersonation합니다. 이때 Service Ticket을 변경하여 service name에 service class를 추가해야 합니다.

Key Trust abuse의 주요 장점은 공격자가 생성한 private key에만 의존한다는 점입니다. 따라서 잠재적으로 취약한 계정으로 delegation할 필요가 없으며, 제거하기 어려울 수 있는 computer account를 생성할 필요도 없습니다.<sup>[[1]](#references)</sup>

## 도구

### [**Whisker**](https://github.com/eladshamir/Whisker)

DSInternals를 기반으로 하며 이 attack을 위한 C# interface를 제공합니다. Whisker와 Python counterpart인 **pyWhisker**를 사용하면 `msDS-KeyCredentialLink` attribute를 조작하여 Active Directory 계정을 제어할 수 있습니다. 이러한 도구는 대상 객체에서 key credentials를 추가, 나열, 제거 및 초기화하는 등 다양한 작업을 지원합니다.

**Whisker** functions include:

- **Add**: key pair를 생성하고 key credential을 추가합니다.
- **List**: 모든 key credential entries를 표시합니다.
- **Remove**: 지정된 key credential을 삭제합니다.
- **Clear**: 모든 key credentials를 삭제하며, 이로 인해 정상적인 WHfB 사용이 중단될 수 있습니다.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

**UNIX 기반 시스템**으로 Whisker 기능을 확장하며, Impacket와 PyDSInternals를 활용해 KeyCredentials의 목록 조회, 추가 및 제거와 JSON 형식의 가져오기 및 내보내기를 포함한 포괄적인 exploitation 기능을 제공합니다.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray는 **광범위한 사용자 그룹이 도메인 객체에 대해 보유할 수 있는 GenericWrite/GenericAll 권한을 악용하여** ShadowCredentials를 광범위하게 적용하는 것을 목표로 합니다. 이 과정에는 도메인에 로그인하고, 도메인의 기능 수준을 확인하며, 도메인 객체를 열거하고, TGT 획득 및 NT hash 공개를 위해 KeyCredentials를 추가하는 작업이 포함됩니다. 정리 옵션과 재귀적 exploitation 전술을 통해 활용성이 향상됩니다.

## 참고 자료

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
