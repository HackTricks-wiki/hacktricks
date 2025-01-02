# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**이 기술에 대한 [모든 정보는 원본 게시물을 확인하세요](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

**요약**: 사용자의 **msDS-KeyCredentialLink** 속성에 쓸 수 있다면, 해당 객체의 **NT 해시**를 가져올 수 있습니다.

게시물에서는 **공개-개인 키 인증 자격 증명**을 설정하여 대상의 NTLM 해시를 포함하는 고유한 **서비스 티켓**을 획득하는 방법이 설명되어 있습니다. 이 과정에는 암호화된 NTLM_SUPPLEMENTAL_CREDENTIAL이 포함된 권한 속성 인증서(PAC)가 포함되며, 이는 복호화할 수 있습니다.

### Requirements

이 기술을 적용하려면 특정 조건을 충족해야 합니다:

- 최소한 하나의 Windows Server 2016 도메인 컨트롤러가 필요합니다.
- 도메인 컨트롤러에는 서버 인증 디지털 인증서가 설치되어 있어야 합니다.
- Active Directory는 Windows Server 2016 기능 수준이어야 합니다.
- 대상 객체의 msDS-KeyCredentialLink 속성을 수정할 수 있는 권한이 있는 계정이 필요합니다.

## Abuse

컴퓨터 객체에 대한 Key Trust의 남용은 티켓 부여 티켓(TGT) 및 NTLM 해시를 얻는 것을 넘어서는 단계를 포함합니다. 옵션은 다음과 같습니다:

1. 의도한 호스트에서 특권 사용자를 가장하기 위해 **RC4 실버 티켓**을 생성합니다.
2. **S4U2Self**와 함께 TGT를 사용하여 **특권 사용자**를 가장하며, 서비스 이름에 서비스 클래스를 추가하기 위해 서비스 티켓을 수정해야 합니다.

Key Trust 남용의 중요한 이점은 공격자가 생성한 개인 키로 제한되어 있어, 잠재적으로 취약한 계정으로의 위임을 피하고, 제거하기 어려울 수 있는 컴퓨터 계정을 생성할 필요가 없다는 점입니다.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

이 도구는 DSInternals를 기반으로 하여 이 공격을 위한 C# 인터페이스를 제공합니다. Whisker와 그 Python 버전인 **pyWhisker**는 `msDS-KeyCredentialLink` 속성을 조작하여 Active Directory 계정을 제어할 수 있게 해줍니다. 이러한 도구는 대상 객체에서 키 자격 증명을 추가, 나열, 제거 및 지우는 다양한 작업을 지원합니다.

**Whisker** 기능은 다음과 같습니다:

- **Add**: 키 쌍을 생성하고 키 자격 증명을 추가합니다.
- **List**: 모든 키 자격 증명 항목을 표시합니다.
- **Remove**: 지정된 키 자격 증명을 삭제합니다.
- **Clear**: 모든 키 자격 증명을 지워, 합법적인 WHfB 사용에 방해가 될 수 있습니다.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

UNIX 기반 시스템에 Whisker 기능을 확장하며, 포괄적인 악용 기능을 위해 Impacket과 PyDSInternals를 활용하여 KeyCredentials를 나열, 추가 및 제거하고, JSON 형식으로 가져오고 내보내는 기능을 포함합니다.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray는 **도메인 객체에 대해 넓은 사용자 그룹이 가질 수 있는 GenericWrite/GenericAll 권한을 악용하여 ShadowCredentials를 광범위하게 적용하는 것을 목표로 합니다.** 여기에는 도메인에 로그인하고, 도메인의 기능 수준을 확인하고, 도메인 객체를 열거하며, TGT 획득 및 NT 해시 공개를 위한 KeyCredentials 추가를 시도하는 과정이 포함됩니다. 정리 옵션과 재귀적 악용 전술이 유용성을 높입니다.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
