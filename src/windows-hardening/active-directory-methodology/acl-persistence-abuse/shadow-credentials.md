# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#3f17" id="3f17"></a>

**이 기법에 관한 [모든 정보는 원문 게시물](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)을 확인하세요.**<sup>[[1]](#references)</sup>

요약하면, 사용자의 `msDS-KeyCredentialLink` 또는 컴퓨터의 **`msDS-KeyCredentialLink`**를 제어하면 공격자가 키 credential을 추가하고 PKINIT를 사용해 해당 객체로 인증할 수 있습니다. 또한 KDC와 계정이 필요한 흐름을 지원하는 경우, 그 결과로 얻은 티켓을 `S4U2Self`/user-to-user와 함께 사용해 객체의 NT hash를 복구할 수 있습니다.<sup>[[1]](#references)</sup>

원문 게시물에서는 대상의 NTLM hash가 포함된 고유한 **Service Ticket**을 얻기 위해 **public-private key 인증 credential**을 설정하는 방법을 설명합니다. 이 과정에는 Privilege Attribute Certificate (PAC) 내에 암호화된 NTLM_SUPPLEMENTAL_CREDENTIAL이 포함되며, 이를 복호화할 수 있습니다.<sup>[[1]](#references)</sup>

### 요구 사항

이 기법을 사용하려면 다음 조건을 충족해야 합니다.<sup>[[1]](#references)</sup>

- Windows Server 2016 Domain Controller가 최소 하나 필요합니다.
- Domain Controller에 server authentication 디지털 인증서가 설치되어 있어야 합니다.
- 디렉터리 스키마에 `msDS-KeyCredentialLink`가 포함되어야 합니다. 연구에서 설명하는 실질적인 플랫폼 요구 사항은 Windows Server 2016 이상 DC와 KDC의 PKINIT 지원 인증서입니다. 도메인 functional-level 레이블만으로 악용 가능성이 결정된다고 가정하지 말고, 도메인의 스키마와 DC 구성을 확인하세요.
- 대상 객체의 msDS-KeyCredentialLink 속성을 수정할 수 있도록 위임된 권한이 있는 계정이 필요합니다.

## 악용

컴퓨터 객체에 대한 Key Trust 악용에는 Ticket Granting Ticket (TGT)과 NTLM hash를 얻는 것 이상의 단계가 포함됩니다. 다음과 같은 방법이 있습니다.<sup>[[1]](#references)</sup>

1. 의도한 호스트에서 권한이 높은 사용자로 동작하기 위한 **RC4 silver ticket**을 생성합니다.
2. TGT를 **S4U2Self**와 함께 사용해 **권한이 높은 사용자**를 가장합니다. 이때 서비스 이름에 서비스 클래스를 추가하도록 Service Ticket을 변경해야 합니다.

Key Trust 악용의 중요한 장점은 공격자가 생성한 private key만 사용한다는 점입니다. 따라서 잠재적으로 취약한 계정으로 위임할 필요가 없고, 제거하기 어려울 수 있는 컴퓨터 계정을 만들 필요도 없습니다.<sup>[[1]](#references)</sup>

## 도구

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker는 DSInternals를 사용해 C#에서 `msDS-KeyCredentialLink`를 조작합니다. Whisker와 Python 대응 도구인 **pyWhisker**는 key credential 추가, 목록 조회, 제거 및 초기화를 지원합니다.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker**의 기능은 다음과 같습니다.

- **Add**: 키 쌍을 생성하고 key credential을 추가합니다.
- **List**: 모든 key credential 항목을 표시합니다.
- **Remove**: 지정된 key credential을 삭제합니다.
- **Clear**: 모든 key credential을 지웁니다. 이로 인해 정상적인 WHfB 사용이 중단될 수 있습니다.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker는 Impacket와 PyDSInternals를 사용해 **UNIX 계열 시스템**에서도 워크플로를 지원하며, 나열/추가/제거 및 JSON 가져오기/내보내기 작업을 포함합니다.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray는 `GenericWrite`/`GenericAll` 등의 권한이 있는 도메인 객체를 열거하고, 광범위하게 key credentials 추가를 시도하며, 정리/재귀 모드를 포함합니다. 광범위한 spraying은 작업을 방해하고 눈에 띄므로, 명시적으로 대상을 지정하고 정확한 제거를 위해 추가된 각 DeviceID를 기록해 두세요.<sup>[[3]](#references)</sup>

직접 LDAP가 필터링되는 경우 ADWS를 통해 key-credential 쓰기를 수행할 수 있습니다. [SOAPy ADWS 워크플로](../adws-enumeration.md#shadow-credentials-over-adws)를 참조하세요.<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: 계정 탈취를 위한 Key Trust Account Mapping 악용](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink 조작을 통해 AD 계정을 탈취하는 도구](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - 도메인 전반에 Shadow Credentials를 spraying하는 도구](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials 도구의 Python 버전](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
