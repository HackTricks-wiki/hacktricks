# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#3f17" id="3f17"></a>

**[이 technique에 관한 모든 정보가 있는 원문 게시물](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)을 확인하세요.**<sup>[[1]](#references)</sup>

요약하면, 사용자의 또는 컴퓨터의 **`msDS-KeyCredentialLink`**를 제어할 수 있으면 공격자는 key credential을 추가하고, PKINIT을 사용해 해당 객체로 인증할 수 있습니다. 또한 KDC와 계정이 필요한 flow를 지원하는 경우, 그 결과로 얻은 ticket을 `S4U2Self`/user-to-user와 함께 사용하여 객체의 NT hash를 복구할 수 있습니다.<sup>[[1]](#references)</sup>

해당 게시물에서는 **public-private key authentication credentials**를 설정하여 대상의 NTLM hash가 포함된 고유한 **Service Ticket**을 획득하는 method를 설명합니다. 이 process에는 Privilege Attribute Certificate (PAC) 내부에 있는 암호화된 NTLM_SUPPLEMENTAL_CREDENTIAL이 포함되며, 이를 복호화할 수 있습니다.<sup>[[1]](#references)</sup>

### 요구 사항

이 technique을 적용하려면 다음 조건을 충족해야 합니다:<sup>[[1]](#references)</sup>

- 최소 하나의 Windows Server 2016 Domain Controller가 필요합니다.
- Domain Controller에 server authentication digital certificate가 설치되어 있어야 합니다.
- directory schema에 `msDS-KeyCredentialLink`가 포함되어 있어야 합니다. 연구에서 설명한 실질적인 platform requirements는 Windows Server 2016 이상 DC와 KDC의 PKINIT-capable certificate입니다. domain functional-level label만으로 exploitability가 결정된다고 가정하지 말고, domain의 schema/DC 구성을 확인하세요.
- 대상 객체의 msDS-KeyCredentialLink attribute를 수정할 수 있도록 delegated rights가 부여된 계정이 필요합니다.

## 악용

컴퓨터 객체에 대한 Key Trust 악용에는 Ticket Granting Ticket (TGT)과 NTLM hash를 획득하는 것 이상의 steps가 포함됩니다. 가능한 options는 다음과 같습니다:<sup>[[1]](#references)</sup>

1. 의도한 host에서 privileged users로 동작할 수 있도록 **RC4 silver ticket**을 생성합니다.
2. TGT를 `S4U2Self`와 함께 사용하여 **privileged users**를 impersonation합니다. 이 경우 service name에 service class를 추가하도록 Service Ticket을 변경해야 합니다.

Key Trust 악용의 중요한 장점은 공격자가 생성한 private key에만 의존한다는 점입니다. 따라서 잠재적으로 취약한 계정으로의 delegation을 피할 수 있고, 제거하기 어려울 수 있는 computer account를 생성할 필요도 없습니다.<sup>[[1]](#references)</sup>

## 도구

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker는 C#에서 DSInternals를 사용하여 `msDS-KeyCredentialLink`를 조작합니다. Whisker와 그 Python counterpart인 **pyWhisker**는 key credential의 추가, 조회, 제거 및 초기화를 지원합니다.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** functions include:

- **Add**: key pair를 생성하고 key credential을 추가합니다.
- **List**: 모든 key credential entry를 표시합니다.
- **Remove**: 지정된 key credential을 삭제합니다.
- **Clear**: 모든 key credential을 제거하며, 이로 인해 정상적인 WHfB 사용이 중단될 수 있습니다.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker는 Impacket와 PyDSInternals를 사용하여 **UNIX-like systems**에서 list/add/remove 및 JSON import/export 작업을 수행할 수 있는 workflow를 제공합니다.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray는 operator가 `GenericWrite`/`GenericAll`과 같은 권한을 보유한 domain objects를 열거하고, 광범위하게 key credentials를 추가하려 시도하며, cleanup/recursive modes를 포함합니다. 광범위한 spraying은 disruptive하고 눈에 잘 띄므로, 명시적인 targets를 사용하고 추가된 각 DeviceID를 보관하여 정확하게 제거하십시오.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Account Takeover를 위한 Key Trust Account Mapping 악용](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - msDS-KeyCredentialLink를 조작하여 AD accounts를 탈취하는 Tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - domain 전체에 Shadow Credentials를 spray하는 Tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool의 Python version](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
