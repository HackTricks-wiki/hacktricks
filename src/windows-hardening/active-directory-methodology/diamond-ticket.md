# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, ein diamond ticket ist ein TGT, mit dem man **auf jeden Dienst als beliebiger Benutzer zugreifen** kann. Ein golden ticket wird komplett offline gefälscht, mit dem krbtgt-Hash dieser Domäne verschlüsselt und dann in eine Anmeldesitzung injiziert. Da Domänencontroller ausgestellte TGTs nicht nachverfolgen, akzeptieren sie problemlos TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.

Es gibt zwei gängige Techniken, um den Einsatz von golden tickets zu erkennen:

- Suche nach TGS-REQs, die keine entsprechende AS-REQ haben.
- Suche nach TGTs mit unrealistischen Werten, z. B. Mimikatz' voreingestellter 10‑Jahres‑Gültigkeitszeitraum.

Ein diamond ticket entsteht, indem die Felder eines legitimen TGT, das von einem DC ausgestellt wurde, verändert werden. Dies wird erreicht, indem man ein TGT anfordert, es mit dem krbtgt-Hash der Domäne entschlüsselt, die gewünschten Felder des Tickets modifiziert und es dann wieder verschlüsselt. Dadurch werden die zwei zuvor genannten Nachteile eines golden ticket überwunden, weil:

- TGS-REQs eine vorausgehende AS-REQ haben.
- Das TGT von einem DC ausgestellt wurde, sodass es alle korrekten Details aus der Kerberos-Policy der Domäne enthält. Auch wenn diese Details in einem golden ticket genau gefälscht werden können, ist das komplexer und fehleranfälliger.

### Anforderungen & Ablauf

- Kryptographisches Material: der krbtgt AES256-Schlüssel (vorzuziehen) oder NTLM-Hash, um das TGT zu entschlüsseln und erneut zu signieren.
- Legitimes TGT-BLOB: erhalten mit `/tgtdeleg`, `asktgt`, `s4u` oder durch Exportieren von Tickets aus dem Speicher.
- Kontextdaten: die RID des Zielbenutzers, Gruppen‑RIDs/SIDs und (optional) LDAP‑abgeleitete PAC‑Attribute.
- Service‑Schlüssel (nur falls Service-Tickets neu erstellt werden sollen): AES‑Schlüssel des zu imitierenden Service‑SPN.

1. Beschaffe ein TGT für einen kontrollierten Benutzer via AS-REQ (Rubeus `/tgtdeleg` ist praktisch, weil es den Client dazu zwingt, den Kerberos GSS-API‑Ablauf ohne Anmeldeinformationen auszuführen).
2. Entschlüssele das zurückgegebene TGT mit dem krbtgt‑Schlüssel, passe PAC‑Attribute an (Benutzer, Gruppen, Anmeldeinformationen, SIDs, Geräteansprüche usw.).
3. Verschlüssele/signiere das Ticket erneut mit demselben krbtgt‑Schlüssel und injiziere es in die aktuelle Anmeldesitzung (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional: Wiederhole den Vorgang für ein Service‑Ticket, indem du ein gültiges TGT‑BLOB sowie den Ziel‑Service‑Schlüssel bereitstellst, um auf dem Netzwerk unauffällig zu bleiben.

### Aktualisierte Rubeus-Tradecraft (2024+)

Jüngste Arbeiten von Huntress modernisierten die `diamond`-Aktion in Rubeus, indem die `/ldap`- und `/opsec`-Verbesserungen portiert wurden, die zuvor nur für golden/silver tickets existierten. `/ldap` füllt nun automatisch präzise PAC‑Attribute direkt aus AD (user profile, logon hours, sidHistory, domain policies) aus, während `/opsec` den AS-REQ/AS-REP‑Ablauf durch Durchführung der zweistufigen Pre‑Auth‑Sequenz und das Erzwingen von AES‑only‑Krypto von einem Windows‑Client nicht unterscheidbar macht. Dies reduziert deutlich offensichtliche Indikatoren wie leere Geräte‑IDs oder unrealistische Gültigkeitszeiträume.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (mit optionalen `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC policy data des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Retry, nullt störende Flags und beschränkt sich auf AES256.
- `/tgtdeleg` hält deine Hände vom Klartext-Passwort oder dem NTLM/AES-Schlüssel des Opfers fern, während es dennoch ein entschlüsselbares TGT zurückgibt.

### Service-ticket recutting

Das gleiche Rubeus-Refresh fügte die Möglichkeit hinzu, die diamond-Technik auf TGS-Blobs anzuwenden. Indem du `diamond` ein **base64-encoded TGT** (aus `asktgt`, `/tgtdeleg` oder einem zuvor gefälschten TGT), den **service SPN**, und den **service AES key** zuführst, kannst du realistisch wirkende Service-Tickets erstellen, ohne den KDC zu berühren — effektiv ein unauffälligeres silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn Sie bereits einen Service-Account-Schlüssel kontrollieren (z. B. mit `lsadump::lsa /inject` oder `secretsdump.py` gedumpt) und ein einmaliges TGS erstellen möchten, das AD-Richtlinien, Zeiträume und PAC-Daten perfekt abbildet, ohne neuen AS/TGS-Verkehr zu erzeugen.

### OPSEC & detection notes

- Die traditionellen hunter heuristics (TGS without AS, decade-long lifetimes) gelten weiterhin für golden tickets, aber diamond tickets treten hauptsächlich zutage, wenn der **PAC-Inhalt oder die Gruppenabbildung unmöglich erscheint**. Füllen Sie jedes PAC-Feld (logon hours, user profile paths, device IDs) aus, damit automatisierte Vergleiche die Fälschung nicht sofort als solche markieren.
- **Do not oversubscribe groups/RIDs**. Wenn Sie nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigen, belassen Sie es dabei und stellen Sie sicher, dass das Zielkonto plausibel an anderer Stelle in AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` sind ein Hinweis.
- Splunk's Security Content project stellt Attack-Range-Telemetrie für diamond tickets sowie Detections wie *Windows Domain Admin Impersonation Indicator* bereit, die ungewöhnliche Event ID 4768/4769/4624-Sequenzen und PAC-Gruppenänderungen korreliert. Das Abspielen dieses Datasets (oder das Generieren eigener Daten mit den oben genannten Befehlen) hilft, die SOC-Abdeckung für T1558.001 zu validieren und liefert konkrete Alert-Logik, die Sie beim Umgehen berücksichtigen können.

## Referenzen

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
