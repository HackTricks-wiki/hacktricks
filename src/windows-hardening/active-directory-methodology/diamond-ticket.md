# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Wie ein golden ticket** ist ein diamond ticket ein TGT, der verwendet werden kann, um **auf jeden Service als beliebiger Benutzer zuzugreifen**. Ein golden ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash der Domain verschlüsselt und anschließend in eine Logon-Session eingeschleust. Da Domain Controller keine TGTs nachverfolgen, die sie selbst legitim ausgestellt haben, akzeptieren sie problemlos TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt wurden.<sup>[[1]](#references)</sup>

Es gibt zwei gängige Techniken, um die Verwendung von golden tickets zu erkennen:

- Nach TGS-REQs suchen, für die kein entsprechendes AS-REQ existiert.
- Nach TGTs mit auffälligen Werten suchen, beispielsweise der standardmäßigen 10-jährigen Gültigkeitsdauer von Mimikatz.

Ein **diamond ticket** wird erstellt, indem die **Felder eines legitimen, von einem DC ausgestellten TGTs geändert werden**. Dazu wird ein **TGT angefordert**, mit dem krbtgt-Hash der Domain **entschlüsselt**, die gewünschten Felder des Tickets **geändert** und anschließend **erneut verschlüsselt**. Dadurch werden die beiden zuvor genannten Schwachstellen eines golden tickets **überwunden**, weil:<sup>[[1]](#references)</sup>

- TGS-REQs ein vorausgehendes AS-REQ haben.
- Der TGT von einem DC ausgestellt wurde und daher alle korrekten Details der Kerberos-Richtlinie der Domain enthält. Obwohl diese bei einem golden ticket präzise gefälscht werden können, ist dies komplexer und anfälliger für Fehler.

### Anforderungen & Ablauf

- **Kryptografisches Material**: der krbtgt-AES256-Schlüssel (bevorzugt) oder NTLM-Hash, um den TGT zu entschlüsseln und erneut zu signieren.
- **Legitimer TGT-Blob**: erhalten mit `/tgtdeleg`, `asktgt`, `s4u` oder durch Exportieren von Tickets aus dem Speicher.
- **Kontextdaten**: die RID des Zielbenutzers, Gruppen-RIDs/SIDs und optional aus LDAP abgeleitete PAC-Attribute.
- **Service-Schlüssel** (nur wenn Service-Tickets neu erstellt werden sollen): AES-Schlüssel des zu impersonierenden Service-SPNs.

1. Einen TGT für einen beliebigen kontrollierten Benutzer über AS-REQ beziehen (`/tgtdeleg` von Rubeus ist praktisch, da der Client dadurch ohne Credentials zum Kerberos-GSS-API-Austausch gezwungen wird).
2. Den zurückgegebenen TGT mit dem krbtgt-Schlüssel entschlüsseln und PAC-Attribute (Benutzer, Gruppen, Logon-Informationen, SIDs, Device Claims usw.) anpassen.
3. Das Ticket mit demselben krbtgt-Schlüssel erneut verschlüsseln/signieren und in die aktuelle Logon-Session injizieren (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional den Vorgang für ein Service-Ticket wiederholen, indem ein gültiger TGT-Blob zusammen mit dem Schlüssel des Ziel-Services angegeben wird, um unauffällig im Netzwerk zu bleiben.

### Aktualisierte Rubeus-Techniken (2024+)

Neuere Arbeiten von Huntress haben die `diamond`-Action in Rubeus modernisiert, indem die zuvor nur für golden/silver tickets vorhandenen Verbesserungen `/ldap` und `/opsec` portiert wurden. `/ldap` ruft nun realen PAC-Kontext ab, indem LDAP abgefragt und SYSVOL eingebunden wird, um Konto-/Gruppenattribute sowie die Kerberos-/Passwort-Richtlinie zu extrahieren (z. B. `GptTmpl.inf`). `/opsec` sorgt dafür, dass der AS-REQ/AS-REP-Ablauf dem Verhalten von Windows entspricht, indem der zweistufige Preauth-Austausch durchgeführt und AES-only sowie realistische KDCOptions erzwungen werden. Dadurch werden offensichtliche Indikatoren wie fehlende PAC-Felder oder nicht zur Richtlinie passende Gültigkeitsdauern erheblich reduziert.<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (mit optionalem `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC-Richtliniendaten des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Wiederholungsversuch, setzt auffällige Flags auf null und beschränkt sich auf AES256.
- `/tgtdeleg` sorgt dafür, dass du weder das Klartextpasswort noch den NTLM/AES-Schlüssel des Opfers benötigst, und trotzdem ein entschlüsselbares TGT zurückerhältst.

### Service-Ticket-Neuzuschnitt

Das gleiche Rubeus-Refresh fügte die Möglichkeit hinzu, die Diamond-Technik auf TGS-Blobs anzuwenden. Indem du `diamond` ein **base64-codiertes TGT** (von `asktgt`, `/tgtdeleg` oder einem zuvor gefälschten TGT), den **Service-SPN** und den **Service-AES-Schlüssel** übergibst, kannst du realistische Service-Tickets erstellen, ohne den KDC zu kontaktieren – praktisch ein unauffälligeres silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn du bereits über einen Service-Account-Key verfügst (z. B. mit `lsadump::lsa /inject` oder `secretsdump.py` gedumpt) und ein einmaliges TGS ausstellen möchtest, das exakt der AD-Policy, den Zeitverläufen und den PAC-Daten entspricht, ohne neuen AS/TGS-Traffic zu erzeugen.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Eine neuere Variante, die manchmal **sapphire ticket** genannt wird, kombiniert die „real TGT“-Basis von Diamond mit **S4U2self+U2U**, um einen privilegierten PAC zu stehlen und in das eigene TGT einzusetzen. Statt zusätzliche SIDs zu erfinden, forderst du ein U2U-S4U2self-Ticket für einen Benutzer mit hohen Privilegien an, wobei der `sname` auf den Requester mit niedrigen Privilegien zielt. Der KRB_TGS_REQ überträgt das TGT des Requesters in `additional-tickets` und setzt `ENC-TKT-IN-SKEY`, sodass das Service-Ticket mit dem Key dieses Benutzers entschlüsselt werden kann. Anschließend extrahierst du den privilegierten PAC und fügst ihn in dein legitimes TGT ein, bevor du ihn mit dem krbtgt-Key erneut signierst.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket enthält inzwischen Sapphire-Support über `-impersonate` + `-request` (Live-KDC-Austausch):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` akzeptiert einen Benutzernamen oder eine SID; `-request` erfordert gültige Live-Benutzer-Credentials sowie krbtgt-Schlüsselmaterial (AES/NTLM), um Tickets zu entschlüsseln und zu patchen.

Wichtige OPSEC-Merkmale bei Verwendung dieser Variante:<sup>[[5]](#references)</sup>

- TGS-REQ enthält `ENC-TKT-IN-SKEY` und `additional-tickets` (das Opfer-TGT) – ein seltenes Muster im normalen Datenverkehr.
- `sname` entspricht häufig dem anfordernden Benutzer (Self-Service-Zugriff), und Event ID 4769 zeigt den Aufrufer und das Ziel als denselben SPN/Benutzer.
- Rechne mit zusammengehörigen 4768/4769-Einträgen mit demselben Clientcomputer, aber unterschiedlichen CNAMES (Anforderer mit geringen Rechten gegenüber privilegiertem PAC-Eigentümer).

### OPSEC- und Erkennungshinweise

- Die herkömmlichen Hunter-Heuristiken (TGS ohne AS, jahrzehntelange Gültigkeitsdauer) gelten weiterhin für Golden Tickets, aber Diamond Tickets treten hauptsächlich dann hervor, wenn der **PAC-Inhalt oder die Gruppenzuordnung unmöglich erscheint**. Fülle jedes PAC-Feld (Anmeldezeiten, Benutzerprofilpfade, Geräte-IDs) aus, damit automatisierte Vergleiche die Fälschung nicht sofort erkennen.<sup>[[3]](#references)</sup>
- **Überfülle Gruppen/RIDs nicht**. Wenn du nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigst, belasse es dabei und stelle sicher, dass das Zielkonto an anderer Stelle in AD plausibel Mitglied dieser Gruppen ist. Übermäßig viele `ExtraSids` sind ein eindeutiges Indiz.
- Swaps im Sapphire-Stil hinterlassen U2U-Fingerabdrücke: `ENC-TKT-IN-SKEY` + `additional-tickets` sowie ein `sname`, das in 4769 auf einen Benutzer (häufig den Anforderer) verweist, und ein nachfolgender 4624-Logon, der aus dem gefälschten Ticket stammt. Korreliere diese Felder, anstatt nur nach Lücken ohne AS-REQ zu suchen.<sup>[[5]](#references)</sup>
- Microsoft hat begonnen, die **Ausstellung von RC4-Service-Tickets** aufgrund von CVE-2026-20833 schrittweise einzustellen. Die Durchsetzung von ausschließlich AES-basierten Etypes auf dem KDC härtet die Domain und entspricht zugleich den Diamond-/Sapphire-Tools (/opsec erzwingt bereits AES). Das Einmischen von RC4 in gefälschte PACs wird zunehmend auffallen.<sup>[[6]](#references)</sup>
- Splunks Security Content project stellt Telemetrie aus Attack Ranges für Diamond Tickets sowie Erkennungen wie *Windows Domain Admin Impersonation Indicator* bereit. Diese korrelieren ungewöhnliche Sequenzen aus Event ID 4768/4769/4624 und Änderungen an PAC-Gruppen. Das Wiederholen dieses Datensatzes (oder das Erzeugen eines eigenen Datensatzes mit den obigen Befehlen) hilft dabei, die SOC-Abdeckung für T1558.001 zu validieren und liefert gleichzeitig konkrete Alert-Logik zur Umgehung.<sup>[[4]](#references)</sup>

## Referenzen

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
