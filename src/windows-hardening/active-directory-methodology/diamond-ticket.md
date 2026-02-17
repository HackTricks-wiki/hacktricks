# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

Wie ein golden ticket ist ein diamond ticket ein TGT, das verwendet werden kann, um auf jeden Service als beliebiger Benutzer zuzugreifen. Ein golden ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash dieser Domäne verschlüsselt und dann in eine Anmeldesitzung geladen. Da Domänencontroller ausgestellte TGTs nicht nachverfolgen, akzeptieren sie TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind, problemlos.

Es gibt zwei gängige Techniken, um die Verwendung von golden tickets zu erkennen:

- Suche nach TGS-REQs, die keine entsprechende AS-REQ haben.
- Achte auf TGTs mit unrealistischen Werten, z. B. der standardmäßigen 10-Jahres-Laufzeit von Mimikatz.

Ein diamond ticket wird erstellt, indem die Felder eines legitimen, von einem DC ausgestellten TGT geändert werden. Dies wird erreicht, indem man ein TGT anfordert, es mit dem krbtgt-Hash der Domäne entschlüsselt, die gewünschten Felder des Tickets modifiziert und es danach wieder verschlüsselt/signiert. Dadurch werden die beiden zuvor genannten Nachteile eines golden ticket überwunden, weil:

- TGS-REQs werden eine vorausgehende AS-REQ haben.
- Das TGT wurde von einem DC ausgestellt, daher enthält es alle korrekten Details der Kerberos-Richtlinie der Domäne. Auch wenn diese in einem golden ticket akkurat gefälscht werden können, ist das komplizierter und fehleranfälliger.

### Anforderungen & Ablauf

- **Kryptografisches Material**: der krbtgt AES256-Schlüssel (bevorzugt) oder der NTLM-Hash, um das TGT zu entschlüsseln und erneut zu signieren.
- **Legitimer TGT blob**: beschafft mit `/tgtdeleg`, `asktgt`, `s4u` oder durch Exportieren von Tickets aus dem Speicher.
- **Kontextdaten**: die Zielbenutzer-RID, Gruppen-RIDs/SIDs und (optional) LDAP-abgeleitete PAC-Attribute.
- **Service keys** (nur falls du planst, Service-Tickets neu zu erstellen): AES-Key des zu impersonierenden Service-SPN.

1. Erhalte ein TGT für einen beliebigen kontrollierten Benutzer via AS-REQ (Rubeus `/tgtdeleg` ist praktisch, weil es den Client dazu zwingt, den Kerberos GSS-API-Ablauf ohne Anmeldedaten durchzuführen).
2. Entschlüssele das zurückgegebene TGT mit dem krbtgt-Schlüssel, passe PAC-Attribute an (Benutzer, Gruppen, Anmeldeinformationen, SIDs, Geräte-Claims, etc.).
3. Verschlüssele/signiere das Ticket erneut mit demselben krbtgt-Schlüssel und injiziere es in die aktuelle Anmeldesitzung (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional: Wiederhole den Vorgang für ein Service-Ticket, indem du ein gültiges TGT-Blob zusammen mit dem Ziel-Service-Schlüssel bereitstellst, um auf dem Wire möglichst unauffällig zu bleiben.

### Aktualisierte Rubeus tradecraft (2024+)

Jüngste Arbeiten von Huntress haben die `diamond`-Aktion in Rubeus modernisiert, indem die `/ldap`- und `/opsec`-Verbesserungen portiert wurden, die zuvor nur für golden/silver tickets existierten. `/ldap` füllt jetzt automatisch präzise PAC-Attribute direkt aus AD (Benutzerprofil, logon hours, sidHistory, domain policies), während `/opsec` den AS-REQ/AS-REP-Fluss gegenüber einem Windows-Client ununterscheidbar macht, indem die zweistufige Pre-Auth-Sequenz ausgeführt und ausschließlich AES-Krypto erzwungen wird. Dadurch werden offensichtliche Indikatoren wie leere Device-IDs oder unrealistische Gültigkeitszeiträume drastisch reduziert.
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
- `/ldap` (mit optionalen `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC-Policy-Daten des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt ein Windows-ähnliches AS-REQ-Retry, nullt auffällige Flags und bleibt bei AES256.

### Service-ticket-Rekonstruktion

Das gleiche Rubeus-Refresh fügte die Möglichkeit hinzu, die diamond technique auf TGS-Blobs anzuwenden. Indem man `diamond` ein **base64-encoded TGT** (aus `asktgt`, `/tgtdeleg` oder einem zuvor gefälschten TGT), den **service SPN** und den **service AES key** zuführt, kann man realistische service tickets erzeugen, ohne den KDC zu berühren — effektiv ein unauffälligerer silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn Sie bereits einen Service-Account-Schlüssel kontrollieren (z. B. gedumpt mit `lsadump::lsa /inject` oder `secretsdump.py`) und ein einmaliges TGS erstellen möchten, das perfekt den AD-Richtlinien, Zeitvorgaben und PAC-Daten entspricht, ohne neuen AS/TGS-Verkehr zu erzeugen.

### Sapphire-style PAC swaps (2025)

Eine neuere Variante, manchmal als **sapphire ticket** bezeichnet, kombiniert Diamond's "real TGT" Basis mit **S4U2self+U2U**, um ein privilegiertes PAC zu stehlen und in Ihr eigenes TGT einzusetzen. Anstatt zusätzliche SIDs zu erfinden, fordern Sie ein U2U S4U2self-Ticket für einen hochprivilegierten Benutzer an, extrahieren dieses PAC und fügen es in Ihr legitimes TGT ein, bevor Sie es mit dem krbtgt key neu signieren. Da U2U `ENC-TKT-IN-SKEY` setzt, sieht der resultierende Netzwerkverkehr wie ein legitimer Benutzer-zu-Benutzer-Austausch aus.

Minimale Linux-seitige Reproduktion mit Impacket's gepatchtem `ticketer.py` (fügt sapphire-Unterstützung hinzu):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — selten im normalen Netzwerkverkehr.
- `sname` often equals the requesting user (Self-Service-Zugriff) and Event ID 4769 shows the caller and target as the same SPN/user.
- Expect paired 4768/4769 entries with the same client computer but different CNAMES (low-priv requester vs. privileged PAC owner).

### OPSEC & Erkennungsnotizen

- Die traditionellen Hunter-Heuristiken (TGS ohne AS, jahrzehntelange Lifetimes) gelten weiterhin für golden tickets, aber diamond tickets treten vor allem dann auf, wenn der **PAC-Inhalt oder die Gruppenabbildung unmöglich** erscheint. Füllen Sie jedes PAC-Feld (logon hours, user profile paths, device IDs) aus, damit automatisierte Vergleiche die Fälschung nicht sofort markieren.
- **Weisen Sie Gruppen/RIDs nicht übermäßig zu**. Wenn Sie nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigen, belassen Sie es dabei und stellen Sie sicher, dass das Zielkonto plausibel an anderer Stelle im AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` verraten die Manipulation.
- Sapphire-style swaps leave U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` in 4769, and a follow-up 4624 logon sourced from the forged ticket. Korrrelieren Sie diese Felder, anstatt nur nach no-AS-REQ-Lücken zu suchen.
- Microsoft started phasing out **RC4 service ticket issuance** because of CVE-2026-20833; das Erzwingen von AES-only etypes auf dem KDC härtet die Domain und stimmt mit diamond/sapphire-Tooling überein (/opsec erzwingt bereits AES). Das Einmischen von RC4 in gefälschte PACs wird zunehmend auffallen.
- Splunk's Security Content project distributes attack-range telemetry for diamond tickets plus detections such as *Windows Domain Admin Impersonation Indicator*, which correlates unusual Event ID 4768/4769/4624 sequences and PAC group changes. Das Abspielen dieses Datasets (oder das Erzeugen eines eigenen mit den oben genannten Befehlen) hilft, die SOC-Abdeckung für T1558.001 zu validieren und liefert konkrete Alert-Logik, die es zu umgehen gilt.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
