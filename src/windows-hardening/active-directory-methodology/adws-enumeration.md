# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **seit Windows Server 2008 R2 standardmäßig auf jedem Domain Controller aktiviert** und lauscht auf TCP **9389**. Trotz des Namens kommt **kein HTTP zum Einsatz**. Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stack proprietärer .NET-Framing-Protokolle bereit:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Datenverkehr in diese binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port läuft, ist es **deutlich unwahrscheinlicher, dass Enumeration über ADWS überwacht, gefiltert oder anhand von Signaturen erkannt wird als klassischer LDAP-/389- und 636-Datenverkehr**. Für Operatoren bedeutet das:<sup>[[1]](#references)[[7]](#references)</sup>

* Unauffälligere Recon – Blue Teams konzentrieren sich oft auf LDAP-Abfragen.
* Daten können auch von **Nicht-Windows-Hosts (Linux, macOS)** gesammelt werden, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Dieselben Daten, die über LDAP verfügbar sind (Benutzer, Gruppen, ACLs, Schema usw.), und die Möglichkeit, **Schreibvorgänge** auszuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die LDAP-Filter/Attribute definiert und eine `EnumerationContext`-GUID zurückgibt. Darauf folgen eine oder mehrere `Pull`-Nachrichten, die Ergebnisse bis zum vom Server festgelegten Limit streamen.<sup>[[7]](#references)</sup> Kontexte laufen nach etwa 30 Minuten ab. Daher müssen Tools Ergebnisse entweder seitenweise abrufen oder Filter aufteilen (Präfixabfragen pro CN), um den Verlust des Zustands zu vermeiden.<sup>[[8]](#references)</sup> Bei Abfragen von Sicherheitsbeschreibungen muss das Steuerelement `LDAP_SERVER_SD_FLAGS_OID` angegeben werden, um SACLs auszuschließen. Andernfalls lässt ADWS das Attribut `nTSecurityDescriptor` einfach aus seiner SOAP-Antwort weg.

> HINWEIS: Viele RSAT-GUI-/PowerShell-Tools verwenden ebenfalls ADWS. Der Datenverkehr kann daher mit legitimer Admin-Aktivität verschmelzen.

## SoaPy – Nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokoll-Stacks in reinem Python**. Es erstellt die NBFX/NBFSE/NNS/NMF-Frames bytegenau und ermöglicht so die Datensammlung von Unix-ähnlichen Systemen, ohne die .NET-Runtime zu verwenden.<sup>[[1]](#references)[[2]](#references)</sup>

### Hauptfunktionen

* Unterstützt **Proxy-Verbindungen über SOCKS** (nützlich von C2-Implants aus).
* Detaillierte Suchfilter, identisch mit LDAP, z. B. `-q '(objectClass=user)'`.
* Gezielte **Schreibvorgänge** für RBCD, SPNs, Kontoflags und Schlüssel-Credentials.<sup>[[2]](#references)</sup>
* Die SOAPy-Ausgabe kann von **BOFHound** geparst und in BloodHound importiert werden.<sup>[[2]](#references)[[3]](#references)</sup>
* `--parse`-Flag zur lesbaren Darstellung von Zeitstempeln und `userAccountControl`, wenn eine menschenlesbare Ausgabe benötigt wird.<sup>[[2]](#references)</sup>

### Gezielte Collection-Flags und Schreibvorgänge

SoaPy bietet eine Auswahl an Schaltern, die die häufigsten LDAP-Hunting-Aufgaben über ADWS abbilden: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds` sowie die Optionen `--query` / `--filter` für benutzerdefinierte Abrufe. Dazu kommen Schreibfunktionen wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für gezieltes Kerberoasting) und `--asrep` (aktiviert `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Beispiel für eine gezielte SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Verwende denselben Host/dieselben Zugangsdaten, um die Findings sofort auszunutzen: Dump die bereits für RBCD konfigurierten Objekte mit `--rbcds` und führe dann `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` aus, um eine Resource-Based Constrained Delegation-Kette vorzubereiten (den vollständigen Abuse-Pfad findest du unter [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).<sup>[[2]](#references)</sup>

### Installation (Operator-Host)

Installiere die aktuelle SOAPy CLI aus dem Upstream-Repository; der Name der ausführbaren Datei unterscheidet auf Unix-ähnlichen Systemen zwischen Groß- und Kleinschreibung.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Ticket-only-Sammlung über einen SOCKS-Pivot

Wenn ein Zugang einen Kerberos-Ticket, aber kein Klartextpasswort liefert, konvertiere eine `.kirbi`-Ticketdatei wie unter [Pass the Ticket](pass-the-ticket.md) beschrieben in einen `ccache` und verweise SOAPy auf diesen Cache. Ein Ticket für den LDAP-Dienst des DC kann im dokumentierten SOAPy-ADWS-Workflow verwendet werden; leite sowohl den ADWS- als auch den Kerberos-Datenverkehr über den Pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials over ADWS

Wenn der aktuelle Principal Schreibzugriff auf `msDS-KeyCredentialLink` eines Zielobjekts hat, kann SOAPy über ADWS ein Key Credential hinzufügen und das entsprechende PFX exportieren. Notiere die zurückgegebene DeviceID, um es gezielt zu entfernen, statt das gesamte Attribut zu löschen. Verwende das PFX für PKINIT, wie unter [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) beschrieben.<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump über ADWS (Linux/Windows)

* Fork von `ldapdomaindump`, der LDAP-Abfragen durch ADWS-Aufrufe über TCP/9389 ersetzt, um LDAP-Signaturtreffer zu reduzieren.
* Führt eine anfängliche Erreichbarkeitsprüfung für Port 9389 durch, sofern nicht `--force` angegeben wird (überspringt die Prüfung, wenn Portscans auffällig oder gefiltert sind).
* Laut README erfolgreich gegen Microsoft Defender for Endpoint und CrowdStrike Falcon getestet.<sup>[[4]](#references)</sup>

### Installation

```bash
pipx install .
```

### Verwendung

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Typische Ausgabe protokolliert die Erreichbarkeitsprüfung auf Port 9389, den ADWS-Bind sowie den Start und Abschluss des Dumps:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokollstack (MS-NNS + MC-NMF + SOAP) in Golang und stellt Kommandozeilen-Flags bereit, um ADWS-Aufrufe wie die folgenden auszuführen:<sup>[[5]](#references)</sup>

* **Objektsuche und -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Kontoverwaltung** - `set-password` / `change-password`
* und weitere wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]` usw.

### Wichtige Protokollzuordnungen

* LDAP-ähnliche Suchvorgänge werden über **WS-Enumeration** (`Enumerate` + `Pull`) mit Attributprojektion, Bereichssteuerung (Base/OneLevel/Subtree) und Paginierung ausgeführt.
* Zum Abrufen einzelner Objekte wird **WS-Transfer** `Get` verwendet; Attributänderungen erfolgen mit `Put`, Löschungen mit `Delete`.
* Die integrierte Objekterstellung verwendet **WS-Transfer ResourceFactory**; benutzerdefinierte Objekte verwenden eine durch YAML-Vorlagen gesteuerte **IMDA AddRequest**.
* Kennwortoperationen sind **MS-ADCAP**-Aktionen (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Unauthentifizierte Metadatenermittlung (mex)

ADWS stellt WS-MetadataExchange ohne Anmeldedaten bereit. Das ist eine schnelle Möglichkeit, die Erreichbarkeit zu überprüfen, bevor man sich authentifiziert:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Hinweise zur DNS/DC-Erkennung und zum Kerberos-Targeting

Sopa kann DCs über SRV auflösen, wenn `--dc` weggelassen und `--domain` angegeben wird. Es fragt in dieser Reihenfolge ab und verwendet das Ziel mit der höchsten Priorität:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

In der Praxis sollte ein vom DC kontrollierter Resolver verwendet werden, um Fehler in segmentierten Umgebungen zu vermeiden:

* `--dns <DC-IP>` verwenden, damit **alle** SRV-/PTR-/Forward-Lookups über den DC-DNS laufen.
* `--dns-tcp` verwenden, wenn UDP blockiert ist oder SRV-Antworten groß sind.
* Wenn `--dc` eine IP-Adresse ist, führt sopa immer eine **Reverse-PTR**-Abfrage durch: Der ADWS-Adressfilter `wsa:To` erfordert einen FQDN, auch ohne Kerberos. Wenn die Reverse-Zone fehlt, direkt einen DC-FQDN angeben.<sup>[[5]](#references)</sup>

Beispiel (IP + Kerberos, DNS-Abfragen werden über den DC erzwungen):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Authentifizierungsoptionen

Neben Klartextpasswörtern unterstützt sopa **NT-Hashes**, **Kerberos-AES-Schlüssel**, **ccache** und **PKINIT-Zertifikate** (PFX oder PEM) für die ADWS-Authentifizierung. Bei Verwendung von `--aes-key`, `-c` (ccache) oder zertifikatsbasierten Optionen wird Kerberos impliziert.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Erstellung benutzerdefinierter Objekte mithilfe von Vorlagen

Für beliebige Objektklassen verwendet der Befehl `create custom` eine YAML-Vorlage, die einer IMDA-`AddRequest` entspricht:<sup>[[5]](#references)</sup>

* `parentDN` und `rdn` definieren den Container und den relativen DN.
* `attributes[].name` unterstützt `cn` oder den namespaced Wert `addata:cn`.
* `attributes[].type` akzeptiert `string|int|bool|base64|hex` oder explizite `xsd:*`-Werte.
* Fügen Sie **nicht** `ad:relativeDistinguishedName` oder `ad:container-hierarchy-parent` ein; sopa fügt sie automatisch hinzu.
* `hex`-Werte werden in `xsd:base64Binary` umgewandelt. Verwenden Sie `value: ""`, um leere Zeichenfolgen festzulegen.

## SOAPHound – ADWS-Sammlung mit hohem Datenvolumen (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Sammler, der alle LDAP-Interaktionen innerhalb von ADWS hält und mit BloodHound v4 kompatibles JSON ausgibt. Zunächst erstellt er einen vollständigen Cache mit `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` (`--buildcache`). Anschließend verwendet er ihn für umfangreiche `--bhdump`-, `--certdump`- (ADCS) oder `--dnsdump`-Durchläufe (AD-integriertes DNS), sodass nur etwa 35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) unterteilt Abfragen automatisch nach CN-Präfix, um in großen Forests das 30-minütige Timeout für EnumerationContext einzuhalten.<sup>[[8]](#references)</sup>

Typischer Workflow auf einer domänengebundenen Operator-VM:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

Exportierte JSON-Daten lassen sich direkt in SharpHound/BloodHound-Workflows einbinden – siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Graphdarstellung. AutoSplit macht SOAPHound auch in Gesamtstrukturen mit mehreren Millionen Objekten robust und hält dabei die Abfragezahl niedriger als bei ADExplorer-ähnlichen Snapshots.

## Stealth-AD-Erfassungsworkflow

Der folgende Workflow zeigt, wie sich **Domänen- und ADCS-Objekte** über ADWS enumerieren, in BloodHound-JSON umwandeln und nach zertifikatbasierten Angriffspfaden durchsuchen lassen – alles unter Linux:

1. **Tunneln Sie 9389/TCP** vom Zielnetzwerk zu Ihrem Rechner (z. B. über Chisel, Meterpreter, SSH Dynamic Port Forwarding usw.). Leiten Sie den Raw-TCP-Client über SOCKS mit `proxychains4 SOAPy ...` (konfigurieren Sie die SOCKS5-Adresse in `proxychains4.conf`); `HTTPS_PROXY` leitet dieses Nicht-HTTP-Protokoll nicht weiter.<sup>[[9]](#references)</sup>

2. **Erfassen Sie das Stamm-Domänenobjekt:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **ADCS-bezogene Objekte aus dem Configuration NC sammeln:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **In BloodHound konvertieren:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Laden Sie die ZIP-Datei hoch** in der BloodHound-GUI und führen Sie Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8 usw.) aufzudecken.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Verwenden Sie bei Schreibzugriff auf das Zielcomputerobjekt die RBCD-Aktion von SOAPy statt einer rohen Sicherheitsdeskriptor-Zeichenfolge. Hier ist `WEBSRV01$` die kontrollierte Quelle und `FILE01$` das Ziel, dessen Attribut geändert wird.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Setze die Kerberos-S4U-Kette in [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) fort.

## Tooling Summary

| Zweck | Tool | Hinweise |
|---------|------|-------|
| ADWS-Aufzählung | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, Lesen/Schreiben |
| ADWS-Dump mit hohem Volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, Cache-first, BH/ADCS/DNS-Modi |
| BloodHound-Import | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy-/ldapsearch-Logs |
| Zertifikatskompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy geleitet werden |
| ADWS-Aufzählung und Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Generischer Client für die Kommunikation mit bekannten ADWS-Endpunkten – ermöglicht Aufzählungen, das Erstellen von Objekten, Attributänderungen und Passwortänderungen |



## References

- [1] [SpecterOps – SOAP(y) verwenden – Ein Leitfaden für Operatoren zur unauffälligen AD-Erfassung mit ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy auf GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound auf GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump auf GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa auf GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Spezifikationen für MC-NBFX, MC-NBFSE, MS-NNS und MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Unauffällige Aufzählung von Active-Directory-Umgebungen über ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – SOAPHound-Tool zur Erfassung von Active-Directory-Daten über ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy-Wiki – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy-Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
