# Active Directory Web Services (ADWS) Aufzählung & verdeckte Sammlung

{{#include ../../banners/hacktricks-training.md}}

## Was ist ADWS?

Active Directory Web Services (ADWS) ist **standardmäßig auf jedem Domain Controller seit Windows Server 2008 R2 aktiviert** und hört auf TCP **9389**. Trotz des Namens ist **kein HTTP beteiligt**. Stattdessen exponiert der Dienst LDAP-ähnliche Daten über einen Stack proprietärer .NET-Framing-Protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Da der Datenverkehr innerhalb dieser binären SOAP-Frames gekapselt ist und über einen unüblichen Port läuft, ist **die Aufzählung über ADWS deutlich weniger wahrscheinlich inspiziert, gefiltert oder per Signaturen erkannt als klassischer LDAP/389 & 636-Verkehr**. Für Operatoren bedeutet das:

* Heimlichere Aufklärung – Blue teams konzentrieren sich oft auf LDAP-Abfragen.
* Möglichkeit, von **non-Windows hosts (Linux, macOS)** zu sammeln, indem 9389/TCP durch einen SOCKS-Proxy getunnelt wird.
* Die gleichen Daten, die man über LDAP erhalten würde (users, groups, ACLs, schema, etc.), und die Möglichkeit, **writes** durchzuführen (z. B. `msDs-AllowedToActOnBehalfOfOtherIdentity` für **RBCD**).

ADWS-Interaktionen werden über WS-Enumeration implementiert: Jede Abfrage beginnt mit einer `Enumerate`-Nachricht, die den LDAP-Filter/Attribute definiert und einen `EnumerationContext` GUID zurückgibt, gefolgt von einer oder mehreren `Pull`-Nachrichten, die bis zum serverdefinierten Ergebnisfenster streamen. Kontexte laufen nach ~30 Minuten ab, daher muss Tooling entweder Ergebnisse seitenweise abrufen oder Filter aufteilen (Präfixabfragen pro CN), um den Zustand nicht zu verlieren. Beim Anfordern von Security Descriptors sollte die `LDAP_SERVER_SD_FLAGS_OID`-Control angegeben werden, um SACLs auszuschließen, andernfalls droppt ADWS einfach das `nTSecurityDescriptor`-Attribut aus seiner SOAP-Antwort.

> NOTE: ADWS wird auch von vielen RSAT GUI/PowerShell-Tools verwendet, sodass der Traffic mit legitimer Administratoraktivität verschmelzen kann.

## SoaPy – Nativer Python-Client

[SoaPy](https://github.com/logangoins/soapy) ist eine **vollständige Neuimplementierung des ADWS-Protokollstacks in reinem Python**. Es baut die NBFX/NBFSE/NNS/NMF-Frames Byte-für-Byte und erlaubt das Sammeln von Unix-ähnlichen Systemen, ohne die .NET-Runtime anzufassen.

### Hauptmerkmale

* Unterstützt **Proxying through SOCKS** (nützlich für C2 implants).
* Feinkörnige Suchfilter identisch zu LDAP `-q '(objectClass=user)'`.
* Optionale **Schreib-**Operationen ( `--set` / `--delete` ).
* **BOFHound output mode** für direkte Ingestion in BloodHound.
* `--parse`-Flag zur Aufbereitung von Zeitstempeln / `userAccountControl`, wenn menschliche Lesbarkeit erforderlich ist.

### Zielgerichtete Sammel-Flags & Schreib-Operationen

SoaPy wird mit kuratierten Schaltern ausgeliefert, die die häufigsten LDAP-Hunting-Aufgaben über ADWS replizieren: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, plus rohe `--query` / `--filter`-Knobs für benutzerdefinierte Pulls. Kombiniere diese mit Schreib-Primitiven wie `--rbcd <source>` (setzt `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN-Staging für targeted Kerberoasting) und `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Beispiel für eine zielgerichtete SPN-Suche, die nur `samAccountName` und `servicePrincipalName` zurückgibt:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Verwenden Sie denselben Host bzw. dieselben Zugangsdaten, um Funde sofort zu weaponise: dumpen Sie RBCD-capable Objekte mit `--rbcds`, und wenden Sie dann `--rbcd 'WEBSRV01$' --account 'FILE01$'` an, um eine Resource-Based Constrained Delegation-Kette vorzubereiten (siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) für den vollständigen Missbrauchspfad).

### Installation (Operator-Host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Ein praktischer Client für ADWS in Golang

Ähnlich wie soapy implementiert [sopa](https://github.com/Macmod/sopa) den ADWS-Protokollstack (MS-NNS + MC-NMF + SOAP) in Golang und bietet Kommandozeilen-Flags zum Ausführen von ADWS-Aufrufen wie:

* **Objektsuche & -abruf** - `query` / `get`
* **Objektlebenszyklus** - `create [user|computer|group|ou|container|custom]` und `delete`
* **Attributbearbeitung** - `attr [add|replace|delete]`
* **Account-Verwaltung** - `set-password` / `change-password`
* und weitere wie `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Hochvolumige ADWS-Erfassung (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ist ein .NET-Collector, der alle LDAP-Interaktionen innerhalb von ADWS hält und BloodHound v4-kompatibles JSON ausgibt. Er baut einmalig einen vollständigen Cache der Attribute `objectSid`, `objectGUID`, `distinguishedName` und `objectClass` auf (`--buildcache`) und verwendet diesen dann für hochvolumige `--bhdump`-, `--certdump`- (ADCS) oder `--dnsdump`-Durchläufe (AD-integrierter DNS), sodass nur etwa ~35 kritische Attribute den DC verlassen. AutoSplit (`--autosplit --threshold <N>`) teilt Abfragen automatisch nach CN-Präfix auf, um in großen Forests unter dem 30-minütigen EnumerationContext-Timeout zu bleiben.

Typischer Workflow auf einer an die Domäne angebundenen Operator-VM:
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
Exportierte JSON-Slots direkt in SharpHound/BloodHound-Workflows — siehe [BloodHound methodology](bloodhound.md) für Ideen zur nachgelagerten Graph-Visualisierung. AutoSplit macht SOAPHound in Multi-Millionen-Objekt-Forests widerstandsfähig und hält gleichzeitig die Anzahl der Abfragen niedriger als bei ADExplorer-ähnlichen Snapshots.

## Stealth AD-Collection-Workflow

Der folgende Workflow zeigt, wie man über ADWS **Domänen- & ADCS-Objekte** auflistet, sie in BloodHound JSON konvertiert und nach zertifikatbasierten Angriffswegen sucht – alles von Linux aus:

1. **Tunnel 9389/TCP** vom Zielnetzwerk zu deinem Rechner (z. B. via Chisel, Meterpreter, SSH dynamic port-forward, etc.). Setze `export HTTPS_PROXY=socks5://127.0.0.1:1080` oder nutze SoaPy’s `--proxyHost/--proxyPort`.

2. **Sammle das Root-Domänenobjekt:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Sammle ADCS-bezogene Objekte aus der Configuration NC:**
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
5. **Lade das ZIP hoch** in der BloodHound GUI und führe cypher queries wie `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` aus, um Zertifikats-Eskalationspfade (ESC1, ESC8, usw.) aufzudecken.

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
| ADWS-Enumerierung | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| ADWS-Dump mit hohem Volumen | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound-Import | [BOFHound](https://github.com/bohops/BOFHound) | Konvertiert SoaPy/ldapsearch-Logs |
| Kompromittierung von Zertifikaten | [Certipy](https://github.com/ly4k/Certipy) | Kann über denselben SOCKS-Proxy geroutet werden |
| ADWS-Enumerierung & Objektänderungen | [sopa](https://github.com/Macmod/sopa) | Generischer Client zur Schnittstelle mit bekannten ADWS-Endpunkten - ermöglicht Enumerierung, Objekterstellung, Attributänderungen und Passwortänderungen |

## Referenzen

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
