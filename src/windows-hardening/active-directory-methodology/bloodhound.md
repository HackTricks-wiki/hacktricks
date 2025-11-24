# BloodHound & Andere Active Directory Enumeration Tools

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
adws-enumeration.md
{{#endref}}

> HINWEIS: Diese Seite fasst einige der nützlichsten Dienstprogramme zusammen, um **enumerate** und **visualise** Active Directory Beziehungen. Für die Sammlung über den stealthy **Active Directory Web Services (ADWS)**-Kanal siehe die obige Referenz.

---

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) ist ein fortgeschrittener AD-Viewer & -Editor, der Folgendes ermöglicht:

* GUI-Durchsuchen des Verzeichnisbaums
* Bearbeitung von Objektattributen & Sicherheitsdeskriptoren
* Erstellung von Snapshots / Vergleich für Offline-Analysen

### Kurzanleitung

1. Starten Sie das Tool und verbinden Sie sich mit `dc01.corp.local` mit beliebigen Domain-Anmeldedaten.
2. Erstellen Sie einen Offline-Snapshot über `File ➜ Create Snapshot`.
3. Vergleichen Sie zwei Snapshots mit `File ➜ Compare`, um Berechtigungsabweichungen zu erkennen.

---

## ADRecon

[ADRecon](https://github.com/adrecon/ADRecon) extrahiert eine große Menge an Artefakten aus einer Domain (ACLs, GPOs, trusts, CA templates …) und erzeugt einen **Excel-Bericht**.
```powershell
# On a Windows host in the domain
PS C:\> .\ADRecon.ps1 -OutputDir C:\Temp\ADRecon
```
---

## BloodHound (Graphvisualisierung)

[BloodHound](https://github.com/BloodHoundAD/BloodHound) nutzt Graphentheorie + Neo4j, um verborgene Berechtigungsbeziehungen innerhalb von on-prem AD & Azure AD aufzudecken.

### Bereitstellung (Docker CE)
```bash
curl -L https://ghst.ly/getbhce | docker compose -f - up
# Web UI ➜ http://localhost:8080  (user: admin / password from logs)
```
### Sammler

* `SharpHound.exe` / `Invoke-BloodHound` – nativ oder PowerShell-Variante
* `AzureHound` – Azure AD enumeration
* **SoaPy + BOFHound** – ADWS collection (siehe Link oben)

#### Häufige SharpHound-Modi
```powershell
SharpHound.exe --CollectionMethods All           # Full sweep (noisy)
SharpHound.exe --CollectionMethods Group,LocalAdmin,Session,Trusts,ACL
SharpHound.exe --Stealth --LDAP                      # Low noise LDAP only
```
Die Collector erzeugen JSON, das über die BloodHound-GUI importiert wird.

---

## Priorisierung von Kerberoasting mit BloodHound

Graph-Kontext ist entscheidend, um lautes, wahlloses roasting zu vermeiden. Ein schlanker Workflow:

1. **Sammle einmalig alles** mit einem ADWS-kompatiblen Collector (z. B. RustHound-CE), damit du offline arbeiten und Pfade proben kannst, ohne den DC erneut zu kontaktieren:
```bash
rusthound-ce -d corp.local -u svc.collector -p 'Passw0rd!' -c All -z
```
2. **Importiere die ZIP, markiere das kompromittierte Principal als owned**, dann führe eingebaute Abfragen wie *Kerberoastable Users* und *Shortest Paths to Domain Admins* aus. Das hebt sofort Konten mit SPNs hervor, die nützliche Gruppenmitgliedschaften haben (Exchange, IT, tier0 Servicekonten, usw.).
3. **Priorisiere nach Blast-Radius** – konzentriere dich auf SPNs, die gemeinsam genutzte Infrastruktur kontrollieren oder Admin-Rechte besitzen, und überprüfe `pwdLastSet`, `lastLogon` und erlaubte Verschlüsselungstypen, bevor du Zeit mit Cracking verbringst.
4. **Fordere nur die Tickets an, die dich interessieren**. Tools wie NetExec können gezielt ausgewählte `sAMAccountName`s anvisieren, sodass jede LDAP ROAST-Anfrage eine klare Rechtfertigung hat:
```bash
netexec ldap dc01.corp.local -u svc.collector -p 'Passw0rd!' --kerberoasting kerberoast.txt --spn svc-sql
```
5. **Crack offline**, frage dann sofort BloodHound erneut ab, um die post-exploitation mit den neuen Privilegien zu planen.

Dieser Ansatz hält das Signal-Rausch-Verhältnis hoch, reduziert das erkennbare Volumen (keine Massen-SPN-Anfragen) und stellt sicher, dass jedes cracked ticket in sinnvolle privilege escalation-Schritte umgesetzt wird.

## Group3r

[Group3r](https://github.com/Group3r/Group3r) führt eine Enumeration von **Group Policy Objects** durch und hebt Fehlkonfigurationen hervor.
```bash
# Execute inside the domain
Group3r.exe -f gpo.log   # -s to stdout
```
---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) führt einen **Gesundheitscheck** von Active Directory durch und erstellt einen HTML-Bericht mit Risikobewertung.
```powershell
PingCastle.exe --healthcheck --server corp.local --user bob --password "P@ssw0rd!"
```
## Referenzen

- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [RustHound-CE](https://github.com/g0h4n/RustHound-CE)

{{#include ../../banners/hacktricks-training.md}}
