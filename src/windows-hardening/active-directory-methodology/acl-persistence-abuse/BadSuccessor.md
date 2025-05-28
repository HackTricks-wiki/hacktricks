# Missbrauch von Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Delegierte verwaltete Dienstkonten (**dMSAs**) sind ein brandneuer AD-Prinzipientyp, der mit **Windows Server 2025** eingeführt wurde. Sie sind dafür konzipiert, veraltete Dienstkonten zu ersetzen, indem sie eine Ein-Klick-"Migration" ermöglichen, die automatisch die Service Principal Names (SPNs), Gruppenmitgliedschaften, Delegationseinstellungen und sogar kryptografische Schlüssel des alten Kontos in das neue dMSA kopiert, was Anwendungen einen nahtlosen Übergang ermöglicht und das Risiko von Kerberoasting eliminiert.

Akamai-Forscher fanden heraus, dass ein einzelnes Attribut — **`msDS‑ManagedAccountPrecededByLink`** — dem KDC mitteilt, welches veraltete Konto ein dMSA "nachfolgt". Wenn ein Angreifer dieses Attribut schreiben kann (und **`msDS‑DelegatedMSAState` → 2** umschaltet), wird der KDC bereitwillig ein PAC erstellen, das **jede SID des gewählten Opfers erbt**, was es dem dMSA effektiv ermöglicht, jeden Benutzer, einschließlich Domain-Admins, zu impersonieren.

## Was genau ist ein dMSA?

* Basierend auf **gMSA**-Technologie, aber als neue AD-Klasse **`msDS‑DelegatedManagedServiceAccount`** gespeichert.
* Unterstützt eine **Opt-in-Migration**: Der Aufruf von `Start‑ADServiceAccountMigration` verknüpft das dMSA mit dem veralteten Konto, gewährt dem veralteten Konto Schreibzugriff auf `msDS‑GroupMSAMembership` und schaltet `msDS‑DelegatedMSAState` = 1 um.
* Nach `Complete‑ADServiceAccountMigration` wird das abgelöste Konto deaktiviert und das dMSA wird voll funktionsfähig; jeder Host, der zuvor das veraltete Konto verwendet hat, ist automatisch berechtigt, das Passwort des dMSA abzurufen.
* Während der Authentifizierung bettet der KDC einen **KERB‑SUPERSEDED‑BY‑USER**-Hinweis ein, sodass Windows 11/24H2-Clients transparent mit dem dMSA erneut versuchen.

## Anforderungen für den Angriff
1. **Mindestens ein Windows Server 2025 DC**, damit die dMSA LDAP-Klasse und die KDC-Logik existieren.
2. **Beliebige Objekt-Erstellungs- oder Attribut-Schreibrechte auf einer OU** (beliebige OU) – z.B. `Create msDS‑DelegatedManagedServiceAccount` oder einfach **Create All Child Objects**. Akamai fand heraus, dass 91 % der realen Mandanten solche "harmlosen" OU-Berechtigungen an Nicht-Administratoren gewähren.
3. Fähigkeit, Tools (PowerShell/Rubeus) von einem beliebigen domänenverbundenen Host auszuführen, um Kerberos-Tickets anzufordern.
*Keine Kontrolle über den Opferbenutzer ist erforderlich; der Angriff berührt das Zielkonto niemals direkt.*

## Schritt-für-Schritt: BadSuccessor*Privilegieneskalation

1. **Finden oder Erstellen eines dMSA, das Sie kontrollieren**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Da Sie das Objekt innerhalb einer OU erstellt haben, auf die Sie schreiben können, besitzen Sie automatisch alle seine Attribute.

2. **Simulieren einer "abgeschlossenen Migration" in zwei LDAP-Schreibvorgängen**:
- Setzen Sie `msDS‑ManagedAccountPrecededByLink = DN` eines beliebigen Opfers (z.B. `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Setzen Sie `msDS‑DelegatedMSAState = 2` (Migration abgeschlossen).

Tools wie **Set‑ADComputer, ldapmodify** oder sogar **ADSI Edit** funktionieren; keine Domain-Admin-Rechte sind erforderlich.

3. **Fordern Sie ein TGT für das dMSA an** — Rubeus unterstützt das `/dmsa`-Flag:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Das zurückgegebene PAC enthält jetzt die SID 500 (Administrator) sowie die Gruppen Domain Admins/Enterprise Admins.

## Alle Benutzerpasswörter sammeln

Während legitimer Migrationen muss der KDC dem neuen dMSA erlauben, **Tickets zu entschlüsseln, die vor dem Übergang an das alte Konto ausgestellt wurden**. Um laufende Sitzungen nicht zu unterbrechen, platziert er sowohl aktuelle Schlüssel als auch vorherige Schlüssel in einem neuen ASN.1-Blob namens **`KERB‑DMSA‑KEY‑PACKAGE`**.

Da unsere gefälschte Migration behauptet, dass das dMSA dem Opfer nachfolgt, kopiert der KDC pflichtbewusst den RC4-HMAC-Schlüssel des Opfers in die **previous-keys**-Liste – selbst wenn das dMSA niemals ein "vorheriges" Passwort hatte. Dieser RC4-Schlüssel ist ungesalzen, sodass er effektiv der NT-Hash des Opfers ist, was dem Angreifer **offline cracking oder "pass-the-hash"**-Fähigkeiten verleiht.

Daher ermöglicht das massenhafte Verlinken von Tausenden von Benutzern einem Angreifer, Hashes "in großem Maßstab" zu dumpen und verwandelt **BadSuccessor sowohl in ein Privilegieneskalations- als auch in ein Anmeldeinformationen-Kompromittierungsprimitive**.

## Werkzeuge

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Referenzen

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
