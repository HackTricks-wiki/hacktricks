# Kerberos-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

Eine Beschreibung der Exchanges auf Protokollebene, die unten zusammengefasst werden, findest du im Kerberos-Artikel von Tarlogic.<sup>[[3]](#references)</sup>

## TL;DR für Angreifer
- Kerberos ist das standardmäßige AD-Authentifizierungsprotokoll; die meisten Chains für laterale Bewegungen werden damit in Berührung kommen.
- Denke in **drei Operator-Phasen**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → Passwort/Hash/Zertifikat verwenden, um ein **TGT** zu erhalten. Hier finden **AS-REP roasting**, **over-pass-the-hash / pass-the-key** und **PKINIT** statt.
- **TGS-REQ / TGS-REP** → Ein TGT verwenden, um **Service-Tickets** zu erhalten. Hier werden **Kerberoasting**, **S4U abuse**, **delegation abuse** und die meisten **ticket-forging tradecraft** relevant.
- **AP-REQ / AP-REP** → Das Ticket dem Service präsentieren. Hier finden **pass-the-ticket** und service-spezifische laterale Bewegungen statt.
- Für praktische Cheatsheets zu (AS-REP/Kerberoasting, ticket forgery, delegation abuse usw.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Verwende diese Seite als **Übersicht / „was sich kürzlich geändert hat“** und wechsle anschließend zu den entsprechenden Seiten für [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) oder [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Aktuelle Angriffsnotizen (2024-2026)
- **RC4-Hardening hat die Defaults geändert, nicht Kerberos selbst** – modernes DC-Hardening konzentriert sich auf die **standardmäßig angenommenen Verschlüsselungstypen** für Accounts, die `msDS-SupportedEncryptionTypes` **nicht** explizit setzen. Nach dem Rollout von 2026 verwenden diese Accounts auf gepatchten DCs zunehmend standardmäßig **nur AES**, sodass blinde `/rc4`-Annahmen bei Kerberoast häufiger fehlschlagen. Explizit für RC4 aktivierte Service-Accounts bleiben jedoch ausgezeichnete Ziele für Offline-Cracking.<sup>[[1]](#references)</sup>
- **Die Durchsetzung der PAC-Validierung ist für gefälschte Tickets entscheidend** – das PAC-Signature-Hardening von 2024 bedeutet, dass **golden/diamond/sapphire/extraSID-style abuses** realistischere PAC-Daten und den korrekten Signing-Kontext benötigen. Nicht gepatchte Domains oder Domains, die in Kompatibilitäts-/Audit-ähnlichen Deployments belassen wurden, bleiben schwächere Ziele.<sup>[[2]](#references)</sup>
- **Zertifikatbasiertes Kerberos hat sich zweimal geändert**:
- **Strong certificate binding** (Zeitplan von KB5014754) macht nachlässige Zertifikat-zu-Account-Mappings in vollständig erzwungenen Umgebungen weniger zuverlässig.
- **CVE-2025-26647** fügte eine weitere Hardening-Schicht für `altSecurityIdentities`-Mappings hinzu, die den Subject Key Identifier eines Zertifikats verwenden. Patch-Level, Enforcement- oder Audit-Status und die explizite Mapping-Konfiguration sind daher bei der Bewertung von pass-the-certificate und verwandten zertifikatbasierten Pfaden entscheidend.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Für PKINIT validiert der KDC außerdem den Zertifikatpfad und prüft, ob der Aussteller über den NTAuth-Store vertrauenswürdig ist.<sup>[[8]](#references)</sup>
- **Cross-domain- / Cross-forest-delegation abuse ist weiterhin sehr relevant** – Windows unterstützt moderne Cross-Realm-**S4U2Self/S4U2Proxy**-Flows, daher sind beschreibbare Delegation-Attribute in einer anderen Domain weiterhin wertvoll. Der Blocker sind normalerweise die Tooling-Fidelity sowie Trust-/Policy-Details, nicht die Protokollunterstützung.
- **Rekursives Multi-Domain-RBCD ist operativ relevant** – in Forests mit mindestens drei Domains können **S4U2Self/S4U2Proxy** über Trust-Referrals rekursiv durchlaufen werden, und **SPN-less** abuse kann einen abschließenden **`S4U2Self+U2U`**-Hop sowie RC4-abhängiges Ticket-Handling erfordern. Siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 führte delegierte Managed Service Accounts (dMSAs)** und deren Migrationslogik ein. Wenn du in einer 2025-Domain delegierte Rechte über OUs oder Service-Account-Objekte siehst, prüfe die entsprechende [BadSuccessor-Seite](acl-persistence-abuse/BadSuccessor.md), anstatt dies als „nur eine weitere gMSA“ zu behandeln.<sup>[[7]](#references)</sup>

## Schnelle Operator-Prüfungen in modernen Domains

Bevor du einen Kerberos-Angriffspfad auswählst, beantworte schnell vier Fragen:

1. **Welche Accounts sind weiterhin RC4-freundlich?**
2. **Welche Benutzer benötigen keine Pre-Authentication?**
3. **Welche Objekte ermöglichen delegation abuse?**
4. **Welche Teile der Domain sind neu genug, um aktuelles Hardening durchzusetzen?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Praktische Interpretation:
- Wenn **interessante SPN-Accounts explizit RC4-fähig** sind, bleibt Kerberoasting kostengünstig und schnell.
- Wenn die meisten Service-Accounts **keine explizite Etype-Konfiguration** haben, ist auf aktualisierten DCs im Jahr 2026 ein **AES-only**-Verhalten zu erwarten. Plane daher langsameres Offline-Cracking oder einen anderen Angriffsweg ein.
- Wenn **RBCD / KCD / unconstrained delegation** vorhanden ist, ist S4U häufig besser als Brute-Force.
- Wenn **certificate auth** im Einsatz ist, beachte, dass ein fehlgeschlagener PKINIT-Pfad **nicht immer bedeutet**, dass das Zertifikat nutzlos ist. In vielen Umgebungen funktioniert dasselbe Zertifikat weiterhin für den Missbrauch von **Schannel/LDAPS** (siehe [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Der Ziel-Account / DC verwendet nicht den von dir angeforderten Verschlüsselungstyp. Versuche es nicht weiter ausschließlich mit RC4; stelle **AES keys** bereit oder fordere stattdessen **AES**-Roast-Material an.
- **`KRB_AP_ERR_MODIFIED`** → Du hast wahrscheinlich den **falschen Service Key**, den **falschen SPN** oder ein gefälschtes Ticket, das nicht zum Service-Account passt, der es tatsächlich entschlüsselt.
- **`KRB_AP_ERR_SKEW`** → Deine Zeit ist falsch. Synchronisiere dich mit dem DC, bevor du etwas anderes untersuchst.
- **`KDC_ERR_BADOPTION`** während S4U- / Delegation-Flows → bedeutet häufig **sensitive/nicht delegierbare Benutzer**, das falsche Delegation-Modell oder dass du versuchst, **klassisches KCD** zu verwenden, obwohl nur **RBCD** ein nicht weiterleitbares S4U2Self-Ticket akzeptieren würde.

## References
- [1] [Microsoft Learn - Erkennen und Beheben der RC4-Nutzung in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Aktuelle Windows-Hardening-Anleitung und wichtige Termine](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Wie funktioniert Kerberos? – Theorie](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Ausnutzen von RBCD in Cross-Domain- und Cross-Forest-Umgebungen: Teil 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Änderungen bei der zertifikatsbasierten Authentifizierung in KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647-Schwachstelle beim Kerberos-Zertifikatmapping](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Übersicht über Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Anforderungen an Smart-Card-Zertifikate und KDC-Validierung](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
