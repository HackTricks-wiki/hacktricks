# Kerberos-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

**Siehe den großartigen Beitrag unter:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR für Angreifer
- Kerberos ist das standardmäßige AD-Authentifizierungsprotokoll; die meisten Chains für laterale Bewegungen verwenden es.
- Denke in **drei Operator-Phasen**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → Passwort/Hash/Zertifikat verwenden, um ein **TGT** zu erhalten. Hier finden **AS-REP roasting**, **over-pass-the-hash / pass-the-key** und **PKINIT** statt.
- **TGS-REQ / TGS-REP** → Ein TGT verwenden, um **Service-Tickets** zu erhalten. Hier werden **Kerberoasting**, **S4U abuse**, **delegation abuse** und die meisten **Ticket-forging tradecraft** relevant.
- **AP-REQ / AP-REP** → Das Ticket dem Service vorlegen. Hier finden **pass-the-ticket** und service-spezifische laterale Bewegungen statt.
- Für praktische Cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse usw.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Verwende diese Seite als **Übersichtsindex / „was sich kürzlich geändert hat“**, und wechsle anschließend zu den dedizierten Seiten für [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) oder [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Aktuelle Angriffsnotizen (2024-2026)
- **RC4 hardening hat die Defaults geändert, nicht Kerberos selbst** – das moderne DC hardening konzentriert sich auf die **standardmäßig angenommenen Verschlüsselungstypen** für Konten, die `msDS-SupportedEncryptionTypes` **nicht** explizit setzen. Nach dem Rollout von 2026 verwenden diese Konten auf gepatchten DCs zunehmend standardmäßig **nur AES**, wodurch blinde `/rc4`-Kerberoast-Annahmen häufiger fehlschlagen. Explizit für RC4 aktivierte Servicekonten bleiben jedoch hervorragende Ziele für Offline-Cracking.<sup>[[1]](#references)</sup>
- **Die Durchsetzung der PAC-Validierung ist für gefälschte Tickets wichtig** – das PAC-signature hardening von 2024 bedeutet, dass **golden/diamond/sapphire/extraSID-style abuses** realistischere PAC-Daten und den korrekten Signing-Kontext benötigen. Ungepatchte Domains oder Domains, die in Kompatibilitäts-/Audit-ähnlichen Deployments verbleiben, sind weiterhin leichtere Ziele.<sup>[[2]](#references)</sup>
- **Zertifikatbasiertes Kerberos hat sich zweimal geändert**:<sup>[[2]](#references)</sup>
- **Strong certificate binding** (KB5014754 timeline) macht nachlässige Zertifikat-zu-Konto-Zuordnungen in vollständig erzwungenen Umgebungen weniger zuverlässig.
- **CVE-2025-26647** fügte eine weitere hardening-Ebene für **altSecID / SKI certificate mappings** hinzu. Wenn DCs ungepatcht sind, sich weiterhin im Audit-Modus befinden oder die NTAuth-Validierung explizit umgehen, bleibt der nachfolgende pass-the-certificate- / shadow-credential-Missbrauch praktischer.
- **Cross-domain- / cross-forest delegation abuse ist weiterhin sehr relevant** – Windows unterstützt moderne Cross-Realm-**S4U2Self/S4U2Proxy**-Flows, daher sind schreibbare Delegation-Attribute in einer anderen Domain weiterhin wertvoll. Das Hindernis sind normalerweise die Tool-Fidelity sowie Trust-/Policy-Details, nicht die Protokollunterstützung.
- **Rekursives Multi-Domain-RBCD ist operativ relevant** – in Forests mit mindestens drei Domains kann **S4U2Self/S4U2Proxy** über Trust-Referrals rekursiv ausgeführt werden, und **SPN-less** abuse kann einen abschließenden **`S4U2Self+U2U`**-Hop sowie eine von RC4 abhängige Ticket-Verarbeitung erfordern. Siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 führte durch die **dMSA**-Migrationslogik eine neue, an Kerberos angrenzende Angriffsfläche ein. Wenn du in einer 2025-Domain delegierte Rechte über OUs oder Servicekonto-Objekte siehst, prüfe die dedizierte [BadSuccessor-Seite](acl-persistence-abuse/BadSuccessor.md), statt dies als „nur eine weitere gMSA“ zu behandeln.

## Schnelle Operator-Prüfungen in modernen Domains

Bevor du einen Kerberos-Angriffspfad auswählst, beantworte schnell vier Fragen:

1. **Welche Konten sind weiterhin RC4-freundlich?**
2. **Welche Benutzer benötigen keine Pre-Authentication?**
3. **Welche Objekte ermöglichen delegation abuse?**
4. **Welche Teile der Domain sind neu genug, um aktuelles hardening durchzusetzen?**
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
- Wenn **interessante SPN-Konten explizit RC4-fähig sind**, bleibt Kerberoasting günstig und schnell.
- Wenn die meisten Servicekonten **keine explizite Etype-Konfiguration** haben, ist auf aktualisierten DCs im Jahr 2026 **AES-only**-Verhalten zu erwarten. Plane langsamere Offline-Cracking-Versuche oder einen anderen Ansatz ein.
- Wenn **RBCD / KCD / unconstrained delegation** vorhanden ist, ist S4U oft effektiver als brute-force.
- Wenn **Zertifikatauthentifizierung** zum Einsatz kommt, beachte, dass ein fehlgeschlagener PKINIT-Pfad nicht immer bedeutet, dass das Zertifikat unbrauchbar ist; in vielen Umgebungen funktioniert dasselbe Zertifikat weiterhin für den **Schannel/LDAPS-Missbrauch** (siehe [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Häufige Kerberos-Fehler, die den Angriffsplan ändern
- **`KDC_ERR_ETYPE_NOTSUPP`** → Das Zielkonto / der DC verwendet den von dir angeforderten Verschlüsselungstyp nicht. Versuche es nicht weiter ausschließlich mit RC4; stelle **AES-Schlüssel** bereit oder fordere stattdessen **AES**-Roast-Material an.
- **`KRB_AP_ERR_MODIFIED`** → Du hast wahrscheinlich den **falschen Servicesschlüssel**, den **falschen SPN** oder ein gefälschtes Ticket, das nicht zum Dienstkonto passt, das es tatsächlich entschlüsselt.
- **`KRB_AP_ERR_SKEW`** → Deine Zeit ist nicht synchron. Synchronisiere dich mit dem DC, bevor du etwas anderes untersuchst.
- **`KDC_ERR_BADOPTION`** während S4U- / Delegation-Abläufen → Bedeutet häufig **sensible/nicht delegierbare Benutzer**, das falsche Delegation-Modell oder dass du versuchst, **klassisches KCD** zu verwenden, obwohl nur **RBCD** ein nicht weiterleitbares S4U2Self-Ticket akzeptieren würde.

## Referenzen
- [1] [Microsoft Learn - RC4-Nutzung in Kerberos erkennen und beheben](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Aktuelle Windows-Hardening-Anleitung und wichtige Termine](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Wie funktioniert Kerberos? – Theorie](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Ausnutzung von RBCD in Cross-Domain- und Cross-Forest-Umgebungen: Teil 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
