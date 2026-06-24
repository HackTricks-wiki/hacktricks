# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Sieh dir den großartigen Beitrag an von:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR für attackers
- Kerberos ist das standardmäßige AD auth protocol; die meisten lateral-movement chains kommen damit in Berührung.
- Denke in **drei operator phases**:
- **AS-REQ / AS-REP** → password/hash/certificate, um ein **TGT** zu erhalten. Hier finden **AS-REP roasting**, **over-pass-the-hash / pass-the-key** und **PKINIT** statt.
- **TGS-REQ / TGS-REP** → nutze ein TGT, um **service tickets** zu erhalten. Hier werden **Kerberoasting**, **S4U abuse**, **delegation abuse** und der Großteil des **ticket-forging tradecraft** relevant.
- **AP-REQ / AP-REP** → präsentiere das Ticket dem service. Hier passieren **pass-the-ticket** und service-spezifisches lateral movement.
- Für praktische cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse usw.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Nutze diese Seite als **overview / „what changed recently“** index, dann gehe zu den speziellen Seiten für [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) oder [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening hat die defaults geändert, nicht Kerberos selbst** – modernes DC hardening konzentriert sich auf die **default assumed encryption types** für accounts, die `msDS-SupportedEncryptionTypes` **nicht** explizit setzen. Nach dem 2026 rollout defaulten diese accounts auf gepatchten DCs zunehmend zu **AES-only**, sodass blinde `/rc4` Kerberoast-Annahmen häufiger scheitern. Allerdings bleiben **explizit RC4-enabled service accounts hervorragende offline-crack targets**.
- **PAC validation enforcement ist wichtig für forged tickets** – das 2024 PAC-signature hardening bedeutet, dass **golden/diamond/sapphire/extraSID-style abuses** realistischere PAC data und den korrekten signing context benötigen. Ungepatchte domains oder domains, die in compatibility/audit-style deployments verbleiben, sind weiterhin weichere targets.
- **Certificate-based Kerberos hat sich zweimal geändert**:
- **Strong certificate binding** (KB5014754 timeline) macht schlampige certificate-to-account mappings in vollständig erzwungenen Umgebungen weniger zuverlässig.
- **CVE-2025-26647** fügte eine weitere hardening layer rund um **altSecID / SKI certificate mappings** hinzu. Wenn DCs ungepatcht sind, noch auditiert werden oder NTAuth validation explizit umgehen, bleibt pass-the-certificate / shadow-credential follow-on abuse praktischer.
- **Cross-domain / cross-forest delegation abuse ist immer noch sehr lebendig** – Windows unterstützt moderne cross-realm **S4U2Self/S4U2Proxy** flows, daher sind beschreibbare delegation attributes in einer anderen domain weiterhin wertvoll. Der blocker ist meist tooling fidelity und trust/policy details, nicht protocol support.
- **Windows Server 2025 hat neue Kerberos-adjacent attack surface eingeführt** durch **dMSA** migration logic. Wenn du delegated rights über OUs oder service-account objects in einer 2025 domain siehst, prüfe die dedizierte [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md), statt es als „nur noch ein weiteres gMSA“ zu behandeln.

## Fast operator checks in modern domains

Bevor du einen Kerberos attack path auswählst, beantworte schnell vier Fragen:

1. **Welche accounts sind noch RC4-friendly?**
2. **Welche users benötigen kein pre-auth?**
3. **Welche objects bieten delegation abuse?**
4. **Welche Teile der domain sind neu genug, um aktuelles hardening zu erzwingen?**
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
- Wenn **interessante SPN accounts explizit RC4-fähig** sind, bleibt Kerberoasting billig und schnell.
- Wenn die meisten Service accounts **keine explizite etype-Konfiguration** haben, erwarte **AES-only**-Verhalten auf aktualisierten 2026 DCs und plane langsamere Offline-Cracking oder einen anderen Weg.
- Wenn **RBCD / KCD / unconstrained delegation** vorhanden ist, ist S4U oft besser als Brute-Force.
- Wenn **certificate auth** im Spiel ist, denke daran, dass ein fehlgeschlagener PKINIT-Pfad nicht **immer** bedeutet, dass das Cert nutzlos ist; in vielen Umgebungen funktioniert dasselbe Cert weiterhin für **Schannel/LDAPS**-Missbrauch (siehe [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Häufige Kerberos-Fehler, die den Angriffsplan ändern
- **`KDC_ERR_ETYPE_NOTSUPP`** → Das Zielkonto / der DC verwendet nicht den Encryption Type, den du angefordert hast. Hör auf, nur mit RC4 erneut zu versuchen; liefere **AES keys** oder fordere stattdessen **AES** roast material an.
- **`KRB_AP_ERR_MODIFIED`** → Du hast wahrscheinlich den **falschen service key**, den **falschen SPN** oder ein gefälschtes Ticket, das nicht zu dem Service account passt, der es tatsächlich entschlüsselt.
- **`KRB_AP_ERR_SKEW`** → Deine Zeit stimmt nicht. Synchronisiere dich mit dem DC, bevor du irgendetwas anderes debugst.
- **`KDC_ERR_BADOPTION`** während S4U / delegation flows → bedeutet häufig **sensitive/not-delegable users**, das falsche delegation model, oder dass du **classic KCD** verwendest, wo nur **RBCD** ein nicht-forwardable S4U2Self-Ticket akzeptieren würde.

## Referenzen
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
