# Kerberos-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

**Siehe den hervorragenden Beitrag auf:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR für Angreifer
- Kerberos ist das standardmäßige AD-Authentifizierungsprotokoll; die meisten Ketten für laterale Bewegungen verwenden es.
- Denke in **drei Operator-Phasen**:
- **AS-REQ / AS-REP** → Passwort/Hash/Zertifikat verwenden, um ein **TGT** zu erhalten. Hier finden **AS-REP roasting**, **over-pass-the-hash / pass-the-key** und **PKINIT** statt.
- **TGS-REQ / TGS-REP** → Ein TGT verwenden, um **Service-Tickets** zu erhalten. Hier werden **Kerberoasting**, **S4U abuse**, **delegation abuse** und die meisten Techniken zum **Ticket-Forging** relevant.
- **AP-REQ / AP-REP** → Das Ticket dem Service vorlegen. Hier finden **pass-the-ticket** und service-spezifische laterale Bewegungen statt.
- Für praktische Cheatsheets (AS-REP/Kerberoasting, Ticket-Forging, delegation abuse usw.) siehe:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Verwende diese Seite als **Übersicht / „was sich kürzlich geändert hat“** und wechsle anschließend zu den dedizierten Seiten für [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) oder [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Aktuelle Angriffsnotizen (2024-2026)
- **Die RC4-Härtung hat die Standardeinstellungen geändert, nicht Kerberos selbst** – Die moderne DC-Härtung konzentriert sich auf die **standardmäßig angenommenen Verschlüsselungstypen** für Konten, die `msDS-SupportedEncryptionTypes` **nicht explizit setzen**. Nach dem Rollout von 2026 verwenden diese Konten auf gepatchten DCs zunehmend standardmäßig **nur AES**, weshalb blinde `/rc4`-Annahmen bei Kerberoast häufiger scheitern. **Explizit für RC4 aktivierte Servicekonten bleiben jedoch ausgezeichnete Ziele für Offline-Cracking**.
- **Die Durchsetzung der PAC-Validierung ist für gefälschte Tickets wichtig** – Die PAC-Signatur-Härtung von 2024 bedeutet, dass **golden/diamond/sapphire/extraSID-style abuses** realistischere PAC-Daten und den korrekten Signaturkontext benötigen. Ungepatchte Domänen oder Domänen, die im Kompatibilitäts-/Audit-Modus betrieben werden, bleiben leichtere Ziele.
- **Zertifikatbasierte Kerberos-Authentifizierung hat sich zweimal geändert**:
- **Strong certificate binding** (Zeitplan von KB5014754) macht ungenaue Zertifikat-zu-Konto-Zuordnungen in vollständig erzwungenen Umgebungen weniger zuverlässig.
- **CVE-2025-26647** hat eine weitere Härtungsebene für **altSecID / SKI certificate mappings** hinzugefügt. Wenn DCs ungepatcht sind, sich weiterhin im Audit-Modus befinden oder die NTAuth-Validierung ausdrücklich umgehen, bleibt der nachfolgende Missbrauch durch pass-the-certificate / shadow-credential praktischer.
- **Delegation abuse über Domänen- und Forest-Grenzen hinweg ist weiterhin sehr relevant** – Windows unterstützt moderne Cross-Realm-**S4U2Self/S4U2Proxy**-Abläufe, weshalb beschreibbare Delegationsattribute in einer anderen Domäne weiterhin wertvoll sind. Das Hindernis sind normalerweise die Genauigkeit der Tools sowie Trust-/Policy-Details, nicht die Protokollunterstützung.
- **Rekursives RBCD über mehrere Domänen ist operativ relevant** – In Forests mit mindestens drei Domänen kann **S4U2Self/S4U2Proxy** über Trust-Referrals rekursiv angewendet werden, und **SPN-less** abuse kann einen abschließenden **`S4U2Self+U2U`**-Hop sowie eine von RC4 abhängige Ticket-Verarbeitung erfordern. Siehe [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 hat durch die dMSA-Migrationslogik eine neue, an Kerberos angrenzende Angriffsfläche eingeführt**. Wenn du in einer 2025-Domäne delegierte Rechte über OUs oder Servicekontoobjekte siehst, prüfe stattdessen die dedizierte [BadSuccessor-Seite](acl-persistence-abuse/BadSuccessor.md), anstatt dies als „nur eine weitere gMSA“ zu behandeln.

## Schnelle Operator-Prüfungen in modernen Domänen

Bevor du einen Kerberos-Angriffspfad auswählst, beantworte schnell vier Fragen:

1. **Welche Konten sind weiterhin RC4-freundlich?**
2. **Welche Benutzer benötigen keine Pre-Authentication?**
3. **Welche Objekte ermöglichen delegation abuse?**
4. **Welche Teile der Domäne sind neu genug, um die aktuelle Härtung durchzusetzen?**
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
- Wenn **interessante SPN-Accounts ausdrücklich RC4-fähig** sind, bleibt Kerberoasting günstig und schnell.
- Wenn die meisten Service-Accounts **keine explizite Etype-Konfiguration** haben, solltest du auf aktualisierten 2026-DCs **AES-only**-Verhalten erwarten und langsameres Offline-Cracking oder einen anderen Ansatz einplanen.
- Wenn **RBCD / KCD / unconstrained delegation** vorhanden ist, ist S4U häufig effektiver als Brute-Force.
- Wenn **Zertifikatsauthentifizierung** eingesetzt wird, beachte, dass ein fehlgeschlagener PKINIT-Pfad **nicht immer bedeutet, dass das Zertifikat unbrauchbar ist**; in vielen Umgebungen funktioniert dasselbe Zertifikat weiterhin für **Schannel/LDAPS**-Abuse (siehe [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Häufige Kerberos-Fehler, die den Angriffsplan ändern
- **`KDC_ERR_ETYPE_NOTSUPP`** → Der Ziel-Account / DC verwendet den von dir angeforderten Verschlüsselungstyp nicht. Versuche nicht weiterhin nur RC4; stelle **AES-Schlüssel** bereit oder fordere stattdessen **AES**-Roast-Material an.
- **`KRB_AP_ERR_MODIFIED`** → Du hast wahrscheinlich den **falschen Service-Key**, den **falschen SPN** oder ein gefälschtes Ticket, das nicht zum Service-Account passt, der es tatsächlich entschlüsselt.
- **`KRB_AP_ERR_SKEW`** → Deine Zeit stimmt nicht. Synchronisiere dich mit dem DC, bevor du etwas anderes debugst.
- **`KDC_ERR_BADOPTION`** während S4U- / Delegation-Abläufen → bedeutet häufig **sensitive/nicht delegierbare Benutzer**, das falsche Delegation-Modell oder dass du versuchst, **klassisches KCD** zu verwenden, obwohl nur **RBCD** ein nicht weiterleitbares S4U2Self-Ticket akzeptieren würde.

## Referenzen
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
