# AD Dynamic Objects (dynamicObject) Anti-Forensik

{{#include ../../banners/hacktricks-training.md}}

## Grundlagen zu Funktionsweise und Erkennung

- Jedes mit der Hilfsklasse **`dynamicObject`** erstellte Objekt erhält **`entryTTL`** (Countdown in Sekunden) und **`msDS-Entry-Time-To-Die`** (absolutes Ablaufdatum). Wenn **`entryTTL`** 0 erreicht, löscht der **Garbage Collector** das Objekt ohne Tombstone/Recycle-Bin, wodurch Ersteller und Zeitstempel gelöscht werden und eine Wiederherstellung verhindert wird.
- **`entryTTL`** ist ein operatives/konstruierte Attribut: Fordere es in LDAP-Abfragen explizit an. Die TTL kann entweder durch Aktualisieren von **`entryTTL`** vor Ablauf oder über die LDAP-TTL-Refresh-OID **`1.3.6.1.4.1.1466.101.119.1`** erneuert werden.
- TTL-Minimum und -Standardwert werden unter **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** erzwungen. Microsoft dokumentiert **86400s** als Standard-TTL und **900s** als standardmäßige minimale gültige TTL; beide unterstützen **1s–1y**. Dynamic Objects werden in **Configuration/Schema**-Partitionen nicht unterstützt.
- Es gibt keine Konvertierung von statisch zu dynamisch und nach Ablauf keine Tombstone-Phase. IR-Teams können sich daher nicht auf gelöschte-Objekt-Kontrollen oder den Recycle Bin verlassen; sie müssen das Live-Objekt bzw. dessen Metadaten erfassen, bevor der GC es entfernt.
- Die Erneuerung ist **replikatabhängig**: Wird die TTL zu kurz vor Ablauf erneuert, können ein anderes beschreibbares Replikat oder der GC das Objekt lokal weiterhin löschen, bevor die Erneuerung repliziert wird. Sehr kurze TTLs funktionieren daher am besten, wenn der Angreifer weiß, welcher DC den Missbrauch verarbeitet; Verteidiger sollten während der Triage **alle Naming Contexts / Replikate** abfragen.
- Die Löschung kann auf DCs mit kurzer Betriebszeit (<24h) einige Minuten verzögert erfolgen, wodurch ein begrenztes Zeitfenster zum Abfragen/Sichern von Attributen bleibt. Erkenne dies durch **Alarme für neue Objekte mit `entryTTL`/`msDS-Entry-Time-To-Die`** und korreliere sie mit verwaisten SIDs/beschädigten Links.<sup>[[1]](#references)</sup>

## Schnelle Enumeration / Live-Triage

- Frage **alle `namingContexts` aus RootDSE** ab, nicht nur den Domain-NC. Dynamic Abuse kann in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) oder in Application Partitions liegen.
- Solange das Objekt noch vorhanden ist, exportiere sofort die **Replikationsmetadaten** sowie alle verknüpften Attributen/ACLs. Nach Ablauf bleiben möglicherweise nur **beschädigte `gPLink`-Werte, verwaiste SIDs oder gecachte DNS-Antworten** zurück.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ-Umgehung mit sich selbst löschenden Computern

- Das standardmäßige **`ms-DS-MachineAccountQuota` = 10** erlaubt jedem authentifizierten Benutzer, Computer zu erstellen. Füge während der Erstellung `dynamicObject` hinzu, damit sich der Computer selbst löscht, den Quota-Slot **freigibt** und dabei Spuren beseitigt.
- Powermad-Anpassung innerhalb von `New-MachineAccount` (objectClass-Liste):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Liegt die angeforderte TTL unter `DynamicObjectMinTTL`, ist abhängig vom Erstellungspfad eine serverseitige Anpassung oder Ablehnung zu erwarten; in vielen Domains liegt die effektive Untergrenze bei **900s**, während der Fallback-/Standardwert weiterhin **86400s** beträgt. ADUC blendet `entryTTL` möglicherweise aus, aber LDP-/LDAP-Abfragen machen sie sichtbar.
- Solange das Objekt existiert, können Verteidiger den nicht privilegierten Ersteller weiterhin über **`msDS-CreatorSID`** am Computerobjekt ermitteln. Sobald der dynamische Computer abläuft, verschwindet diese Zuordnung zusammen mit dem Objekt.<sup>[[1]](#references)</sup>

## Verdeckte Primary-Group-Mitgliedschaft

- Erstelle eine **dynamische Sicherheitsgruppe** und setze anschließend die **`primaryGroupID`** eines Benutzers auf die RID dieser Gruppe, um eine effektive Mitgliedschaft zu erlangen, die **nicht in `memberOf` angezeigt**, aber in Kerberos und Zugriffstokens berücksichtigt wird.<sup>[[1]](#references)</sup>
- Der Ablauf der TTL **löscht die Gruppe trotz des Löschschutzes für Primary Groups**. Dadurch bleibt beim Benutzer eine beschädigte **`primaryGroupID`** zurück, die auf eine nicht vorhandene RID verweist, und es gibt keinen Tombstone, anhand dessen untersucht werden könnte, wie das Privileg vergeben wurde.
- Die Darstellung hängt vom Tool ab: **`Get-ADGroupMember` / `net group`** lösen normalerweise Mitgliedschaften auf, die aus der Primary Group abgeleitet sind, während **`memberOf`** und **`Get-ADGroup -Properties member`** dies nicht tun. Weitere Informationen zu `primaryGroupID`-Tradecraft findest du auf [dieser anderen Seite über DCShadow- und PGID-Missbrauch](dcshadow.md).
- Für Ziele, die **nicht durch AdminSDHolder geschützt** sind, können Angreifer den Trick mit der dynamischen Gruppe mit einem **DACL-Deny für das Lesen von `primaryGroupID`** (oder des Gruppenattributs `member`) kombinieren, um die Verknüpfung bereits vor Ablauf der Gruppe vor vielen LDAP-/PowerShell-Workflows zu verbergen.<sup>[[2]](#references)</sup>

## AdminSDHolder-Orphan-SID-Pollution

- Füge ACEs für einen **kurzlebigen dynamischen Benutzer/eine kurzlebige dynamische Gruppe** zu **`CN=AdminSDHolder,CN=System,...`** hinzu. Nach Ablauf der TTL wird die SID in der Template-ACL zu einer **nicht auflösbaren („Unknown SID“) SID**, und **SDProp (~60 min)** verbreitet diese verwaiste SID über alle geschützten Tier-0-Objekte.
- Die Forensik verliert die Zuordnung, weil der Principal verschwunden ist (keine DN eines gelöschten Objekts). Überwache **neue dynamische Principals sowie plötzlich auftretende verwaiste SIDs in AdminSDHolder-/privilegierten ACLs**.<sup>[[1]](#references)</sup>

## Dynamische GPO-Ausführung mit sich selbst zerstörenden Spuren

- Erstelle ein **dynamisches `groupPolicyContainer`-Objekt** mit einem bösartigen **`gPCFileSysPath`** (z. B. einer SMB-Freigabe à la GPODDITY) und verknüpfe es über **`gPLink`** mit einer Ziel-OU.
- Clients verarbeiten die Richtlinie und laden Inhalte vom SMB des Angreifers. Wenn die TTL abläuft, verschwinden das GPO-Objekt und **`gPCFileSysPath`**; nur eine **defekte `gPLink`**-GUID bleibt zurück, wodurch LDAP-Spuren der ausgeführten Payload entfernt werden.
- Dies ist operativ sauberer als die klassische Bereinigung im **GPODDITY-Stil**: Statt den ursprünglichen `gPCFileSysPath` selbst wiederherzustellen, entfernt AD den bösartigen GPC automatisch, sobald der Timer abläuft.<sup>[[1]](#references)</sup>

## Temporäre AD-integrierte DNS-Umleitung

- AD-DNS-Einträge sind **`dnsNode`**-Objekte in **DomainDnsZones/ForestDnsZones**. Werden sie als **dynamische Objekte** erstellt, ermöglichen sie eine temporäre Host-Umleitung (Credential-Capture/MITM). Clients cachen die bösartige A-/AAAA-Antwort; der Eintrag löscht sich später selbst, sodass die Zone sauber aussieht (der DNS Manager benötigt möglicherweise ein Neuladen der Zone, um die Ansicht zu aktualisieren).
- Erkennung: Überwache **jeden DNS-Eintrag mit `dynamicObject`/`entryTTL`** über Replikations-/Ereignisprotokolle; temporäre Einträge erscheinen nur selten in standardmäßigen DNS-Logs.<sup>[[1]](#references)</sup>

## Hybrid-Entra-ID-Delta-Sync-Lücke (Hinweis)

- Entra-Connect-Delta-Sync basiert auf **Tombstones**, um Löschungen zu erkennen. Ein **dynamischer On-Premises-Benutzer** kann mit Entra ID synchronisiert werden, ablaufen und ohne Tombstone gelöscht werden – die Delta-Synchronisierung entfernt das Cloud-Konto nicht, wodurch ein **verwaister aktiver Entra-Benutzer** verbleibt, bis eine **initiale/vollständige Synchronisierung** oder eine manuelle Bereinigung in der Cloud erzwungen wird.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
