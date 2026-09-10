# AD Dynamic Objects (dynamicObject) Anti-Forensik

{{#include ../../banners/hacktricks-training.md}}

## Grundlagen der Funktionsweise und Erkennung

- Jedes mit der Hilfsklasse **`dynamicObject`** erstellte Objekt erhält **`entryTTL`** (Countdown in Sekunden) und **`msDS-Entry-Time-To-Die`** (absolutes Ablaufdatum). Wenn `entryTTL` 0 erreicht **und das Objekt keine Nachkommen hat**, löscht der Garbage Collector es ohne Tombstone/Recycle Bin, entfernt Ersteller und Zeitstempel und verhindert eine Wiederherstellung.<sup>[[4]](#references)</sup>
- **`entryTTL` ist ein operatives/konstruierte Attribut**: Fordere es in LDAP-Abfragen explizit an. Die TTL kann entweder durch Aktualisieren von `entryTTL` vor dem Ablauf oder über die LDAP-TTL-Refresh-OID **`1.3.6.1.4.1.1466.101.119.1`** erneuert werden.
- Das TTL-Minimum und der Standardwert sind forestweite AVAs in **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` und `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft dokumentiert **86400s** als Standard-TTL und **900s** als standardmäßige minimale gültige TTL; der `entryTTL`-Schemabereich liegt bei **1–31557600s** (eine Sekunde bis ein Jahr).<sup>[[3]](#references)</sup> Dynamic objects werden in Configuration-/Schema-Partitionen **nicht unterstützt**.
- Es gibt keine **static→dynamic conversion** und nach dem Ablauf keine Tombstone-Phase. IR-Teams können sich nicht auf gelöschte-Objekt-Kontrollen oder den Recycle Bin verlassen; sie müssen das Live-Objekt bzw. dessen Metadaten erfassen, bevor der GC es entfernt.
- Die Erneuerung ist **replikatsensitiv**: Wird die TTL zu knapp vor dem Ablauf erneuert, kann ein anderes beschreibbares Replikat oder der GC das Objekt lokal weiterhin löschen, bevor die Erneuerung repliziert wird. Sehr kurze TTLs funktionieren daher am besten, wenn der Angreifer weiß, welcher DC den Missbrauch verarbeitet; Verteidiger sollten während der Triage **alle Naming Contexts / Replikate** abfragen.
- Die Löschung kann auf DCs mit kurzer Betriebszeit (<24h) um einige Minuten verzögert sein, wodurch ein begrenztes Zeitfenster zur Abfrage bzw. Sicherung von Attributen entsteht. Erkenne dies durch **Alarme für neue Objekte mit `entryTTL`/`msDS-Entry-Time-To-Die`** und korreliere sie mit verwaisten SIDs bzw. defekten Links.<sup>[[1]](#references)</sup>

### Ablaufdiagramm und Sonderfälle bei der Referenzbereinigung

- Jeder Nachkomme unterhalb eines dynamic objects muss selbst dynamisch sein. Ein abgelaufener dynamischer Parent wird erst dann vom Garbage Collector erfasst, wenn er zu einem Blatt geworden ist; wenn ein Nachkomme ein späteres `msDS-Entry-Time-To-Die` besitzt, verschiebt der DC den Ablauf des Parents über den Ablaufzeitpunkt des spätesten Nachkommens hinaus. Folglich kann ein beschreibbarer dynamischer Teilbaum einen Parent, der scheinbar kurz vor dem Verschwinden steht, **festhalten/verlängern**: Enumeriere den gesamten Teilbaum und verwende die beobachtete `entryTTL` des Parents nicht als Frist für die Bereinigung.<sup>[[4]](#references)</sup>
- Die Ablaufbereinigung berücksichtigt **Schema-Links**. Replikate entfernen verknüpfte Attributwerte, die auf das gelöschte dynamic object verweisen, behalten jedoch nicht verknüpfte Werte bei. Erwarte, dass gewöhnliche Forward-/Back-Link-Mitgliedschaften bereinigt werden, während Integer-/SID-/String-Referenzen wie `primaryGroupID`, in `nTSecurityDescriptor` eingebettete SIDs oder `gPLink`-Text als forensische Rückstände bestehen bleiben können.<sup>[[4]](#references)</sup>

## Schnelle Enumeration / Live-Triage

- Frage **alle `namingContexts` von RootDSE** ab, nicht nur den Domain NC. Dynamic abuse kann in **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) oder in application partitions vorhanden sein.
- Solange das Objekt noch vorhanden ist, sichere sofort **Replikationsmetadaten** sowie alle verknüpften Attribute/ACLs. Nach dem Ablauf bleiben möglicherweise nur **defekte `gPLink`-Werte, verwaiste SIDs oder gecachte DNS-Antworten** übrig.<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ-Evasion mit sich selbst löschenden Computern

- Das standardmäßige **`ms-DS-MachineAccountQuota` = 10** ermöglicht es jedem authentifizierten Benutzer, Computer zu erstellen. Durch das Hinzufügen von `dynamicObject` während der Erstellung löscht sich der Computer selbst und **gibt den Kontingentplatz frei**, während Beweise beseitigt werden.
- Powermad-Anpassung innerhalb von `New-MachineAccount` (objectClass-Liste):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Liegt die angeforderte TTL unter `DynamicObjectMinTTL`, ist je nach Erstellungspfad mit einer serverseitigen Anpassung oder Ablehnung zu rechnen; in vielen Domänen liegt die effektive Untergrenze bei **900s**, während der Fallback-/Standardwert weiterhin **86400s** beträgt. ADUC blendet `entryTTL` möglicherweise aus, aber LDP-/LDAP-Abfragen machen es sichtbar.
- Solange das Objekt existiert, können Verteidiger den nicht privilegierten Ersteller weiterhin über **`msDS-CreatorSID`** am Computerobjekt ermitteln. Sobald der dynamische Computer abläuft, verschwindet diese Zuordnung zusammen mit dem Objekt.<sup>[[1]](#references)</sup>

## Verdeckte Mitgliedschaft in der primären Gruppe

- Eine **dynamische Sicherheitsgruppe** erstellen und anschließend die **`primaryGroupID`** eines Benutzers auf die RID dieser Gruppe setzen, um eine effektive Mitgliedschaft zu erlangen, die **nicht in `memberOf` angezeigt**, aber in Kerberos-/Zugriffstokens berücksichtigt wird.<sup>[[1]](#references)</sup>
- Der Ablauf der TTL **löscht die Gruppe trotz des Löschschutzes für primäre Gruppen**. Dadurch bleibt beim Benutzer eine beschädigte **`primaryGroupID`** zurück, die auf eine nicht vorhandene RID verweist, ohne Tombstone, anhand dessen untersucht werden könnte, wie die Berechtigung erteilt wurde.
- Die Berichterstellung hängt vom Tool ab: **`Get-ADGroupMember` / `net group`** lösen in der Regel aus der primären Gruppe abgeleitete Mitgliedschaften auf, während **`memberOf`** und **`Get-ADGroup -Properties member`** dies nicht tun. Weitere Informationen zu `primaryGroupID`-Tradecraft finden Sie auf [dieser anderen Seite über DCShadow- und PGID-Missbrauch](dcshadow.md).
- Bei **Zielen, die nicht durch AdminSDHolder geschützt sind**, können Angreifer den Trick mit der dynamischen Gruppe mit einem **DACL-Deny für das Lesen von `primaryGroupID`** (oder des Gruppenattributs `member`) kombinieren, um die Verbindung bereits vor Ablauf der Gruppe aus vielen LDAP-/PowerShell-Workflows auszublenden.<sup>[[2]](#references)</sup>

## AdminSDHolder-Orphan-SID-Verschmutzung

- ACEs für einen **kurzlebigen dynamischen Benutzer/eine kurzlebige dynamische Gruppe** zu **`CN=AdminSDHolder,CN=System,...`** hinzufügen. Nach Ablauf der TTL wird die SID in der Template-ACL **nicht mehr aufgelöst („Unknown SID“)**, und **SDProp (~60 min)** verbreitet diese verwaiste SID über alle geschützten Tier-0-Objekte.
- Forensik verliert die Zuordnung, weil der Principal nicht mehr existiert (keine DN eines gelöschten Objekts). Auf **neue dynamische Principals + plötzlich auftretende verwaiste SIDs in AdminSDHolder-/privilegierten ACLs** überwachen.<sup>[[1]](#references)</sup>

## Dynamische GPO-Ausführung mit sich selbst zerstörenden Beweisen

- Ein **dynamisches `groupPolicyContainer`**-Objekt mit einem schädlichen **`gPCFileSysPath`** erstellen (z. B. eine SMB-Freigabe à la GPODDITY) und es über **`gPLink`** mit einer Ziel-OU verknüpfen.
- Clients verarbeiten die Richtlinie und laden Inhalte vom Angreifer-SMB. Nach Ablauf der TTL verschwindet das GPO-Objekt (und **`gPCFileSysPath`**); nur eine **defekte `gPLink`**-GUID bleibt zurück, wodurch LDAP-Beweise für die ausgeführte Payload entfernt werden.
- Dies ist operativ sauberer als die klassische **GPODDITY-typische** Bereinigung: Statt den ursprünglichen `gPCFileSysPath` selbst wiederherzustellen, entfernt AD den schädlichen GPC automatisch, sobald der Timer abläuft.<sup>[[1]](#references)</sup> Siehe [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) für Protokoll- und Tooling-Details, statt diese hier zu duplizieren.

## Flüchtige AD-integrierte DNS-Umleitung

- AD-DNS-Einträge sind **`dnsNode`**-Objekte in **DomainDnsZones/ForestDnsZones**. Werden sie als **dynamic objects** erstellt, ermöglichen sie eine temporäre Host-Umleitung (Credential Capture/MITM). Clients cachen die schädliche A-/AAAA-Antwort; der Eintrag löscht sich später selbst, sodass die Zone sauber aussieht (möglicherweise muss der DNS Manager die Zonenansicht neu laden).
- Erkennung: Über Replikations-/Ereignisprotokolle auf **jeden DNS-Eintrag mit `dynamicObject`/`entryTTL`** alarmieren; flüchtige Einträge erscheinen nur selten in standardmäßigen DNS-Logs.<sup>[[1]](#references)</sup>

## Lücke bei der Delta-Synchronisierung von Hybrid Entra ID (Hinweis)

- Die Delta-Synchronisierung von Entra Connect beruht auf **Tombstones**, um Löschungen zu erkennen. Ein **dynamischer On-Premises-Benutzer** kann mit Entra ID synchronisiert werden, ablaufen und ohne Tombstone gelöscht werden — die Delta-Synchronisierung entfernt das Cloud-Konto nicht, sodass ein **verwaister aktiver Entra-Benutzer** zurückbleibt, bis eine **initiale/vollständige Synchronisierung** oder eine manuelle Cloud-Bereinigung erzwungen wird.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamische Objekte in Active Directory: Die unauffällige Bedrohung](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Abenteuer mit dem Verhalten, der Berichterstellung und der Ausnutzung primärer Gruppen](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Konfiguration von TTL-Grenzwerten](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Anforderungen an DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
