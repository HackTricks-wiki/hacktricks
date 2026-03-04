# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Funktionsweise & Erkennungsgrundlagen

- Jedes Objekt, das mit der Hilfsklasse **`dynamicObject`** erstellt wird, erhält **`entryTTL`** (Sekunden-Countdown) und **`msDS-Entry-Time-To-Die`** (absolute Ablaufzeit). Wenn `entryTTL` 0 erreicht, löscht der **Garbage Collector** das Objekt **ohne tombstone/recycle-bin**, wodurch Ersteller/Time‑Stamps entfernt werden und eine Wiederherstellung blockiert wird.
- TTL lässt sich durch Aktualisierung von `entryTTL` erneuern; Mindest- und Standardwerte werden in **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** durchgesetzt (unterstützt 1s–1y, Standardwert häufig 86,400s/24h). Dynamic objects werden in **Configuration/Schema-Partitionen** nicht unterstützt.
- Die Löschung kann auf DCs mit kurzer Laufzeit (<24h) ein paar Minuten verzögert sein, wodurch ein enges Zeitfenster zum Abfragen/Sichern von Attributen entsteht. Erkennen lässt sich das durch **Alerts auf neue Objekte mit `entryTTL`/`msDS-Entry-Time-To-Die`** und Korrelation mit Waisen-SIDs/gebrochenen Links.

## MAQ-Umgehung mit selbstlöschenden Computern

- Standardmäßig erlaubt **`ms-DS-MachineAccountQuota` = 10**, dass jeder authentifizierte Benutzer Computer erstellt. Fügt man bei der Erstellung `dynamicObject` hinzu, löscht sich der Computer selbst und **macht den Quota-Slot frei**, während Spuren entfernt werden.
- Powermad-Tweak innerhalb von `New-MachineAccount` (objectClass-Liste):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Kurze TTLs (z. B. 60s) schlagen bei Standardbenutzern oft fehl; AD fällt auf **`DynamicObjectDefaultTTL`** zurück (Beispiel: 86.400s). ADUC kann `entryTTL` verbergen, aber LDP/LDAP-Abfragen zeigen es an.

## Versteckte Primary-Group-Mitgliedschaft

- Erstelle eine **dynamische Sicherheitsgruppe** und setze dann die `primaryGroupID` eines Nutzers auf die RID dieser Gruppe, um effektive Mitgliedschaft zu erlangen, die **nicht in `memberOf`** erscheint, aber in Kerberos/Access-Tokens berücksichtigt wird.
- Beim Ablauf der TTL **wird die Gruppe gelöscht, trotz Primary-Group-Löschschutz**, sodass der Benutzer eine korrupte `primaryGroupID` besitzt, die auf eine nicht-existenten RID zeigt und keine Tombstone-Einträge zur Untersuchung mehr vorhanden sind.

## AdminSDHolder Orphan-SID-Verschmutzung

- Füge ACEs für einen **kurzlebigen dynamischen Nutzer/Gruppe** zu **`CN=AdminSDHolder,CN=System,...`** hinzu. Nach Ablauf der TTL wird die SID in der Vorlagen-ACL **nicht mehr aufgelöst („Unknown SID“)**, und **SDProp (~60 min)** propagiert diese Waisen-SID über alle geschützten Tier-0-Objekte.
- Die Forensik verliert die Attribution, weil der Principal verschwunden ist (kein gelöschtes Objekt-DN). Überwache auf **neue dynamic principals + plötzliche Waisen-SIDs in AdminSDHolder/privilegierten ACLs**.

## Dynamische GPO-Ausführung mit sich selbst zerstörenden Beweisen

- Erstelle ein **dynamisches `groupPolicyContainer`**-Objekt mit einem bösartigen **`gPCFileSysPath`** (z. B. SMB-Share à la GPODDITY) und **verlinke es via `gPLink`** mit einer Ziel-OU.
- Clients verarbeiten die Richtlinie und laden Inhalte vom angreifenden SMB. Wenn die TTL abläuft, verschwindet das GPO-Objekt (und `gPCFileSysPath`); nur eine **gebrochene `gPLink`**-GUID bleibt übrig, wodurch LDAP-Spuren der ausgeführten Payload entfernt werden.

## Temporäre AD-integrierte DNS-Umleitung

- AD-DNS-Einträge sind **`dnsNode`**-Objekte in **DomainDnsZones/ForestDnsZones**. Werden sie als **dynamic objects** angelegt, ermöglichen sie temporäre Host-Umleitungen (Credential-Capture/MITM). Clients cachen die bösartige A/AAAA-Antwort; der Eintrag löscht sich später selbst, sodass die Zone sauber aussieht (DNS Manager benötigt eventuell Zone-Reload zur Ansichtsaktualisierung).
- Erkennung: Alerting auf **jedes DNS-Record mit `dynamicObject`/`entryTTL`** via Replikation/Event-Logs; transiente Records tauchen selten in Standard-DNS-Logs auf.

## Hybride Entra ID Delta-Sync-Lücke (Hinweis)

- Entra Connect Delta-Sync verlässt sich auf **tombstones**, um Löschungen zu erkennen. Ein **dynamic on-prem Benutzer** kann zu Entra ID synchronisiert werden, verfallen und ohne Tombstone gelöscht werden — Delta-Sync entfernt das Cloud-Konto nicht, wodurch ein **verwaister aktiver Entra-Benutzer** verbleibt, bis ein manueller **Full Sync** erzwungen wird.

## Referenzen

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
