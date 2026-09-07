# State Divergence und Authorization Bypasses durch Standardwerte

{{#include ../../banners/hacktricks-training.md}}

Authorization hängt manchmal vom abgeleiteten wirtschaftlichen Zustand statt von einer expliziten Rolle ab – zum Beispiel: „Der Aufrufer besitzt das gesamte Supply.“ Wenn die Werte in diesem Prädikat aus verschiedenen Stores stammen, kann ein veraltetes Duplikat einen legitimen Ownership-Shortcut in einen Authorization Bypass verwandeln. Das Provenance marker module zeigte die gefährliche Kombination: Ein aktuelles Caller-Balance wurde mit Supply-Metadaten aus dem Marker-Store verglichen, die bei Assets mit nicht festgelegtem Supply nicht aktualisiert wurden.<sup>[[1]](#references)</sup>

## Duplizierten State als Authorization-Grenze prüfen

Für jeden Wert, der von einem Permission-Check verwendet wird, müssen **alle Repräsentationen** erfasst werden: kanonischer Module-State, Object-Felder, gecachte Aggregate, Indexes, Snapshots, Bridge-Records und Off-Chain-Mirrors. Verfolge anschließend jeden Create-, Mint-, Burn-, Transfer-, Reset-, Migration- und Synchronization-Pfad, um zu bestimmen, welche Kopie in jedem Object-Mode aktualisiert wird. Ein Feld kann in einem Mode maßgeblich und in einem anderen nur informativ sein.<sup>[[1]](#references)</sup>

Ein praktischer Review-Workflow ist:<sup>[[1]](#references)</sup>

1. Finde geschützte Actions und reduziere jeden Authorization-Branch auf ein boolesches Prädikat.
2. Dokumentiere für jeden Operanden seinen Store, seine Update-Pfade, Lifecycle-States und die Source of Truth.
3. Erzeuge Transitions, die nur eine Repräsentation aktualisieren, und vergleiche anschließend alle Kopien.
4. Versuche nach jeder Transition, die geschützte Action von einem frischen Account auszuführen.
5. Gehe über den Bypass hinaus: Wenn die Action eine ACL bearbeitet, gewähre dir selbst persistente Rollen und rufe normale privilegierte APIs auf.

Verdächtige Muster sind `cachedSupply == balance`, `metadataOwner == caller` oder `snapshotShares == currentShares`, wenn die beiden Seiten unterschiedlichen Synchronization-Regeln unterliegen. Das Abfragen eines maßgeblichen Werts für einen Operanden macht den Vergleich nicht sicher, wenn der andere Operand veraltet ist.<sup>[[1]](#references)</sup>

## Equality Bypass durch Standardwerte

Ein Equality-Prädikat ist ebenfalls unsicher, wenn beide Operanden unabhängig voneinander denselben Standardwert annehmen können. Der folgende Check gewährt jedem leeren Account „vollständige Supply-Kontrolle“, wenn `supply` null ist – unabhängig davon, ob null durch veraltete Metadaten oder durch ein legitimerweise nicht finanziertes Object entsteht.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Der Wechsel zum kanonischen Speicher behebt die Divergenz, aber **nicht** den Fall des leeren Objekts. Die Sicherheitseigenschaft muss eine unabhängige Gültigkeitsbedingung enthalten; der Provenance-Patch verwendet die live bank supply und weist nil oder eine supply von null zurück, bevor er das Guthaben des Aufrufers vergleicht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Wende dieselbe Logik auf quorum counts, ownership percentages, debt, collateral, epochs, nonces, timestamps und counters an: `callerValue == protectedValue` darf einen caller erst dann autorisieren, wenn der protected value unabhängig gültig ist und zum erwarteten Wertebereich gehört.<sup>[[1]](#references)</sup>

## ACL takeover to legitimate privileged operations

Ein Bypass in einer ACL-editing-Operation ist ein dauerhafter Privilege-Escalation-Primitiv. Im Provenance-Fall konnte ein unprivilegierter Account mit null Tokens den veralteten `0 == 0`-Supply-Test bestehen, sich selbst administrative Berechtigungen sowie mint- und withdrawal-Berechtigungen erteilen und anschließend gewöhnliche Message-Handler verwenden, um Assets zu minten oder Escrow abzuheben. Der Exploit erforderte daher nach der ACL-Änderung keine zweite Vulnerability.<sup>[[1]](#references)</sup>

Allgemeine Exploitation-Sequenz:<sup>[[1]](#references)</sup>

1. Finde ein Objekt, dessen nicht maßgebliches Feld vom Live State abweicht oder dessen geschützter Wert dem Default entspricht.
2. Verwende eine neue/leere Identity, sodass ihr lokaler Wert mit diesem veralteten/Default-Wert übereinstimmt.
3. Rufe den Role-Management-, Ownership-Transfer- oder Policy-Update-Endpoint auf und erteile dir selbst dauerhafte Capabilities.
4. Bestätige die Persistenz, indem du die ACL aus dem Canonical State ausliest.
5. Rufe die legitime Operation mit hoher Auswirkung auf (mint, withdraw, Upgrade, Ownership übertragen oder Policy ändern).

Bei der Bewertung der Auswirkungen solltest du jede Capability untersuchen, die über die neue Rolle erreichbar ist, statt beim Authorization-Bypass aufzuhören. Escrow-ähnliche Accounts können Assets verwahren, die nicht mit dem Objekt zusammenhängen, dessen veraltete Metadaten die Übernahme ermöglicht haben.<sup>[[1]](#references)</sup>

## Invariant and stateful-fuzzing targets

Spezifiziere die Authorization unabhängig von der Implementation. Für einen Full-Supply-Shortcut lautet die minimale Invariant:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Verwende einen Model-/State-Machine-Fuzzer, um Sequenzen – keine isolierten Aufrufe – zu generieren, die Erstellung, Initialisierung mit Nullwerten, Aktivierung/Finalisierung, Minting, Burning, Transfers, Resets, Migrationen, Sync-Aufrufe und ACL-Änderungen abdecken. Vergleiche nach jedem Übergang die duplizierten Repräsentationen und stelle sicher, dass ein neues Konto keine geschützte Aktion ausführen kann. Lege explizite Fälle für null, eine Einheit, teilweisen Besitz, vollständigen Besitz, veraltete niedrige und veraltete hohe Werte an.<sup>[[1]](#references)[[2]](#references)</sup>

Regressionseigenschaften mit hoher Aussagekraft sind:<sup>[[1]](#references)[[2]](#references)</sup>

- Eine autoritative Supply von null impliziert niemals Besitz oder Administration.
- Teilweise Besitzende können nicht zu Administratoren werden, wenn eine duplizierte Supply ihrem Kontostand entspricht.
- Ein tatsächlicher vollständiger Besitzer behält die vorgesehene Abkürzung bei, wenn die live Supply positiv ist.
- Fehlgeschlagene Self-Grants verändern weder die ACL noch ermöglichen sie nachgelagerte privilegierte Aufrufe.
- Modusänderungen können nicht unbemerkt ändern, welche Repräsentation ein Authorization-Check als autoritativ behandelt.

## References

- [1] [State Divergence ermöglicht unautorisierten Zugriff (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 – Veraltete Supply-Checks beheben](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance-Commit c81fd65 – Null-Supply in der Authorization-Abkürzung für die Gesamt-Supply ablehnen](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
