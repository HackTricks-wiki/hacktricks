# State-Divergenz und Authorization-Bypasses durch Default-Werte

{{#include ../../banners/hacktricks-training.md}}

Authorization hängt manchmal von einem abgeleiteten wirtschaftlichen Zustand statt von einer expliziten Rolle ab – zum Beispiel davon, ob „der Aufrufer den gesamten Bestand besitzt“. Wenn die Werte in diesem Prädikat aus unterschiedlichen Speichern stammen, kann eine veraltete Kopie einen legitimen Ownership-Kurzw eg in einen Authorization-Bypass verwandeln. Das Provenance-marker-Modul zeigte die gefährliche Kombination: Ein aktuelles Guthaben des Aufrufers wurde mit lokalen Supply-Metadaten des Markers verglichen, die bei Assets mit nicht festgelegtem Supply nicht aktualisiert wurden.<sup>[[1]](#references)</sup>

## Duplizierten Zustand als Authorization-Grenze prüfen

Erfassen Sie für jeden Wert, der bei einer Berechtigungsprüfung verwendet wird, **alle Repräsentationen**: kanonischen Modulzustand, Objektfelder, zwischengespeicherte Aggregate, Indizes, Snapshots, Bridge-Einträge und Off-Chain-Spiegelungen. Verfolgen Sie dann bei jedem Objektmodus sämtliche Erstellungs-, Mint-, Burn-, Transfer-, Reset-, Migrations- und Synchronisierungspfade, um festzustellen, welche Kopie jeweils aktualisiert wird. Ein Feld kann in einem Modus maßgeblich und in einem anderen lediglich informativ sein.<sup>[[1]](#references)</sup>

Ein praktischer Prüfungsablauf:<sup>[[1]](#references)</sup>

1. Finden Sie geschützte Aktionen und reduzieren Sie jeden Authorization-Zweig auf ein boolesches Prädikat.
2. Erfassen Sie für jeden Operanden den Speicherort, die Aktualisierungspfade, die Lebenszykluszustände und die maßgebliche Quelle.
3. Erzeugen Sie Zustandsübergänge, bei denen nur eine Repräsentation aktualisiert wird, und vergleichen Sie anschließend alle Kopien.
4. Versuchen Sie nach jedem Zustandsübergang, die geschützte Aktion von einem neuen Konto aus aufzurufen.
5. Prüfen Sie über den Bypass hinaus weiter: Ändert die Aktion eine ACL, weisen Sie sich selbst dauerhafte Rollen zu und rufen Sie normale privilegierte APIs auf.

Verdächtige Muster sind etwa `cachedSupply == balance`, `metadataOwner == caller` oder `snapshotShares == currentShares`, wenn für die beiden Seiten unterschiedliche Synchronisierungsregeln gelten. Einen Operanden aus einer maßgeblichen Quelle abzufragen, macht den Vergleich nicht sicher, wenn der andere Operand veraltet ist.<sup>[[1]](#references)</sup>

## Equality-Bypass durch Default-Werte

Ein Gleichheitsprädikat ist auch dann unsicher, wenn beide Operanden unabhängig voneinander denselben Default-Wert annehmen können. Die folgende Prüfung gewährt jedem leeren Konto „volle Kontrolle über den gesamten Bestand“, wenn `supply` null ist – unabhängig davon, ob der Wert null auf veraltete Metadaten oder ein legitimerweise nicht finanziertes Objekt zurückgeht.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Der Wechsel zum kanonischen Store behebt die Divergenz, aber **nicht** den Fall eines leeren Objekts. Die Sicherheitsbedingung muss eine unabhängige Gültigkeitsprüfung umfassen; der Provenance-Patch verwendet den aktuellen Bank-Supply-Wert und weist einen nil- oder nullwertigen Supply-Wert zurück, bevor er den Kontostand des Aufrufers vergleicht.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Wende dieselbe Logik auf Quorum-Zahlen, Eigentumsanteile, Schulden, Sicherheiten, Epochen, Nonces, Zeitstempel und Zähler an: `callerValue == protectedValue` darf einen Aufrufer erst dann autorisieren, wenn der geschützte Wert unabhängig als gültig bestätigt wurde und zum erwarteten Bereich gehört.<sup>[[1]](#references)</sup>

## ACL-Übernahme für legitime privilegierte Operationen

Ein Bypass in einer ACL-Bearbeitungsoperation ist ein dauerhafter Privilegieneskalationsvektor. Im Provenance-Fall konnte ein nicht privilegiertes Konto mit null Token den veralteten Versorgungstest `0 == 0` bestehen, sich selbst administrative Berechtigungen zum Minten und Abheben erteilen und anschließend gewöhnliche Message-Handler verwenden, um Assets zu minten oder Escrow abzuheben. Nach der ACL-Änderung war für den Exploit daher keine zweite Schwachstelle erforderlich.<sup>[[1]](#references)</sup>

Allgemeiner Exploit-Ablauf:<sup>[[1]](#references)</sup>

1. Finde ein Objekt, dessen nicht maßgebliches Feld vom Live-Zustand abweicht, oder dessen geschützter Wert dem Standardwert entspricht.
2. Verwende eine neue/leere Identität, deren lokaler Wert mit diesem veralteten/Standardwert übereinstimmt.
3. Rufe den Endpunkt für Rollenverwaltung, Eigentumsübertragung oder Richtlinienaktualisierung auf und gewähre dir selbst dauerhafte Berechtigungen.
4. Bestätige die Persistenz, indem du die ACL aus dem kanonischen Zustand ausliest.
5. Rufe die legitime Operation mit hohen Auswirkungen auf (Mint, Abhebung, Upgrade, Eigentumsübertragung oder Richtlinienänderung).

Prüfe bei der Bewertung der Auswirkungen jede Berechtigung, die über die neue Rolle erreichbar ist, statt bei der Autorisierungsumgehung stehenzubleiben. Escrow-ähnliche Konten können Assets verwahren, die nichts mit dem Objekt zu tun haben, dessen veraltete Metadaten die Übernahme ermöglichten.<sup>[[1]](#references)</sup>

## Invarianten und Ziele für Stateful Fuzzing

Spezifiziere die Autorisierung unabhängig von der Implementierung. Für eine Abkürzung bei voller Versorgung lautet die minimale Invariante:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Verwende einen Modell-/Zustandsmaschinen-Fuzzer, um Sequenzen statt isolierter Aufrufe zu generieren. Decke dabei Erstellung, Initialisierung mit Nullwerten, Aktivierung/Finalisierung, Minting, Burning, Transfers, Resets, Migrationen, Sync-Aufrufe und ACL-Änderungen ab. Vergleiche nach jedem Zustandsübergang doppelte Repräsentationen und stelle sicher, dass ein neues Konto keine geschützte Aktion ausführen kann. Lege explizite Fälle für null, eine Einheit, teilweisen Besitz, vollständigen Besitz sowie veraltete zu niedrige und zu hohe Werte an.<sup>[[1]](#references)[[2]](#references)</sup>

Regressionseigenschaften mit hoher Aussagekraft sind:<sup>[[1]](#references)[[2]](#references)</sup>

- Eine maßgebliche Supply von null impliziert niemals Besitz oder administrative Rechte.
- Teilweise Besitzer können nicht zu Administratoren werden, wenn eine doppelte Supply ihrem Kontostand entspricht.
- Ein tatsächlicher Besitzer des gesamten Bestands behält die vorgesehene Abkürzung, wenn die Live-Supply positiv ist.
- Fehlgeschlagene Selbstvergaben verändern weder die ACL noch ermöglichen sie nachgelagerte privilegierte Aufrufe.
- Modusänderungen dürfen nicht unbemerkt ändern, welche Repräsentation eine Autorisierungsprüfung als maßgeblich behandelt.

## References

- [1] [Zustandsabweichungen ermöglichen unbefugten Zugriff (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 – Veraltete Supply-Prüfungen beheben](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance-Commit c81fd65 – Supply von null bei der Autorisierungsabkürzung für die Gesamt-Supply ablehnen](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
