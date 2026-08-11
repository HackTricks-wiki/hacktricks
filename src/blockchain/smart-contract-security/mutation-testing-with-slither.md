# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testet deine Tests“, indem systematisch kleine Änderungen (Mutanten) am Contract-Code vorgenommen und die Testsuite erneut ausgeführt wird. Schlägt ein Test fehl, wird der Mutant getötet. Bestehen die Tests weiterhin, überlebt der Mutant. Dadurch wird ein blinder Fleck aufgedeckt, den Zeilen-/Branch-Coverage nicht erkennen kann.

Die zentrale Idee: Coverage zeigt, dass Code ausgeführt wurde; Mutation testing zeigt, ob das Verhalten tatsächlich überprüft wird.<sup>[[2]](#references)</sup>

## Warum Coverage täuschen kann

Betrachte diese einfache Schwellwertprüfung:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit-Tests, die lediglich einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100 % Line-/Branch-Coverage erreichen, ohne die Gleichheitsgrenze (==) zu testen. Ein Refactoring zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen lassen und dabei unbemerkt die Protokolllogik beschädigen.<sup>[[2]](#references)</sup>

Mutation testing macht diese Lücke sichtbar, indem es die Bedingung mutiert und überprüft, ob die Tests fehlschlagen.

Bei Smart Contracts weisen überlebende Mutanten häufig auf fehlende Prüfungen in folgenden Bereichen hin:
- Autorisierung und Rollenbegrenzungen
- Invarianten für Abrechnung und Wertübertragung
- Revert-Bedingungen und Fehlerpfade
- Grenzbedingungen (`==`, Nullwerte, leere Arrays, Maximal-/Minimalwerte)

## Mutation operators with the highest security signal

Nützliche Mutationsklassen für das Contract-Auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hohe Severity**: Anweisungen durch `revert()` ersetzen, um nicht ausgeführte Pfade aufzudecken
- **Mittlere Severity**: Zeilen auskommentieren / Logik entfernen, um nicht überprüfte Seiteneffekte sichtbar zu machen
- **Niedrige Severity**: Subtile Operator- oder Konstantenaustausche wie `>=` -> `>` oder `+` -> `-`
- Weitere häufige Änderungen: Ersetzen von Zuweisungen, Umkehren von Booleans, Negieren von Bedingungen und Ändern von Typen

Praktisches Ziel: Alle relevanten Mutanten beseitigen und überlebende Mutanten, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Warum syntax-aware mutation besser ist als regex

Ältere Mutation Engines stützten sich auf regex- oder zeilenorientierte Umschreibungen. Das funktioniert, hat jedoch wichtige Einschränkungen:<sup>[[1]](#references)</sup>
- Mehrzeilige Anweisungen lassen sich nur schwer sicher mutieren
- Die Sprachstruktur wird nicht verstanden, sodass Kommentare/Tokens falsch als Ziel ausgewählt werden können
- Das Generieren jeder möglichen Variante für eine schwache Zeile verschwendet große Mengen an Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern dies, indem sie strukturierte Nodes statt roher Zeilen als Ziel verwenden:<sup>[[1]](#references)</sup>
- **slither-mutate** verwendet Slithers Solidity AST.<sup>[[4]](#references)</sup>
- **mewt** verwendet Tree-sitter als sprachunabhängigen Kern.<sup>[[6]](#references)</sup>
- **MuTON** baut auf `mewt` auf und fügt erstklassige Unterstützung für TON-Sprachen wie FunC, Tolk und Tact hinzu.<sup>[[7]](#references)</sup>

Dadurch werden mehrzeilige Konstrukte und Mutationen auf Ausdrucksebene deutlich zuverlässiger als bei ausschließlich regex-basierten Ansätzen.

## Mutation testing mit slither-mutate ausführen

Voraussetzungen: Slither v0.10.2+.

- Optionen und Mutatoren auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Protokoll aufbewahren):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artifacts werden standardmäßig in `./mutation_campaign` gespeichert. Nicht erkannte (überlebende) Mutanten werden zur Untersuchung dorthin kopiert.<sup>[[5]](#references)</sup>

### Die Ausgabe verstehen

Report-Zeilen sehen so aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in eckigen Klammern ist der Alias des Mutators (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass Tests unter dem mutierten Verhalten erfolgreich waren → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutants priorisieren

Mutation campaigns können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:<sup>[[1]](#references)[[2]](#references)</sup>
- Umfang: Beginne nur mit kritischen Contracts/Verzeichnissen und erweitere den Umfang anschließend.
- Mutators priorisieren: Wenn ein Mutant mit hoher Priorität in einer Zeile überlebt (z. B. `revert()` oder das Auskommentieren), überspringe Varianten mit niedrigerer Priorität für diese Zeile.
- Zwei-Phasen-Campaigns verwenden: Führe zuerst fokussierte/schnelle Tests aus und teste anschließend nur die nicht abgefangenen Mutants mit der vollständigen Testsuite erneut.
- Ordne Mutation targets nach Möglichkeit bestimmten Testbefehlen zu (z. B. Auth-Code -> Auth-Tests).
- Beschränke Campaigns bei Zeitknappheit auf Mutants mit hoher/mittlerer Severity.
- Parallelisiere Tests, wenn dein Runner dies erlaubt; cache Dependencies/Builds.
- Fail-fast: Beende den Lauf frühzeitig, wenn eine Änderung eindeutig eine Assertion-Lücke aufzeigt.

Die Laufzeitberechnung ist brutal: `1000 mutants x 5-minute tests ~= 83 hours`; daher ist das Design der Campaign genauso wichtig wie der Mutator selbst.<sup>[[1]](#references)</sup>

## Persistente Campaigns und Triage im großen Maßstab

Eine Schwäche älterer Workflows besteht darin, Ergebnisse ausschließlich auf `stdout` auszugeben. Bei langen Campaigns erschwert dies das Pausieren/Fortsetzen, Filtern und Überprüfen.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbessern dies, indem sie Mutants und Ergebnisse in SQLite-basierten Campaigns speichern. Vorteile:<sup>[[1]](#references)</sup>
- Lange Läufe pausieren und fortsetzen, ohne den Fortschritt zu verlieren
- Nur nicht abgefangene Mutants in einer bestimmten Datei oder Mutationsklasse filtern
- Ergebnisse für Review-Tools nach SARIF exportieren/übersetzen
- Der AI-gestützten Triage kleinere, gefilterte Ergebnismengen anstelle roher Terminal-Logs bereitstellen

Persistente Ergebnisse sind besonders nützlich, wenn Mutation Testing Bestandteil einer Audit-Pipeline statt einer einmaligen manuellen Überprüfung wird.

## Triage-Workflow für überlebende Mutants

1) Untersuche die mutierte Zeile und das Verhalten.
- Reproduziere das Problem lokal, indem du die mutierte Zeile anwendest und einen fokussierten Test ausführst.

2) Verstärke Tests, sodass sie den State und nicht nur Return Values überprüfen.
- Füge Prüfungen für Gleichheitsgrenzen hinzu (z. B. den Threshold `==` testen).
- Überprüfe Post-Conditions: Balances, Total Supply, Authorization Effects und emittierte Events.

3) Ersetze übermäßig permissive Mocks durch realistisches Verhalten.
- Stelle sicher, dass Mocks Transfers, Failure Paths und Event Emissions erzwingen, die on-chain auftreten.

4) Füge Invariants für Fuzz Tests hinzu.
- Z. B. Werterhaltung, nicht negative Balances, Authorization Invariants und gegebenenfalls eine monotone Supply.

5) Trenne echte Positives von semantischen No-Ops.
- Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Führe die Campaign erneut aus, bis die Überlebenden eliminiert oder ausdrücklich begründet wurden.

## Fallstudie: Fehlende State Assertions aufdecken (Arkis Protocol)

Eine Mutation Campaign während eines Audits des Arkis DeFi Protocols brachte unter anderem folgende überlebende Mutants zutage:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung führte nicht dazu, dass die Tests fehlschlugen, und bewies damit fehlende Post-State-Assertions. Ursache: Der Code vertraute auf einen benutzerkontrollierten `_cmd.value`, anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer hätte erwartete und tatsächliche Transfers entkoppeln können, um Gelder abzuschöpfen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.<sup>[[2]](#references)[[3]](#references)</sup>

Leitlinie: Behandle Survivors, die Werttransfers, Accounting oder Access Control beeinflussen, als hohes Risiko, bis sie gekillt wurden.

## Mutants nicht blind durch Tests zu killen versuchen

Die Generierung von Tests auf Basis von Mutation testing kann nach hinten losgehen, wenn die aktuelle Implementierung fehlerhaft ist. Beispiel: Die Mutation von `priority >= 2` zu `priority > 2` verändert das Verhalten, aber die richtige Lösung ist nicht immer, „einen Test für `priority == 2` zu schreiben“. Dieses Verhalten kann selbst der Bug sein.<sup>[[1]](#references)</sup>

Sichererer Workflow:
- Verwende Survivors, um mehrdeutige Anforderungen zu identifizieren
- Validiere das erwartete Verhalten anhand von Spezifikationen, Protokolldokumentation oder durch Reviewer
- Kodiere das Verhalten erst danach als Test/Invariant

Andernfalls riskierst du, Implementierungsfehler fest in der Testsuite zu verankern und falsche Sicherheit zu gewinnen.

## Praktische Checkliste

- Führe eine gezielte Kampagne aus:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Bevorzuge, sofern verfügbar, syntaxbewusste Mutators (AST/Tree-sitter) gegenüber Mutation ausschließlich per Regex.
- Triage Survivors und schreibe Tests/Invariant, die beim mutierten Verhalten fehlschlagen würden.
- Prüfe Balances, Supply, Authorizations und Events.
- Füge Grenzwerttests hinzu (`==`, Overflows/Underflows, Zero-Address, Zero-Amount, leere Arrays).
- Ersetze unrealistische Mocks; simuliere Failure Modes.
- Speichere Ergebnisse, wenn das Tooling dies unterstützt, und filtere nicht abgefangene Mutants vor der Triage.
- Verwende Zwei-Phasen- oder Per-Target-Kampagnen, um die Laufzeit überschaubar zu halten.
- Wiederhole den Vorgang, bis alle Mutants gekillt oder mit Kommentaren und Begründung gerechtfertigt wurden.

## References

- [1] [Mutation testing für das agentische Zeitalter](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Verwende Mutation testing, um die von deinen Tests nicht erkannten Bugs zu finden (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Sicherheitsprüfung des Arkis DeFi Prime Brokerage (Anhang C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither-Mutator-Dokumentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
