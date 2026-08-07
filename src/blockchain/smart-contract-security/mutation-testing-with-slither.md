# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation Testing „testet deine Tests“, indem systematisch kleine Änderungen (Mutanten) am Contract-Code vorgenommen und die Testsuite erneut ausgeführt wird. Schlägt ein Test fehl, wird der Mutant getötet. Bestehen die Tests weiterhin, überlebt der Mutant, wodurch eine Schwachstelle sichtbar wird, die durch Zeilen-/Branch-Coverage nicht erkannt werden kann.

Die zentrale Idee: Coverage zeigt, dass Code ausgeführt wurde; Mutation Testing zeigt, ob das Verhalten tatsächlich überprüft wird.<sup>[[2]](#references)</sup>

## Warum Coverage täuschen kann

Betrachte diese einfache Schwellenwertprüfung:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit-Tests, die nur einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100 % Line-/Branch-Coverage erreichen, ohne die Gleichheitsgrenze (`==`) zu testen. Ein Refactoring zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen lassen und dadurch unbemerkt die Protokolllogik brechen.<sup>[[2]](#references)</sup>

Mutation testing macht diese Lücke sichtbar, indem die Bedingung mutiert und überprüft wird, ob die Tests fehlschlagen.

Bei Smart Contracts weisen überlebende Mutanten häufig auf fehlende Prüfungen in folgenden Bereichen hin:
- Autorisierung und Rollen-Grenzen
- Invarianten für Accounting und Wertübertragungen
- Revert-Bedingungen und Fehlerpfade
- Grenzbedingungen (`==`, Nullwerte, leere Arrays, Maximal-/Minimalwerte)

## Mutation operators mit dem höchsten Security-Signal

Nützliche Mutation-Klassen für das Contract-Auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hohe Schwere**: Anweisungen durch `revert()` ersetzen, um nicht ausgeführte Pfade sichtbar zu machen
- **Mittlere Schwere**: Zeilen auskommentieren / Logik entfernen, um nicht überprüfte Seiteneffekte aufzudecken
- **Geringe Schwere**: Subtile Operator- oder Konstantenänderungen wie `>=` -> `>` oder `+` -> `-`
- Weitere übliche Änderungen: Ersetzen von Zuweisungen, Umkehren von Booleans, Negieren von Bedingungen und Ändern von Typen

Praktisches Ziel: Alle relevanten Mutanten eliminieren und überlebende Mutanten, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Warum syntaxbewusstes Mutation testing besser ist als Regex

Ältere Mutation Engines nutzten Regex oder zeilenorientierte Umschreibungen. Das funktioniert, hat jedoch wichtige Einschränkungen:<sup>[[1]](#references)</sup>
- Mehrzeilige Anweisungen lassen sich nur schwer sicher mutieren
- Die Sprachstruktur wird nicht verstanden, sodass Kommentare/Tokens falsch als Ziel ausgewählt werden können
- Das Erzeugen jeder möglichen Variante in einer schwachen Zeile verschwendet große Mengen an Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern dies, indem sie strukturierte Knoten statt roher Zeilen als Ziel verwenden:<sup>[[1]](#references)</sup>
- **slither-mutate** verwendet Slithers Solidity-AST
- **mewt** verwendet Tree-sitter als sprachunabhängigen Kern
- **MuTON** baut auf `mewt` auf und ergänzt First-Class-Support für TON-Sprachen wie FunC, Tolk und Tact

Dadurch sind Mutationen mehrzeiliger Konstrukte und auf Expression-Ebene wesentlich zuverlässiger als bei ausschließlich Regex-basierten Ansätzen.

## Mutation testing mit slither-mutate ausführen

Voraussetzung: Slither v0.10.2+.

- Optionen und Mutatoren auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Log behalten):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artifacts werden standardmäßig in `./mutation_campaign` gespeichert. Nicht abgefangene (überlebende) Mutants werden zur Inspektion dorthin kopiert.<sup>[[5]](#references)</sup>

### Die Ausgabe verstehen

Berichtszeilen sehen so aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in Klammern ist das Alias des Mutators (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass die Tests unter dem mutierten Verhalten erfolgreich waren → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutants priorisieren

Mutation-Kampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:<sup>[[1]](#references)[[2]](#references)</sup>
- Umfang: Zuerst nur kritische Contracts/Verzeichnisse überprüfen und anschließend erweitern.
- Mutators priorisieren: Wenn ein Mutant mit hoher Priorität in einer Zeile überlebt (z. B. `revert()` oder das Auskommentieren), Varianten mit niedrigerer Priorität für diese Zeile überspringen.
- Zwei-Phasen-Kampagnen verwenden: Zuerst fokussierte/schnelle Tests ausführen, anschließend nur nicht abgefangene Mutants mit der vollständigen Testsuite erneut testen.
- Mutation Targets nach Möglichkeit bestimmten Testbefehlen zuordnen (z. B. Auth-Code -> Auth-Tests).
- Wenn die Zeit knapp ist, Kampagnen auf Mutants mit hoher/mittlerer Severity beschränken.
- Tests parallelisieren, sofern der Runner dies ermöglicht; Dependencies/Builds cachen.
- Fail-fast: Frühzeitig stoppen, wenn eine Änderung eindeutig eine Assertion-Lücke aufzeigt.

Die Laufzeitberechnung ist brutal: `1000 mutants x 5-minute tests ~= 83 hours` – daher ist das Kampagnen-Design genauso wichtig wie der Mutator selbst.

## Persistente Kampagnen und Triage im großen Maßstab

Eine Schwäche älterer Workflows besteht darin, Ergebnisse ausschließlich in `stdout` auszugeben. Bei langen Kampagnen erschwert dies das Pausieren/Fortsetzen, Filtern und Überprüfen.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbessern dies, indem sie Mutants und Ergebnisse in SQLite-basierten Kampagnen speichern. Vorteile:<sup>[[1]](#references)</sup>
- Lange Läufe pausieren und fortsetzen, ohne den Fortschritt zu verlieren
- Nur nicht abgefangene Mutants in einer bestimmten Datei oder Mutationsklasse filtern
- Ergebnisse für Review-Tools nach SARIF exportieren/übersetzen
- Der AI-gestützten Triage kleinere, gefilterte Ergebnismengen anstelle roher Terminal-Logs bereitstellen

Persistente Ergebnisse sind besonders nützlich, wenn Mutation Testing Bestandteil einer Audit-Pipeline und nicht nur einer einmaligen manuellen Überprüfung wird.

## Triage-Workflow für überlebende Mutants

1) Die mutierte Zeile und das Verhalten überprüfen.
- Lokal reproduzieren, indem die mutierte Zeile angewendet und ein fokussierter Test ausgeführt wird.

2) Tests verstärken, um den Zustand und nicht nur Rückgabewerte zu überprüfen.
- Prüfungen an Gleichheitsgrenzen hinzufügen (z. B. den Schwellenwert `==` testen).
- Post-Conditions überprüfen: Balances, Total Supply, Autorisierungseffekte und emittierte Events.

3) Übermäßig permissive Mocks durch realistisches Verhalten ersetzen.
- Sicherstellen, dass Mocks Transfers, Fehlerpfade und Event-Emissionen erzwingen, die on-chain auftreten.

4) Invariants für Fuzz-Tests hinzufügen.
- Z. B. Werterhaltung, nicht-negative Balances, Autorisierungs-Invariants und, sofern zutreffend, eine monotone Supply.

5) Echte Positives von semantischen No-Ops trennen.
- Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Die Kampagne erneut ausführen, bis die Überlebenden beseitigt oder ausdrücklich begründet wurden.

## Fallstudie: Fehlende Zustandsassertionen aufdecken (Arkis Protocol)

Eine Mutation-Kampagne während eines Audits des Arkis-DeFi-Protokolls brachte unter anderem folgende überlebende Mutants zum Vorschein:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung hat die Tests nicht beeinträchtigt und damit fehlende Post-State-Assertions bewiesen. Grundursache: Der Code vertraute auf einen benutzerkontrollierten `_cmd.value`, anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer hätte erwartete und tatsächliche Transfers entkoppeln können, um Mittel abzuschöpfen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.<sup>[[2]](#references)[[3]](#references)</sup>

Leitlinie: Behandle überlebende Mutanten, die Werttransfers, Accounting oder Access Control beeinflussen, als hohes Risiko, bis sie beseitigt sind.

## Tests nicht blind generieren, um jede Mutante zu beseitigen

Die durch Mutationen gesteuerte Testgenerierung kann nach hinten losgehen, wenn die aktuelle Implementierung fehlerhaft ist. Beispiel: Die Mutation von `priority >= 2` zu `priority > 2` ändert das Verhalten, aber die richtige Korrektur besteht nicht immer darin, „einen Test für `priority == 2` zu schreiben“. Dieses Verhalten kann selbst der Fehler sein.<sup>[[1]](#references)</sup>

Sichererer Workflow:
- Verwende überlebende Mutanten, um unklare Anforderungen zu identifizieren
- Validiere das erwartete Verhalten anhand von Spezifikationen, Protokolldokumentation oder durch Reviewer
- Kodiere das Verhalten erst danach als Test/Invariant

Andernfalls riskierst du, Implementierungszufälle fest in die Testsuite einzubauen und falsche Sicherheit zu gewinnen.

## Praktische Checkliste

- Führe eine gezielte Kampagne aus:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Bevorzuge, sofern verfügbar, syntaxbewusste Mutatoren (AST/Tree-sitter) gegenüber Mutationen, die ausschließlich reguläre Ausdrücke verwenden.
- Triage überlebende Mutanten und schreibe Tests/Invariantien, die beim mutierten Verhalten fehlschlagen würden.
- Prüfe Salden, Supply, Autorisierungen und Events.
- Füge Boundary-Tests hinzu (`==`, Overflows/Underflows, Zero-Address, Zero-Amount, leere Arrays).
- Ersetze unrealistische Mocks und simuliere Failure Modes.
- Speichere Ergebnisse persistent, sofern das Tooling dies unterstützt, und filtere nicht erfasste Mutanten vor der Triage.
- Verwende Zwei-Phasen- oder Per-Target-Kampagnen, um die Laufzeit überschaubar zu halten.
- Iteriere, bis alle Mutanten beseitigt oder mit Kommentaren und Begründung gerechtfertigt sind.

## Referenzen

- [1] [Mutation Testing für die agentische Ära](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Finde mit Mutation Testing Bugs, die deine Tests nicht erkennen (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Anhang C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentation zu Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
