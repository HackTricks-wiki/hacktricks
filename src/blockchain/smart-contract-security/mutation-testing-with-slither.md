# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

Mutation Testing „testet deine Tests“, indem systematisch kleine Änderungen (Mutanten) am Contract-Code eingeführt und die Testsuite erneut ausgeführt wird. Wenn ein Test fehlschlägt, ist der Mutant getötet. Wenn die Tests weiterhin erfolgreich sind, überlebt der Mutant. Dadurch wird eine Blindstelle sichtbar, die durch Zeilen-/Branch-Coverage nicht erkannt werden kann.

Kernidee: Coverage zeigt, dass Code ausgeführt wurde; Mutation Testing zeigt, ob das Verhalten tatsächlich verifiziert wird.<sup>[[2]](#references)</sup>

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
Unit-Tests, die nur einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100 % Line-/Branch-Coverage erreichen, ohne die Gleichheitsgrenze (`==`) zu validieren. Ein Refactoring zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen lassen und die Protokolllogik unbemerkt beschädigen.<sup>[[2]](#references)</sup>

Mutation Testing macht diese Lücke sichtbar, indem die Bedingung mutiert und überprüft wird, ob die Tests fehlschlagen.

Bei Smart Contracts weisen überlebende Mutanten häufig auf fehlende Prüfungen in folgenden Bereichen hin:
- Autorisierung und Rollengrenzen
- Invarianten für Abrechnung und Wertübertragung
- Revert-Bedingungen und Fehlerpfade
- Grenzbedingungen (`==`, Nullwerte, leere Arrays, Maximal-/Minimalwerte)

## Mutation operators with the highest security signal

Nützliche Mutationsklassen für das Contract-Auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hoher Schweregrad**: Anweisungen durch `revert()` ersetzen, um nicht ausgeführte Pfade sichtbar zu machen
- **Mittlerer Schweregrad**: Zeilen auskommentieren / Logik entfernen, um nicht verifizierte Seiteneffekte aufzudecken
- **Niedriger Schweregrad**: Subtile Operator- oder Konstantenänderungen wie `>=` -> `>` oder `+` -> `-`
- Weitere häufige Änderungen: Ersetzungen von Zuweisungen, Umkehrungen boolescher Werte, Negation von Bedingungen und Typänderungen

Praktisches Ziel: Alle relevanten Mutanten eliminieren und überlebende Mutanten, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Why syntax-aware mutation is better than regex

Ältere Mutation Engines basierten auf Regex oder zeilenorientierten Umschreibungen. Das funktioniert, weist jedoch wichtige Einschränkungen auf:<sup>[[1]](#references)</sup>
- Mehrzeilige Anweisungen lassen sich nur schwer sicher mutieren
- Die Sprachstruktur wird nicht verstanden, sodass Kommentare/Tokens falsch ausgewählt werden können
- Das Erzeugen jeder möglichen Variante auf einer schwachen Zeile verbraucht große Mengen an Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern dies, indem sie strukturierte Knoten anstelle roher Zeilen ansprechen:<sup>[[1]](#references)</sup>
- **slither-mutate** verwendet Slithers Solidity-AST.<sup>[[4]](#references)</sup>
- **mewt** verwendet Tree-sitter als sprachunabhängigen Kern.<sup>[[6]](#references)</sup>
- **MuTON** baut auf `mewt` auf und bietet native Unterstützung für TON-Sprachen wie FunC, Tolk und Tact.<sup>[[7]](#references)</sup>

Dadurch sind mehrzeilige Konstrukte und Mutationen auf Ausdrucksebene wesentlich zuverlässiger als bei ausschließlich Regex-basierten Ansätzen.

## Running mutation testing with slither-mutate

Voraussetzung: Slither v0.10.2+.

- Optionen und Mutatoren auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Protokoll führen):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artifacts werden standardmäßig in `./mutation_campaign` gespeichert. Nicht erkannte (überlebende) Mutanten werden zur Inspektion dorthin kopiert.<sup>[[5]](#references)</sup>

### Die Ausgabe verstehen

Report-Zeilen sehen folgendermaßen aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in Klammern ist der Alias des Mutators (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass Tests unter dem mutierten Verhalten erfolgreich waren → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutanten priorisieren

Mutation-Kampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:<sup>[[1]](#references)[[2]](#references)</sup>
- Umfang: Zunächst nur kritische Contracts/Verzeichnisse prüfen und anschließend erweitern.
- Mutatoren priorisieren: Wenn ein Mutant mit hoher Priorität in einer Zeile überlebt (z. B. `revert()` oder Comment-out), Varianten mit niedrigerer Priorität für diese Zeile überspringen.
- Zweiphasige Kampagnen verwenden: Zuerst fokussierte/schnelle Tests ausführen, anschließend nur nicht abgefangene Mutanten mit der vollständigen Testsuite erneut testen.
- Mutation-Ziele nach Möglichkeit bestimmten Testbefehlen zuordnen (z. B. Auth-Code -> Auth-Tests).
- Bei knappem Zeitrahmen Kampagnen auf Mutanten mit hoher/mittlerer Severity beschränken.
- Tests parallelisieren, sofern der Runner dies unterstützt; Dependencies/Builds cachen.
- Fail-fast: frühzeitig stoppen, wenn eine Änderung eindeutig eine Assertion-Lücke aufzeigt.

Die Laufzeitrechnung ist brutal: `1000 mutants x 5-minute tests ~= 83 hours` – daher ist das Kampagnendesign ebenso wichtig wie der Mutator selbst.<sup>[[1]](#references)</sup>

## Persistente Kampagnen und Triage im großen Maßstab

Eine Schwäche älterer Workflows besteht darin, Ergebnisse nur an `stdout` auszugeben. Bei langen Kampagnen erschwert dies das Pausieren/Fortsetzen, Filtern und Überprüfen.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbessern dies, indem sie Mutanten und Ergebnisse in SQLite-basierten Kampagnen speichern. Vorteile:<sup>[[1]](#references)</sup>
- Lange Läufe pausieren und fortsetzen, ohne den Fortschritt zu verlieren
- Nur nicht abgefangene Mutanten in einer bestimmten Datei oder Mutationsklasse filtern
- Ergebnisse zur Verwendung mit Review-Tools nach SARIF exportieren/übersetzen
- Der AI-gestützten Triage kleinere, gefilterte Ergebnismengen statt roher Terminal-Logs bereitstellen

Persistente Ergebnisse sind besonders nützlich, wenn Mutationstests Bestandteil einer Audit-Pipeline und nicht nur einer einmaligen manuellen Überprüfung werden.

## Triage-Workflow für überlebende Mutanten

1) Die mutierte Zeile und das Verhalten untersuchen.
- Lokal reproduzieren, indem die mutierte Zeile angewendet und ein fokussierter Test ausgeführt wird.

2) Tests erweitern, sodass der State und nicht nur Rückgabewerte geprüft wird.
- Prüfungen für Gleichheitsgrenzen hinzufügen (z. B. den Schwellenwert `==` testen).
- Post-Conditions prüfen: Balances, Total Supply, Autorisierungseffekte und emittierte Events.

3) Übermäßig großzügige Mocks durch realistisches Verhalten ersetzen.
- Sicherstellen, dass Mocks Transfers, Fehlerpfade und auf der Chain auftretende Event-Emissionen erzwingen.

4) Invarianten für Fuzz-Tests hinzufügen.
- Z. B. Werterhaltung, nicht-negative Balances, Autorisierungsinvarianten und gegebenenfalls eine monotone Supply.

5) Echte Treffer von semantischen No-ops trennen.
- Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Die Kampagne erneut ausführen, bis überlebende Mutanten beseitigt oder ausdrücklich begründet wurden.

## Fallstudie: Fehlende State-Assertions aufdecken (Arkis Protocol)

Eine Mutation-Kampagne während eines Audits des Arkis DeFi Protocols brachte unter anderem folgende überlebende Mutanten zutage:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung ließ die Tests nicht fehlschlagen, was fehlende Post-State-Assertions belegt. Grundursache: Der Code vertraute auf ein vom Benutzer kontrolliertes `_cmd.value`, anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer hätte erwartete und tatsächliche Transfers entkoppeln können, um Gelder abzuschöpfen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.<sup>[[2]](#references)[[3]](#references)</sup>

Hinweis: Behandle überlebende Mutanten, die Werttransfers, Abrechnung oder Zugriffskontrolle beeinflussen, als hohes Risiko, bis sie beseitigt wurden.

## Tests nicht blind generieren, um jede Mutante zu beseitigen

Die mutation-driven Testgenerierung kann nach hinten losgehen, wenn die aktuelle Implementierung fehlerhaft ist. Beispiel: Die Mutation von `priority >= 2` zu `priority > 2` ändert das Verhalten, aber die richtige Korrektur besteht nicht immer darin, „einen Test für `priority == 2` zu schreiben“. Dieses Verhalten kann selbst der Fehler sein.<sup>[[1]](#references)</sup>

Sichererer Workflow:
- Verwende überlebende Mutanten, um mehrdeutige Anforderungen zu identifizieren
- Validiere das erwartete Verhalten anhand von Spezifikationen, Protokolldokumentation oder durch Reviewer
- Kodiere das Verhalten erst dann als Test/Invariant

Andernfalls riskierst du, Implementierungszufälligkeiten fest in die Testsuite einzubauen und falsches Vertrauen zu gewinnen.

## Praktische Checkliste

- Führe eine gezielte Kampagne aus:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Bevorzuge, sofern verfügbar, syntaxbewusste Mutatoren (AST/Tree-sitter) gegenüber Mutationen, die ausschließlich auf regulären Ausdrücken basieren.
- Analysiere überlebende Mutanten und schreibe Tests/Invariant, die beim mutierten Verhalten fehlschlagen würden.
- Prüfe Salden, Supply, Autorisierungen und Events.
- Füge Grenzfalltests hinzu (`==`, Overflows/Underflows, Nulladresse, Nullbetrag, leere Arrays).
- Ersetze unrealistische Mocks und simuliere Fehlerszenarien.
- Speichere die Ergebnisse, wenn das Tooling dies unterstützt, und filtere nicht erfasste Mutanten vor der Analyse.
- Verwende Zwei-Phasen- oder Pro-Ziel-Kampagnen, um die Laufzeit überschaubar zu halten.
- Wiederhole den Vorgang, bis alle Mutanten beseitigt oder mit Kommentaren und Begründung gerechtfertigt wurden.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Mutation testing verwenden, um Bugs zu finden, die deine Tests nicht erkennen (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Sicherheitsüberprüfung von Arkis DeFi Prime Brokerage (Anhang C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentation zum Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
