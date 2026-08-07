# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation Testing „testet deine Tests“, indem systematisch kleine Änderungen (Mutanten) am Contract-Code vorgenommen und die Testsuite erneut ausgeführt wird. Schlägt ein Test fehl, wird der Mutant getötet. Bestehen die Tests weiterhin, überlebt der Mutant, wodurch ein blinder Fleck sichtbar wird, den die Zeilen-/Branch-Coverage nicht erkennen kann.

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
Unit tests, die nur einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100 % Line-/Branch-Coverage erreichen, ohne die Gleichheitsgrenze (==) zu testen. Ein Refactoring zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen lassen und damit unbemerkt die Protokolllogik brechen.<sup>[[2]](#references)</sup>

Mutation testing macht diese Lücke sichtbar, indem die Bedingung mutiert und verifiziert wird, dass die Tests fehlschlagen.

Bei Smart Contracts weisen überlebende Mutanten häufig auf fehlende Prüfungen in folgenden Bereichen hin:
- Autorisierung und Rollenabgrenzungen
- Accounting-/Werttransfer-Invarianten
- Revert-Bedingungen und Fehlerpfade
- Grenzbedingungen (`==`, Nullwerte, leere Arrays, Maximal-/Minimalwerte)

## Mutation operators mit dem höchsten Security-Signal

Nützliche Mutation-Klassen für das Contract-Auditing:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hohe Schwere**: Statements durch `revert()` ersetzen, um nicht ausgeführte Pfade sichtbar zu machen
- **Mittlere Schwere**: Zeilen auskommentieren / Logik entfernen, um nicht verifizierte Seiteneffekte aufzudecken
- **Geringe Schwere**: Subtile Operator- oder Konstantenänderungen wie `>=` -> `>` oder `+` -> `-`
- Weitere häufige Änderungen: Ersetzen von Zuweisungen, Umkehren von Booleans, Negieren von Bedingungen und Ändern von Typen

Praktisches Ziel: Alle bedeutenden Mutanten eliminieren und überlebende Mutanten, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Warum syntaxbewusstes Mutation testing besser als Regex ist

Ältere Mutation-Engines basierten auf Regex oder zeilenorientierten Umschreibungen. Das funktioniert, hat aber wichtige Einschränkungen:<sup>[[1]](#references)</sup>
- Mehrzeilige Statements lassen sich nur schwer sicher mutieren
- Die Sprachstruktur wird nicht verstanden, sodass Kommentare/Tokens falsch als Ziel ausgewählt werden können
- Das Erzeugen jeder möglichen Variante auf einer schwachen Codezeile verschwendet große Mengen an Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern dies, indem sie strukturierte Nodes statt roher Zeilen als Ziel verwenden:<sup>[[1]](#references)</sup>
- **slither-mutate** verwendet Slithers Solidity-AST<sup>[[4]](#references)</sup>
- **mewt** verwendet Tree-sitter als sprachunabhängigen Kern<sup>[[6]](#references)</sup>
- **MuTON** baut auf `mewt` auf und fügt erstklassige Unterstützung für TON-Sprachen wie FunC, Tolk und Tact hinzu<sup>[[7]](#references)</sup>

Dadurch sind mehrzeilige Konstrukte und Mutationen auf Expression-Ebene deutlich zuverlässiger als bei ausschließlich Regex-basierten Ansätzen.

## Mutation testing mit slither-mutate ausführen

Voraussetzungen: Slither v0.10.2+.

- Optionen und Mutators auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Protokoll aufbewahren):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artefakte werden standardmäßig in `./mutation_campaign` gespeichert. Nicht abgefangene (überlebende) Mutanten werden zur Untersuchung dorthin kopiert.<sup>[[5]](#references)</sup>

### Ausgabe verstehen

Die Zeilen des Reports sehen folgendermaßen aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in Klammern ist der Alias des Mutators (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass die Tests unter dem mutierten Verhalten bestanden wurden → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutanten priorisieren

Mutation-Kampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:<sup>[[1]](#references)[[2]](#references)</sup>
- Umfang: Zuerst nur kritische Contracts/Verzeichnisse einbeziehen, dann erweitern.
- Mutators priorisieren: Wenn ein Mutant mit hoher Priorität in einer Zeile überlebt (z. B. `revert()` oder das Auskommentieren), Varianten mit niedrigerer Priorität für diese Zeile überspringen.
- Zweiphasige Kampagnen verwenden: Zuerst fokussierte/schnelle Tests ausführen, anschließend nur nicht erfasste Mutanten mit der vollständigen Testsuite erneut testen.
- Mutation-Ziele nach Möglichkeit bestimmten Testbefehlen zuordnen (z. B. Auth-Code -> Auth-Tests).
- Bei knappem Zeitbudget Kampagnen auf Mutanten mit hoher/mittlerer Severity beschränken.
- Tests parallelisieren, wenn der Runner dies unterstützt; Dependencies/Builds cachen.
- Fail-fast: Frühzeitig stoppen, wenn eine Änderung eindeutig eine Assertion-Lücke aufzeigt.

Die Laufzeitberechnung ist brutal: `1000 mutants x 5-minute tests ~= 83 hours` — daher ist das Kampagnendesign genauso wichtig wie der Mutator selbst.<sup>[[1]](#references)</sup>

## Persistente Kampagnen und Triage im großen Maßstab

Eine Schwäche älterer Workflows besteht darin, Ergebnisse ausschließlich nach `stdout` zu schreiben. Bei langen Kampagnen erschwert dies das Pausieren/Fortsetzen, Filtern und Überprüfen.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbessern dies, indem sie Mutanten und Ergebnisse in SQLite-basierten Kampagnen speichern. Vorteile:<sup>[[1]](#references)</sup>
- Lange Läufe pausieren und fortsetzen, ohne den Fortschritt zu verlieren
- Nur nicht erfasste Mutanten in einer bestimmten Datei oder Mutationsklasse filtern
- Ergebnisse für Review-Tools nach SARIF exportieren/übersetzen
- Der KI-gestützten Triage kleinere, gefilterte Ergebnismengen anstelle roher Terminal-Logs bereitstellen

Persistente Ergebnisse sind besonders nützlich, wenn Mutation Testing Teil einer Audit-Pipeline statt einer einmaligen manuellen Überprüfung wird.

## Triage-Workflow für überlebende Mutanten

1) Die mutierte Zeile und das Verhalten überprüfen.
- Lokal reproduzieren, indem die mutierte Zeile angewendet und ein fokussierter Test ausgeführt wird.

2) Tests verstärken, sodass der Zustand und nicht nur Rückgabewerte geprüft werden.
- Prüfungen an Gleichheitsgrenzen hinzufügen (z. B. den Schwellenwert `==` testen).
- Post-Conditions prüfen: Balances, Gesamtangebot, Autorisierungseffekte und emittierte Events.

3) Übermäßig permissive Mocks durch realistisches Verhalten ersetzen.
- Sicherstellen, dass Mocks Transfers, Fehlerpfade und on-chain auftretende Event-Emissionen erzwingen.

4) Invarianten für Fuzz-Tests hinzufügen.
- Z. B. Werterhaltung, nicht-negative Balances, Autorisierungsinvarianten und gegebenenfalls ein monoton steigendes Supply.

5) Echte positive Ergebnisse von semantischen No-Ops trennen.
- Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Die Kampagne erneut ausführen, bis überlebende Mutanten getötet oder ausdrücklich begründet wurden.

## Fallstudie: Fehlende State-Assertions aufdecken (Arkis-Protokoll)

Eine Mutation-Kampagne während eines Audits des Arkis DeFi-Protokolls brachte unter anderem folgende überlebende Mutanten zum Vorschein:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung ließ die Tests nicht fehlschlagen und bewies damit, dass Assertions für den Post-State fehlen. Grundursache: Der Code vertraute auf ein benutzerkontrolliertes `_cmd.value`, anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer hätte erwartete und tatsächliche Transfers entkoppeln können, um Gelder abzuschöpfen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.<sup>[[2]](#references)[[3]](#references)</sup>

Hinweis: Behandle Überlebende, die Werttransfers, Buchführung oder Zugriffskontrolle beeinflussen, als hohes Risiko, bis sie beseitigt wurden.

## Nicht blind Tests generieren, um jeden Mutanten zu beseitigen

Die durch Mutation gesteuerte Testgenerierung kann nach hinten losgehen, wenn die aktuelle Implementierung fehlerhaft ist. Beispiel: Die Mutation von `priority >= 2` zu `priority > 2` ändert das Verhalten, aber die richtige Behebung besteht nicht immer darin, „einen Test für `priority == 2` zu schreiben“. Dieses Verhalten kann selbst der Bug sein.<sup>[[1]](#references)</sup>

Sichererer Ablauf:
- Verwende überlebende Mutanten, um mehrdeutige Anforderungen zu identifizieren
- Validiere das erwartete Verhalten anhand von Spezifikationen, Protokolldokumentation oder durch Reviewer
- Kodiere das Verhalten erst danach als Test/Invariant

Andernfalls riskierst du, Implementierungszufälle fest in der Testsuite zu verankern und falsches Vertrauen zu gewinnen.

## Praktische Checkliste

- Führe eine gezielte Kampagne aus:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Bevorzuge, sofern verfügbar, syntaxbewusste Mutatoren (AST/Tree-sitter) gegenüber Mutation, die ausschließlich auf regulären Ausdrücken basiert.
- Triage die Überlebenden und schreibe Tests/Invariant, die beim mutierten Verhalten fehlschlagen würden.
- Prüfe Salden, Supply, Autorisierungen und Events.
- Füge Grenzwerttests hinzu (`==`, Overflows/Underflows, Zero-Address, Zero-Amount, leere Arrays).
- Ersetze unrealistische Mocks; simuliere Fehlerszenarien.
- Speichere Ergebnisse dauerhaft, wenn das Tooling dies unterstützt, und filtere nicht erfasste Mutanten vor der Triage.
- Verwende Zwei-Phasen- oder kampagnenweise pro Ziel ausgeführte Kampagnen, um die Laufzeit überschaubar zu halten.
- Wiederhole den Vorgang, bis alle Mutanten beseitigt oder mit Kommentaren und Begründung gerechtfertigt wurden.

## Referenzen

- [1] [Mutation testing für das agentische Zeitalter](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Verwende Mutation testing, um die von deinen Tests nicht erkannten Bugs zu finden (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Sicherheitsüberprüfung von Arkis DeFi Prime Brokerage (Anhang C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentation zu Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
