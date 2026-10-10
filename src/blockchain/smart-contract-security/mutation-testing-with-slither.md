# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation Testing „testet deine Tests“, indem systematisch kleine Änderungen (Mutanten) am Contract-Code vorgenommen und die Testsuite erneut ausgeführt wird. Schlägt ein Test fehl, ist der Mutant getötet. Bestehen die Tests weiterhin, überlebt der Mutant und deckt so einen blinden Fleck auf, den Line-/Branch-Coverage nicht erkennen kann.

Kernidee: Coverage zeigt, dass Code ausgeführt wurde; Mutation Testing zeigt, ob das Verhalten tatsächlich geprüft wird.<sup>[[2]](#references)</sup>

## Warum Coverage täuschen kann

Betrachten wir diese einfache Schwellwertprüfung:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Unit-Tests, die lediglich einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100 % Line-/Branch-Coverage erreichen, ohne die Gleichheitsgrenze (`==`) zu testen. Ein Refactoring zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen und die Protokolllogik unbemerkt beschädigen.<sup>[[2]](#references)</sup>

Mutation-Testing deckt diese Lücke auf, indem die Bedingung mutiert und überprüft wird, ob die Tests fehlschlagen.

Bei Smart Contracts weisen überlebende Mutanten häufig auf fehlende Prüfungen in folgenden Bereichen hin:
- Autorisierung und Rollengrenzen
- Invarianten zu Abrechnung und Wertübertragung
- Revert-Bedingungen und Fehlerpfade
- Grenzfälle (`==`, Nullwerte, leere Arrays, Maximal-/Minimalwerte)

## Mutationsoperatoren mit dem höchsten Sicherheitssignal

Nützliche Mutationsklassen für Contract-Audits:<sup>[[1]](#references)[[2]](#references)</sup>
- **Hohe Schwere**: Anweisungen durch `revert()` ersetzen, um nicht ausgeführte Pfade aufzudecken
- **Mittlere Schwere**: Zeilen auskommentieren / Logik entfernen, um nicht verifizierte Seiteneffekte aufzudecken
- **Geringe Schwere**: subtile Operator- oder Konstantenänderungen wie `>=` -> `>` oder `+` -> `-`
- Weitere häufige Änderungen: Zuweisungen ersetzen, boolesche Werte umkehren, Bedingungen negieren und Typen ändern

Praktisches Ziel: alle aussagekräftigen Mutanten abtöten und überlebende Mutanten, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Warum syntaxbewusste Mutation besser ist als Regex

Ältere Mutation-Engines stützten sich auf Regex oder zeilenweise Umschreibungen. Das funktioniert, hat aber wichtige Einschränkungen:<sup>[[1]](#references)</sup>
- Mehrzeilige Anweisungen lassen sich nur schwer sicher mutieren
- Die Sprachstruktur wird nicht berücksichtigt, sodass Kommentare/Token falsch erfasst werden können
- Alle möglichen Varianten einer schwach abgedeckten Zeile zu erzeugen, verschwendet viel Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern dies, indem sie strukturierte Knoten statt unverarbeiteter Zeilen anvisieren:<sup>[[1]](#references)</sup>
- **slither-mutate** verwendet Slithers Solidity-AST.<sup>[[4]](#references)</sup>
- **mewt** verwendet Tree-sitter als sprachunabhängigen Kern.<sup>[[6]](#references)</sup>
- **MuTON** baut auf `mewt` auf und ergänzt native Unterstützung für TON-Sprachen wie FunC, Tolk und Tact.<sup>[[7]](#references)</sup>

Dadurch sind mehrzeilige Konstrukte und Mutationen auf Ausdrucksebene deutlich zuverlässiger als bei Ansätzen, die ausschließlich Regex verwenden.

## Mutation-Testing mit slither-mutate ausführen

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

Artifacts werden standardmäßig in `./mutation_campaign` gespeichert. Nicht erkannte (überlebende) Mutanten werden zur Prüfung dorthin kopiert.<sup>[[5]](#references)</sup>

### Die Ausgabe verstehen

Berichtszeilen sehen so aus:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Das Tag in eckigen Klammern ist der Mutator-Alias (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass die Tests mit dem mutierten Verhalten bestanden wurden → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutanten priorisieren

Mutation-Kampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:<sup>[[1]](#references)[[2]](#references)</sup>
- Umfang: Beginne nur mit kritischen Contracts/Verzeichnissen und erweitere den Umfang dann.
- Mutatoren priorisieren: Wenn ein Mutant mit hoher Priorität auf einer Zeile überlebt (z. B. `revert()` oder Auskommentieren), überspringe Varianten mit niedrigerer Priorität für diese Zeile.
- Kampagnen in zwei Phasen durchführen: Führe zuerst gezielte/schnelle Tests aus und teste dann nur die nicht erfassten Mutanten erneut mit der vollständigen Suite.
- Ordne Mutation-Ziele nach Möglichkeit bestimmten Testbefehlen zu (z. B. Auth-Code -> Auth-Tests).
- Beschränke Kampagnen bei knappem Zeitbudget auf Mutanten mit hohem/mittlerem Schweregrad.
- Führe Tests parallel aus, sofern dein Runner dies unterstützt; cache Abhängigkeiten und Builds.
- Fail-fast: Brich frühzeitig ab, wenn eine Änderung eindeutig eine Assertion-Lücke aufzeigt.

Die Laufzeitrechnung ist brutal: `1000 mutants x 5-minute tests ~= 83 hours`. Daher ist das Kampagnendesign genauso wichtig wie der Mutator selbst.<sup>[[1]](#references)</sup>

## Persistente Kampagnen und Triage in großem Maßstab

Eine Schwäche älterer Workflows ist, dass Ergebnisse nur in `stdout` ausgegeben werden. Bei langen Kampagnen erschwert dies das Pausieren/Fortsetzen, Filtern und Überprüfen.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` verbessern dies, indem sie Mutanten und Ergebnisse in SQLite-gestützten Kampagnen speichern. Vorteile:<sup>[[1]](#references)</sup>
- Lange Durchläufe pausieren und fortsetzen, ohne Fortschritte zu verlieren
- Nur nicht erfasste Mutanten in einer bestimmten Datei oder Mutationsklasse filtern
- Ergebnisse für Review-Tools nach SARIF exportieren/übersetzen
- Der KI-gestützten Triage kleinere, gefilterte Ergebnismengen statt unbearbeiteter Terminal-Logs bereitstellen

Persistente Ergebnisse sind besonders nützlich, wenn Mutation Testing Teil einer Audit-Pipeline statt einer einmaligen manuellen Prüfung wird.

## Triage-Workflow für überlebende Mutanten

1) Prüfe die mutierte Zeile und ihr Verhalten.
   - Reproduziere das Problem lokal, indem du die mutierte Zeile anwendest und einen gezielten Test ausführst.

2) Verstärke Tests, sodass sie den Zustand und nicht nur Rückgabewerte prüfen.
   - Füge Prüfungen für Gleichheitsgrenzen hinzu (z. B. teste den Schwellenwert `==`).
   - Prüfe Nachbedingungen: Balances, Gesamtangebot, Autorisierungseffekte und ausgegebene Events.

3) Ersetze übermäßig permissive Mocks durch realistisches Verhalten.
   - Stelle sicher, dass Mocks Transfers, Fehlerpfade und Event-Ausgaben erzwingen, die on-chain auftreten.

4) Füge Invarianten für Fuzz-Tests hinzu.
   - Z. B. Werterhaltung, nicht negative Balances, Autorisierungsinvarianten und, wo zutreffend, ein monoton steigendes Angebot.

5) Trenne echte Treffer von semantischen No-Ops.
   - Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Führe die Kampagne erneut aus, bis überlebende Mutanten erkannt oder ausdrücklich begründet wurden.

## Fallstudie: Fehlende Zustandsassertions aufdecken (Arkis-Protokoll)

Eine Mutation-Kampagne während eines Audits des Arkis-DeFi-Protokolls deckte unter anderem folgende überlebende Mutanten auf:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Das Auskommentieren der Zuweisung ließ die Tests nicht fehlschlagen und belegte damit fehlende Post-State-Assertions. Ursache: Der Code vertraute auf einen benutzergesteuerten Wert in `_cmd.value`, anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer konnte die erwarteten und tatsächlichen Transfers voneinander abweichen lassen, um Gelder abzuziehen. Ergebnis: ein schwerwiegendes Risiko für die Solvenz des Protokolls.<sup>[[2]](#references)[[3]](#references)</sup>

Leitlinie: Behandle überlebende Mutanten, die sich auf Werttransfers, Buchführung oder Zugriffskontrolle auswirken, als hohes Risiko, bis sie beseitigt sind.

## Do not blindly generate tests to kill every mutant

Die durch Mutationstests gesteuerte Testgenerierung kann nach hinten losgehen, wenn die aktuelle Implementierung fehlerhaft ist. Beispiel: Die Mutation von `priority >= 2` zu `priority > 2` verändert das Verhalten, aber die richtige Lösung ist nicht immer, „einen Test für `priority == 2` zu schreiben“. Dieses Verhalten könnte selbst der Fehler sein.<sup>[[1]](#references)</sup>

Sichererer Ablauf:
- Nutze überlebende Mutanten, um unklare Anforderungen zu erkennen
- Überprüfe das erwartete Verhalten anhand von Spezifikationen, Protokolldokumentation oder durch Reviewer
- Übertrage das Verhalten erst dann als Test oder Invariante

Andernfalls riskierst du, Implementierungszufälle in der Testsuite festzuschreiben und falsche Sicherheit zu gewinnen.

## Praktische Checkliste

- Führe eine gezielte Kampagne aus:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Bevorzuge, sofern verfügbar, syntaxbewusste Mutatoren (AST/Tree-sitter) gegenüber Mutationen, die nur auf Regex basieren.
- Werte überlebende Mutanten aus und schreibe Tests oder Invarianten, die bei dem mutierten Verhalten fehlschlagen würden.
- Prüfe Kontostände, Supply, Berechtigungen und Events.
- Füge Grenzfalltests hinzu (`==`, Überläufe/Unterläufe, Nulladresse, Nullbetrag, leere Arrays).
- Ersetze unrealistische Mocks; simuliere Fehlerszenarien.
- Speichere Ergebnisse dauerhaft, sofern das Tool dies unterstützt, und filtere nicht erkannte Mutanten vor der Auswertung heraus.
- Nutze Zwei-Phasen-Kampagnen oder Kampagnen pro Ziel, um die Laufzeit überschaubar zu halten.
- Wiederhole den Vorgang, bis alle Mutanten beseitigt oder mit Kommentaren und Begründung gerechtfertigt sind.

## References

- [1] [Mutationstests für das agentische Zeitalter](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Nutze Mutationstests, um Bugs zu finden, die deine Tests nicht erkennen (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Sicherheitsüberprüfung (Anhang C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentation zum Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
