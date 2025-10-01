# Mutation Testing für Solidity mit Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation Testing "tests your tests", indem es systematisch kleine Änderungen (Mutanten) in deinen Solidity-Code einführt und deine Test-Suite erneut ausführt. Wenn ein Test fehlschlägt, wird der Mutant getötet. Wenn die Tests weiterhin bestehen, überlebt der Mutant und offenbart eine Blindstelle in deiner Test-Suite, die line/branch coverage nicht erkennen kann.

Key idea: Coverage zeigt, dass Code ausgeführt wurde; Mutation Testing zeigt, ob das Verhalten tatsächlich mit Assertions abgesichert wird.

## Warum Coverage in die Irre führen kann

Betrachten wir diese einfache Schwellenwertprüfung:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit-Tests, die nur einen Wert unterhalb und einen Wert oberhalb der Schwelle prüfen, können 100% Zeilen-/Zweigabdeckung erreichen, während sie es versäumen, die Gleichheitsgrenze (==) zu überprüfen. Ein Refactor zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen und dabei stillschweigend die Protokolllogik brechen.

Mutationstests machen diese Lücke sichtbar, indem sie die Bedingung verändern und verifizieren, dass Ihre Tests fehlschlagen.

## Gängige Solidity-Mutationsoperatoren

Slither’s Mutations-Engine wendet viele kleine, die Semantik ändernde Änderungen an, wie zum Beispiel:
- Operatorersetzung: `+` ↔ `-`, `*` ↔ `/`, etc.
- Zuweisungsersetzung: `+=` → `=`, `-=` → `=`
- Konstantenersetzung: nicht-null → `0`, `true` ↔ `false`
- Negation/Ersetzung von Bedingungen innerhalb von `if`/Schleifen
- Ganze Zeilen auskommentieren (CR: Comment Replacement)
- Eine Zeile durch `revert()` ersetzen
- Datentyp-Austausch: z. B. `int128` → `int64`

Ziel: 100% der erzeugten Mutanten eliminieren oder Überlebende mit klarer Begründung rechtfertigen.

## Mutationstests mit slither-mutate ausführen

Voraussetzungen: Slither v0.10.2+.

- Optionen und Mutatoren auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Protokoll führen):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artefakte und Berichte werden standardmäßig in `./mutation_campaign` gespeichert. Nicht gefangene (überlebende) Mutanten werden dorthin zur Prüfung kopiert.

### Ausgabe verstehen

Die Report-Zeilen sehen folgendermaßen aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in eckigen Klammern ist das Mutator-Alias (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass Tests unter dem mutierten Verhalten bestanden haben → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutanten priorisieren

Mutationskampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:
- Umfang: Beginne nur mit kritischen Contracts/Verzeichnissen und erweitere dann.
- Mutatoren priorisieren: Wenn ein hochprioritärer Mutant auf einer Zeile überlebt (z. B. die gesamte Zeile auskommentiert), kannst du niedrigprioritäre Varianten für diese Zeile überspringen.
- Tests parallelisieren, wenn dein Runner das erlaubt; Abhängigkeiten/Builds cachen.
- Fail-fast: früh abbrechen, wenn eine Änderung eindeutig eine Assertion-Lücke zeigt.

## Triage-Workflow für überlebende Mutanten

1) Untersuche die mutierte Zeile und das Verhalten.
- Lokal reproduzieren, indem du die mutierte Zeile anwendest und einen fokussierten Test ausführst.

2) Stärke Tests, um Zustand zu prüfen, nicht nur Rückgabewerte.
- Füge Gleichheits-/Grenzprüfungen hinzu (z. B. Test threshold `==`).
- Prüfe Post-Conditions: Salden, Gesamtversorgung, Autorisierungseffekte und emittierte Events.

3) Ersetze zu permissive Mocks durch realistisches Verhalten.
- Sorge dafür, dass Mocks Transfers, Fehlerpfade und Event-Emissionen erzwingen, die on-chain auftreten.

4) Füge Invarianten für Fuzz-Tests hinzu.
- Z. B. Werterhaltung, nicht-negative Salden, Autorisierungsinvarianten, monotone Gesamtversorgung, falls zutreffend.

5) Führe slither-mutate erneut aus, bis Überlebende eliminiert oder ausdrücklich gerechtfertigt sind.

## Fallstudie: Aufdecken fehlender Zustandsprüfungen (Arkis protocol)

Eine Mutationskampagne während eines Audits des Arkis DeFi-Protokolls brachte Überlebende wie zutage:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Durch Auskommentieren der Zuweisung brachen die Tests nicht, was fehlende Post-State-Assertions beweist. Ursache: Der Code vertraute auf ein vom Nutzer kontrolliertes `_cmd.value` statt tatsächliche Token-Transfers zu validieren. Ein Angreifer könnte erwartete und tatsächliche Transfers desynchronisieren, um Gelder abzuziehen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.

Leitlinie: Behandle Survivors, die Werttransfers, Buchhaltung oder Zugriffskontrolle beeinflussen, als hohes Risiko, bis sie killed sind.

## Praktische Checkliste

- Führe eine gezielte Kampagne durch:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage Survivors und schreibe Tests/Invarianten, die unter dem mutierten Verhalten fehlschlagen würden.
- Prüfe Salden, Supply, Autorisierungen und Events.
- Füge Grenztests hinzu (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Ersetze unrealistische Mocks; simuliere Fehlermodi.
- Iteriere, bis alle Mutanten getötet oder mit Kommentaren und Begründung gerechtfertigt sind.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
