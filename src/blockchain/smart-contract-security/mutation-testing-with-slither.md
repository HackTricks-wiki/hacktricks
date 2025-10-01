# Mutation Testing für Solidity mit Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests", indem es systematisch kleine Änderungen (mutants) in deinen Solidity-Code einführt und deine Test-Suite erneut ausführt. Wenn ein Test fehlschlägt, wird der mutant getötet. Bestehen die Tests weiterhin, überlebt der mutant und offenbart eine Schwachstelle in deiner Test-Suite, die Zeilen- oder Zweigabdeckung nicht erkennen kann.

Kernidee: Coverage zeigt, dass Code ausgeführt wurde; mutation testing zeigt, ob Verhalten tatsächlich abgesichert/geprüft wird.

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
Unit tests that only check a value below and a value above the threshold can reach 100% line/branch coverage while failing to assert the equality boundary (==). A refactor to `deposit >= 2 ether` would still pass such tests, silently breaking protocol logic.

Mutation testing exposes this gap by mutating the condition and verifying your tests fail.

## Häufige Solidity-Mutationsoperatoren

Slither’s mutation engine wendet viele kleine, semantikverändernde Änderungen an, wie zum Beispiel:
- Operator-Ersetzung: `+` ↔ `-`, `*` ↔ `/`, etc.
- Zuweisungsersetzung: `+=` → `=`, `-=` → `=`
- Konstantenersetzung: nicht-null → `0`, `true` ↔ `false`
- Negation/Ersetzung von Bedingungen innerhalb von `if`/Schleifen
- Ganze Zeilen auskommentieren (CR: Comment Replacement)
- Ersetze eine Zeile durch `revert()`
- Datentyp-Tausch: z. B. `int128` → `int64`

Ziel: 100% der erzeugten Mutanten eliminieren, oder Überlebende mit schlüssiger Begründung rechtfertigen.

## Mutation-Testing mit slither-mutate ausführen

Voraussetzungen: Slither v0.10.2+.

- Optionen und Mutatoren auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges log führen):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artefakte und Berichte werden standardmäßig in `./mutation_campaign` gespeichert. Nicht gefangene (überlebende) Mutanten werden dort zur Inspektion kopiert.

### Ausgabe verstehen

Berichtszeilen sehen so aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Das Tag in eckigen Klammern ist das Mutator-Alias (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass Tests unter dem mutierten Verhalten bestanden haben → fehlende Assertion.

## Laufzeit reduzieren: Mutanten mit großer Wirkung priorisieren

Mutationskampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduzierung:
- Umfang: Beginne nur mit kritischen Contracts/Verzeichnissen und erweitere dann.
- Priorisiere Mutatoren: Wenn ein hochprioritärer Mutant in einer Zeile überlebt (z. B. ganze Zeile auskommentiert), kannst du niedrigere Prioritätsvarianten für diese Zeile überspringen.
- Parallelisiere Tests, wenn dein Runner das erlaubt; cache Abhängigkeiten/Builds.
- Fail-fast: brich früh ab, wenn eine Änderung klar eine fehlende Assertion demonstriert.

## Triage-Workflow für überlebende Mutanten

1) Untersuche die mutierte Zeile und das Verhalten.
- Reproduziere lokal, indem du die mutierte Zeile anwendest und einen fokussierten Test ausführst.

2) Stärke Tests, um den Zustand zu prüfen, nicht nur Rückgabewerte.
- Füge Gleichheits-/Grenzprüfungen hinzu (z. B. teste threshold `==`).
- Prüfe Post-Conditions: Salden, Gesamtangebot, Autorisierungseffekte und emittierte Events.

3) Ersetze zu permissive Mocks durch realistisches Verhalten.
- Stelle sicher, dass Mocks Transfers, Fehlerpfade und Event-Emissionen erzwingen, wie sie on-chain auftreten.

4) Füge Invarianten für Fuzz-Tests hinzu.
- Z. B. Erhaltung des Wertes, nicht-negative Salden, Autorisierungsinvarianten, monotones Supply wo anwendbar.

5) Führe slither-mutate erneut aus, bis Überlebende getötet oder explizit gerechtfertigt sind.

## Fallstudie: Aufdecken fehlender Zustandsassertionen (Arkis protocol)

Eine Mutationskampagne während eines Audits des Arkis DeFi-Protokolls förderte Überlebende zutage wie:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung brach die Tests nicht, was fehlende Post-State-Assertions bewies. Ursache: Der Code vertraute auf ein vom Benutzer kontrolliertes `_cmd.value` anstatt tatsächliche Token-Transfers zu validieren. Ein Angreifer konnte erwartete und tatsächliche Transfers desynchronisieren, um Mittel abzuziehen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.

Guidance: Behandle survivors, die Werttransfers, Buchführung oder Zugriffskontrolle beeinflussen, als hohes Risiko, bis sie getötet sind.

## Praktische Checkliste

- Führe eine gezielte Kampagne durch:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage survivors und schreibe Tests/Invarianten, die unter dem mutierten Verhalten fehlschlagen würden.
- Überprüfe Salden, Supply, Authorisierungen und Events.
- Füge Grenzfall-Tests hinzu (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Ersetze unrealistische Mocks; simuliere Fehlermodi.
- Iteriere, bis alle Mutanten getötet oder mit Kommentaren und Begründung gerechtfertigt sind.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
