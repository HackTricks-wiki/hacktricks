# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

Mutation testing "tests your tests", indem es systematisch kleine Änderungen (Mutanten) in deinen Solidity-Code einführt und deine Test-Suite erneut ausführt. Wenn ein Test fehlschlägt, wird der Mutant getötet. Wenn die Tests weiterhin bestehen, überlebt der Mutant und offenbart eine Blindstelle in deiner Test-Suite, die line/branch coverage nicht erkennen kann.

Kernaussage: Coverage zeigt, dass Code ausgeführt wurde; mutation testing zeigt, ob das Verhalten tatsächlich geprüft wird.

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
Unit-Tests, die nur einen Wert unterhalb und einen Wert oberhalb des Schwellenwerts prüfen, können 100% Zeilen-/Branch-Abdeckung erreichen, während sie es versäumen, die Gleichheitsgrenze (==) zu prüfen. Eine Änderung zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen und stillschweigend die Protokoll-Logik brechen.

Mutation-Tests decken diese Lücke auf, indem sie die Bedingung verändern und überprüfen, dass deine Tests fehlschlagen.

## Gängige Solidity-Mutationsoperatoren

Slither’s Mutation-Engine wendet viele kleine, die Semantik ändernde Bearbeitungen an, wie z. B.:
- Operator-Ersetzung: `+` ↔ `-`, `*` ↔ `/`, etc.
- Zuweisungsersetzung: `+=` → `=`, `-=` → `=`
- Konstantenersetzung: nicht-null → `0`, `true` ↔ `false`
- Negation/Ersetzung von Bedingungen innerhalb von `if`/Schleifen
- Ganze Zeilen auskommentieren (CR: Kommentarersetzung)
- Ersetze eine Zeile durch `revert()`
- Datentyp-Tausch: z. B. `int128` → `int64`

Ziel: 100% der generierten Mutanten eliminieren oder verbliebene mit einer klaren Begründung rechtfertigen.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- List options and mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (Ergebnisse erfassen und ein vollständiges Protokoll führen):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artefakte und Berichte werden standardmäßig in `./mutation_campaign` gespeichert. Nicht gefangene (überlebende) Mutanten werden dort zur Inspektion kopiert.

### Ausgabe verstehen

Berichtszeilen sehen folgendermaßen aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Der Tag in eckigen Klammern ist das Mutator-Alias (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass Tests unter dem mutierten Verhalten bestanden haben → fehlende Assertion.

## Laufzeit reduzieren: priorisiere wirkungsvolle Mutanten

Mutationskampagnen können Stunden oder Tage dauern. Tipps zur Kostenreduktion:
- Umfang: Starte nur mit kritischen Contracts/Verzeichnissen und erweitere dann.
- Mutatoren priorisieren: Wenn ein hochprioritärer Mutant in einer Zeile überlebt (z. B. ganze Zeile auskommentiert), kannst du niedrigere Prioritätsvarianten für diese Zeile überspringen.
- Parallelisiere Tests, wenn dein Runner das erlaubt; cache Abhängigkeiten/Builds.
- Fail-fast: brich früh ab, wenn eine Änderung klar eine Assertion-Lücke zeigt.

## Triage-Workflow für überlebende Mutanten

1) Untersuche die mutierte Zeile und das Verhalten.
- Reproduziere lokal, indem du die mutierte Zeile anwendest und einen fokussierten Test ausführst.

2) Stärke Tests, indem du den Zustand überprüfst, nicht nur Rückgabewerte.
- Füge Gleichheits-/Grenzwertprüfungen hinzu (z. B. Schwellenwert `==` testen).
- Überprüfe Post-Conditions: Kontostände, total supply, Autorisierungswirkungen und emittierte Events.

3) Ersetze zu permissive Mocks durch realistisches Verhalten.
- Stelle sicher, dass Mocks Transfers, Fehlerpfade und Event-Emissionen durchsetzen, wie sie on-chain auftreten.

4) Füge Invarianten für Fuzz-Tests hinzu.
- Z. B. Erhaltung des Werts, nicht-negative Kontostände, Autorisierungsinvarianten, monotone Gesamtversorgung, falls anwendbar.

5) Führe slither-mutate erneut aus, bis Überlebende beseitigt oder explizit gerechtfertigt sind.

## Fallstudie: Aufdecken fehlender Status-Assertions (Arkis-Protokoll)

Eine Mutationskampagne während eines Audits des Arkis DeFi-Protokolls förderte Überlebende zutage wie:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Das Auskommentieren der Zuweisung brach die Tests nicht, was fehlende Assertions für den Nachzustand belegte. Ursache: Der Code vertraute einem vom Benutzer kontrollierten `_cmd.value`, anstatt die tatsächlichen Token-Transfers zu validieren. Ein Angreifer könnte erwartete und tatsächliche Transfers desynchronisieren, um Mittel abzuziehen. Ergebnis: hohes Risiko für die Solvenz des Protokolls.

Guidance: Behandle Überlebende, die Werttransfers, Buchführung oder Zugriffskontrolle betreffen, als hohes Risiko, bis sie eliminiert sind.

## Praktische Checkliste

- Führe eine gezielte Kampagne durch:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triage die Überlebenden und schreibe Tests/Invarianten, die unter dem mutierten Verhalten fehlschlagen würden.
- Prüfe Salden, Gesamtangebot, Autorisierungen und Events.
- Füge Grenzfall-Tests hinzu (`==`, Überläufe/Unterläufe, Null-Adresse, Null-Betrag, leere Arrays).
- Ersetze unrealistische Mocks; simuliere Ausfallmodi.
- Iteriere, bis alle Mutanten eliminiert oder mit Kommentaren und Begründung gerechtfertigt sind.

## Referenzen

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
