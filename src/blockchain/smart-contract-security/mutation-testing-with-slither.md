# Mutation Testing für Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testet deine Tests“, indem es systematisch kleine Änderungen (mutants) in Contract-Code einführt und die Test-Suite erneut ausführt. Schlägt ein Test fehl, ist der mutant erledigt. Wenn die Tests trotzdem bestehen, überlebt der mutant und deckt eine blinde Stelle auf, die Line-/Branch-Coverage nicht erkennen kann.

Kernaussage: Coverage zeigt, dass Code ausgeführt wurde; mutation testing zeigt, ob Verhalten tatsächlich geprüft wird.

## Warum Coverage täuschen kann

Betrachte diesen einfachen Threshold-Check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Unit-Tests, die nur einen Wert unterhalb und einen Wert oberhalb der Schwelle prüfen, können 100% line/branch coverage erreichen, obwohl sie es versäumen, die Gleichheitsgrenze (==) zu verifizieren. Ein Refactor zu `deposit >= 2 ether` würde solche Tests weiterhin bestehen, würde aber die Protokoll-Logik unbemerkt beschädigen.

Mutation testing deckt diese Lücke auf, indem es die Bedingung mutiert und überprüft, ob Tests fehlschlagen.

Für smart contracts lassen sich überlebende Mutanten häufig auf fehlende Prüfungen in diesen Bereichen zurückführen:
- Authorization- und Rollen-Grenzen
- Accounting-/value-transfer-Invarianten
- Revert-Bedingungen und Failure Paths
- Grenzbedingungen (`==`, Nullwerte, leere Arrays, Max-/Min-Werte)

## Mutation operators mit dem höchsten Security-Signal

Nützliche Mutationsklassen für Contract-Auditing:
- **Hohe Severity**: Statements durch `revert()` ersetzen, um nicht ausgeführte Pfade sichtbar zu machen
- **Mittlere Severity**: Zeilen auskommentieren / Logik entfernen, um unüberprüfte Side Effects offenzulegen
- **Niedrige Severity**: Subtile Operator- oder Konstanten-Tausche wie `>=` -> `>` oder `+` -> `-`
- Weitere häufige Änderungen: Ersetzung von Zuweisungen, Boolean-Flips, Negation von Bedingungen und Typänderungen

Praktisches Ziel: alle aussagekräftigen Mutanten töten und Überlebende, die irrelevant oder semantisch äquivalent sind, ausdrücklich begründen.

## Warum syntax-aware mutation besser ist als regex

Ältere Mutation Engines verließen sich auf regex oder line-orientierte Rewrite-Ansätze. Das funktioniert, hat aber wichtige Grenzen:
- Mehrzeilige Statements sind schwer sicher zu mutieren
- Die Sprachstruktur wird nicht verstanden, daher können Kommentare/Tokens schlecht getroffen werden
- Jede mögliche Variante auf einer schwachen Zeile zu erzeugen verschwendet enorme Laufzeit

AST- oder Tree-sitter-basierte Tools verbessern das, indem sie strukturierte Knoten statt rohe Zeilen anvisieren:
- **slither-mutate** nutzt Slithers Solidity AST
- **mewt** nutzt Tree-sitter als sprachunabhängigen Kern
- **MuTON** baut auf `mewt` auf und ergänzt erstklassige Unterstützung für TON-Sprachen wie FunC, Tolk und Tact

Dadurch werden mehrzeilige Konstrukte und Mutationen auf Expression-Ebene deutlich zuverlässiger als bei reinen regex-Ansätzen.

## Mutation testing mit slither-mutate ausführen

Requirements: Slither v0.10.2+.

- Optionen und mutators auflisten:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry-Beispiel (Ergebnisse erfassen und ein vollständiges Log beibehalten):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Wenn du Foundry nicht verwendest, ersetze `--test-cmd` durch den Befehl, mit dem du Tests ausführst (z. B. `npx hardhat test`, `npm test`).

Artefakte werden standardmäßig in `./mutation_campaign` gespeichert. Nicht abgefangene (überlebende) Mutanten werden zur Inspektion dorthin kopiert.

### Understanding the output

Report-Zeilen sehen so aus:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Der Tag in eckigen Klammern ist der Mutator-Alias (z. B. `CR` = Comment Replacement).
- `UNCAUGHT` bedeutet, dass die Tests unter dem mutierten Verhalten bestanden haben → fehlende Assertion.

## Laufzeit reduzieren: wirkungsvolle Mutants priorisieren

Mutation-Kampagnen können Stunden oder Tage dauern. Tipps zur Kostensenkung:
- Scope: Zuerst nur mit kritischen Contracts/Verzeichnissen beginnen, dann erweitern.
- Mutators priorisieren: Wenn ein High-Priority-Mutant in einer Zeile überlebt (z. B. `revert()` oder Kommentar-Auskommentierung), niedrigere Prioritätsvarianten für diese Zeile überspringen.
- Zwei-Phasen-Kampagnen verwenden: zuerst fokussierte/schnelle Tests ausführen, dann nur uncaught Mutants mit der vollständigen Suite erneut testen.
- Mutation Targets nach Möglichkeit bestimmten Test-Commands zuordnen (z. B. auth code -> auth tests).
- Kampagnen auf High-/Medium-Severity-Mutants beschränken, wenn die Zeit knapp ist.
- Tests parallelisieren, wenn dein Runner das erlaubt; Dependencies/Builds cachen.
- Fail-fast: früh stoppen, wenn eine Änderung klar eine Assertion-Lücke zeigt.

Die Laufzeit-Mathematik ist brutal: `1000 mutants x 5-minute tests ~= 83 hours`, daher ist das Kampagnen-Design genauso wichtig wie der Mutator selbst.

## Persistente Kampagnen und Triage in großem Maßstab

Eine Schwäche älterer Workflows ist, Ergebnisse nur nach `stdout` zu dumpen. Bei langen Kampagnen erschwert das Pause/Resume, Filterung und Review.

`mewt`/`MuTON` verbessern das, indem sie Mutants und Ergebnisse in SQLite-gestützten Kampagnen speichern. Vorteile:
- Lange Läufe pausieren und fortsetzen, ohne Fortschritt zu verlieren
- Nur uncaught Mutants in einer bestimmten Datei oder Mutation-Klasse filtern
- Ergebnisse für Review-Tools nach SARIF exportieren/übersetzen
- AI-gestützte Triage mit kleineren, gefilterten Resultsets statt roher Terminal-Logs versorgen

Persistente Ergebnisse sind besonders nützlich, wenn Mutation Testing Teil einer Audit-Pipeline wird statt einer einmaligen manuellen Review.

## Triage-Workflow für überlebende Mutants

1) Die mutierte Zeile und das Verhalten prüfen.
- Lokal reproduzieren, indem du die mutierte Zeile anwendest und einen fokussierten Test ausführst.

2) Tests stärken, um State zu prüfen, nicht nur Rückgabewerte.
- Equality-Grenzfälle hinzufügen (z. B. Threshold `==` testen).
- Post-Conditions assertieren: Balances, total supply, Authorization-Effekte und emittierte Events.

3) Zu permissive Mocks durch realistisches Verhalten ersetzen.
- Sicherstellen, dass Mocks Transfers, Failure-Paths und Event-Emissions durchsetzen, die on-chain auftreten.

4) Invariants für Fuzz-Tests hinzufügen.
- Z. B. Werterhaltung, nicht-negative Balances, Authorization-Invariants, monotone Supply, wo anwendbar.

5) Echte Positives von semantischen No-Ops trennen.
- Beispiel: `x > 0` -> `x != 0` ist bedeutungslos, wenn `x` unsigned ist.

6) Die Kampagne erneut ausführen, bis Survivors gekillt oder explizit gerechtfertigt sind.

## Case study: fehlende State-Assertions aufdecken (Arkis protocol)

Eine Mutation-Kampagne während eines Audits des Arkis DeFi protocol brachte Survivors wie die folgenden ans Licht:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Commenting out the assignment didn’t break the tests, proving missing post-state assertions. Root cause: code trusted a user-controlled `_cmd.value` instead of validating actual token transfers. An attacker could desynchronize expected vs. actual transfers to drain funds. Result: high severity risk to protocol solvency.

Guidance: Behandle survivors that affect value transfers, accounting, or access control as high-risk until killed.

## Do not blindly generate tests to kill every mutant

Mutation-driven test generation can backfire if the current implementation is wrong. Example: mutating `priority >= 2` to `priority > 2` changes behavior, but the right fix is not always "write a test for `priority == 2`". That behavior may itself be the bug.

Safer workflow:
- Use surviving mutants to identify ambiguous requirements
- Validate expected behavior from specs, protocol docs, or reviewers
- Only then encode the behavior as a test/invariant

Otherwise, you risk hard-coding implementation accidents into the test suite and gaining false confidence.

## Practical checklist

- Run a targeted campaign:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefer syntax-aware mutators (AST/Tree-sitter) over regex-only mutation when available.
- Triage survivors and write tests/invariants that would fail under the mutated behavior.
- Assert balances, supply, authorizations, and events.
- Add boundary tests (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Replace unrealistic mocks; simulate failure modes.
- Persist results when the tooling supports it, and filter uncaught mutants before triage.
- Use two-phase or per-target campaigns to keep runtime manageable.
- Iterate until all mutants are killed or justified with comments and rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
