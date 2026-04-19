# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" przez systematyczne wprowadzanie małych zmian (mutants) do kodu kontraktu i ponowne uruchamianie zestawu testów. Jeśli test nie przejdzie, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przeżywa, ujawniając martwy punkt, którego line/branch coverage nie potrafi wykryć.

Kluczowa idea: Coverage pokazuje, że kod został wykonany; mutation testing pokazuje, czy zachowanie jest faktycznie asercjonowane.

## Why coverage can deceive

Rozważmy ten prosty check progowy:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają tylko wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/branch, a jednocześnie nie asercować granicy równości (==). Refactor do `deposit >= 2 ether` nadal przejdzie takie testy, cicho psując logikę protokołu.

Mutation testing wykrywa tę lukę, mutując warunek i sprawdzając, czy testy zawodzą.

W przypadku smart contracts, przetrwałe mutanty często wskazują na brakujące checki wokół:
- Authorization i granic ról
- Invariants księgowe/przenoszenia wartości
- Warunki revert i ścieżki błędu
- Warunki brzegowe (`==`, wartości zero, puste tablice, wartości max/min)

## Mutation operators o najwyższym sygnale bezpieczeństwa

Przydatne klasy mutacji do audytu contracts:
- **High severity**: zastąpienie statements przez `revert()` w celu ujawnienia niewykonanych ścieżek
- **Medium severity**: zakomentowanie linii / usunięcie logiki, aby ujawnić niezweryfikowane side effects
- **Low severity**: subtelne podmiany operatorów lub stałych, takie jak `>=` -> `>` albo `+` -> `-`
- Inne częste edycje: zastąpienie przypisań, boolean flips, negacja warunków oraz zmiany typów

Praktyczny cel: zabić wszystkie znaczące mutanty i jasno uzasadnić te, które przetrwały, a są nieistotne albo semantycznie równoważne.

## Dlaczego mutation aware na poziomie składni jest lepsze niż regex

Starsze silniki mutacji opierały się na regex albo przeróbkach opartych o linie. To działa, ale ma ważne ograniczenia:
- Wielolinijkowe statements trudno bezpiecznie mutować
- Struktura języka nie jest rozumiana, więc comments/tokens mogą być źle targetowane
- Generowanie każdej możliwej wariacji na słabej linii marnuje ogromne ilości runtime

Narzędzia oparte o AST lub Tree-sitter poprawiają to, targetując zorganizowane nodes zamiast surowych linii:
- **slither-mutate** używa Solidity AST Slither
- **mewt** używa Tree-sitter jako language-agnostic core
- **MuTON** bazuje na `mewt` i dodaje first-class support dla języków TON, takich jak FunC, Tolk i Tact

To sprawia, że konstrukcje wielolinijkowe i mutacje na poziomie expression są znacznie bardziej niezawodne niż podejścia oparte wyłącznie na regex.

## Uruchamianie mutation testing z slither-mutate

Wymagania: Slither v0.10.2+.

- Wylistuj opcje i mutatory:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (zapisz wyniki i zachowaj pełny log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zastąp `--test-cmd` tym, jak uruchamiasz testy (np. `npx hardhat test`, `npm test`).

Artefakty są domyślnie przechowywane w `./mutation_campaign`. Niezłapane (surviving) mutanty są tam kopiowane do analizy.

### Understanding the output

Wiersze raportu wyglądają tak:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag w nawiasach to alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły mimo zmienionego zachowania → brak asercji.

## Reducing runtime: priorytetyzuj mutacje o największym wpływie

Mutation campaigns mogą trwać godziny albo dni. Wskazówki, jak zmniejszyć koszt:
- Scope: Zacznij tylko od krytycznych contract/directories, potem rozszerzaj.
- Priorytetyzuj mutatory: Jeśli mutator wysokiego priorytetu na linii przetrwa (np. `revert()` albo comment-out), pomiń warianty niższego priorytetu dla tej linii.
- Używaj kampanii dwufazowych: najpierw uruchom skupione/szybkie testy, potem ponownie testuj tylko uncaught mutants pełnym zestawem.
- Mapuj mutation targets na konkretne test commands, gdy to możliwe (np. auth code -> auth tests).
- Ogranicz kampanie do mutants o wysokiej/średniej severity, gdy brakuje czasu.
- Równoleglij testy, jeśli runner na to pozwala; cache dependencies/builds.
- Fail-fast: zatrzymaj się wcześnie, gdy zmiana wyraźnie pokazuje lukę w asercji.

Matematyka runtime jest brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, więc projekt kampanii ma takie samo znaczenie jak sam mutator.

## Persistent campaigns i triage na dużą skalę

Słabością starszych workflow jest wrzucanie wyników tylko do `stdout`. Przy długich kampaniach utrudnia to pause/resume, filtrowanie i review.

`mewt`/`MuTON` poprawiają to, przechowując mutants i wyniki w kampaniach opartych na SQLite. Korzyści:
- Pause i resume długich uruchomień bez tracenia postępu
- Filtrowanie tylko uncaught mutants w konkretnym pliku lub klasie mutacji
- Eksport/translate wyników do SARIF dla narzędzi review
- Dostarczanie AI-assisted triage mniejszych, przefiltrowanych zestawów wyników zamiast surowych terminal logs

Persistent results są szczególnie przydatne, gdy mutation testing staje się częścią pipeline audytu zamiast jednorazowego manual review.

## Workflow triage dla surviving mutants

1) Zbadaj zmienioną linię i zachowanie.
- Odtwórz lokalnie, aplikując zmienioną linię i uruchamiając focused test.

2) Wzmocnij testy tak, aby asercje dotyczyły stanu, a nie tylko wartości zwracanych.
- Dodaj sprawdzenia granic równości (np. test threshold `==`).
- Aseruj post-conditions: balances, total supply, skutki authorization i emitowane events.

3) Zastąp zbyt permissive mocks bardziej realistycznym zachowaniem.
- Upewnij się, że mocks wymuszają transfers, failure paths i event emissions, które występują on-chain.

4) Dodaj invariants do fuzz tests.
- Np. conservation of value, nieujemne balances, authorization invariants, monotonic supply tam, gdzie ma to zastosowanie.

5) Oddziel true positives od semantic no-ops.
- Przykład: `x > 0` -> `x != 0` jest bezsensowne, gdy `x` jest unsigned.

6) Uruchom kampanię ponownie, aż survivors zostaną zabite albo wyraźnie uzasadnione.

## Case study: ujawnianie brakujących state assertions (Arkis protocol)

Mutation campaign podczas audytu Arkis DeFi protocol ujawniła survivors takie jak:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Komentarz zakomentowujący przypisanie nie przerwał testów, co dowodzi braku asercji post-state. Przyczyna główna: kod ufał kontrolowanemu przez użytkownika `_cmd.value` zamiast weryfikować rzeczywiste transfery tokenów. Atakujący mógłby rozjechać oczekiwane vs. rzeczywiste transfery, aby wyprowadzić środki. Wniosek: wysokie ryzyko naruszenia wypłacalności protokołu.

Wskazówka: Traktuj survivory wpływające na transfery wartości, accounting lub access control jako wysokiego ryzyka, dopóki nie zostaną zabite.

## Nie generuj ślepo testów, aby zabić każdy mutant

Mutation-driven generation testów może przynieść odwrotny skutek, jeśli obecna implementacja jest błędna. Przykład: mutacja `priority >= 2` na `priority > 2` zmienia zachowanie, ale właściwa poprawka nie zawsze polega na "napisaniu testu dla `priority == 2`". To zachowanie samo może być bugiem.

Bezpieczniejszy workflow:
- Używaj surviving mutants do identyfikacji niejednoznacznych wymagań
- Waliduj oczekiwane zachowanie na podstawie specs, dokumentacji protokołu lub recenzentów
- Dopiero potem koduj to zachowanie jako test/invariant

W przeciwnym razie ryzykujesz zakodowanie przypadkowych cech implementacji na stałe w zestawie testów i zyskanie fałszywej pewności.

## Praktyczna checklista

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Preferuj mutatory świadome składniowo (AST/Tree-sitter) zamiast mutacji wyłącznie regex, gdy są dostępne.
- Przeanalizuj survivors i napisz testy/invarianty, które zawiodą przy zmutowanym zachowaniu.
- Aseruj balances, supply, authorizations i events.
- Dodaj testy graniczne (`==`, overflows/underflows, zero-address, zero-amount, puste arrays).
- Zastąp nierealistyczne mocks; symuluj failure modes.
- Zachowuj wyniki, jeśli tooling to wspiera, i filtruj uncaught mutants przed triage.
- Używaj kampanii dwuetapowych lub per-target, aby utrzymać runtime na rozsądnym poziomie.
- Iteruj, aż wszystkie mutants zostaną zabite lub uzasadnione komentarzami i rationale.

## References

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
