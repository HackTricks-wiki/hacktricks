# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" przez systematyczne wprowadzanie małych zmian (mutantów) w kodzie Solidity i ponowne uruchamianie zestawu testów. Jeśli test się nie powiedzie, mutant zostaje zabity. Jeśli testy nadal przejdą, mutant przetrwa, ujawniając ślepy punkt w Twoim zestawie testów, którego pokrycie linii/gałęzi nie wykryje.

Key idea: Coverage shows code was executed; mutation testing shows whether behavior is actually asserted.

## Dlaczego pokrycie może wprowadzać w błąd

Rozważ ten prosty warunek progowy:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają tylko wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, jednocześnie nie asercjonując granicy równości (==). Refaktoryzacja do `deposit >= 2 ether` nadal zaliczyłaby takie testy, cicho łamiąc logikę protokołu.

Mutation testing ujawnia tę lukę przez zmodyfikowanie warunku i weryfikację, że Twoje testy nie przechodzą.

## Common Solidity mutation operators

Slither’s mutation engine applies many small, semantics-changing edits, such as:
- Zamiana operatorów: `+` ↔ `-`, `*` ↔ `/`, itd.
- Zamiana przypisań: `+=` → `=`, `-=` → `=`
- Zamiana stałych: wartość różna od zera → `0`, `true` ↔ `false`
- Negacja/zamiana warunku wewnątrz `if`/pętli
- Zakomentowanie całych linii (CR: Comment Replacement)
- Zamiana linii na `revert()`
- Zamiany typów danych: np. `int128` → `int64`

Cel: Zabić 100% wygenerowanych mutantów, albo uzasadnić przeżywających jasnym rozumowaniem.

## Running mutation testing with slither-mutate

Requirements: Slither v0.10.2+.

- Wyświetl opcje i mutatory:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry — przykład (przechwyć wyniki i zachowaj pełny log):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zamień `--test-cmd` na sposób uruchamiania testów (np. `npx hardhat test`, `npm test`).

Artefakty i raporty są domyślnie zapisywane w `./mutation_campaign`. Nieuchwycone (przetrwałe) mutanty są tam kopiowane do inspekcji.

### Understanding the output

Wiersze raportu wyglądają tak:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag w nawiasach to alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły przy zmienionym zachowaniu → brak asercji.

## Redukcja czasu działania: priorytetyzuj mutacje o największym wpływie

Kampanie mutacyjne mogą trwać godziny lub dni. Wskazówki, jak zmniejszyć koszty:
- Scope: Zacznij tylko od krytycznych kontraktów/katalogów, potem rozszerz.
- Priorytetyzuj mutatory: jeśli mutacja o wysokim priorytecie na danej linii przetrwa (np. cała linia skomentowana), możesz pominąć warianty o niższym priorytecie dla tej linii.
- Równoległe uruchamianie testów, jeśli twój runner na to pozwala; cache'uj zależności/kompilacje.
- Fail-fast: zatrzymaj wcześnie, gdy zmiana wyraźnie pokazuje lukę w asercjach.

## Procedura triage dla przetrwałych mutantów

1) Zbadaj zmodyfikowaną linię i zachowanie.
- Odtwórz lokalnie, wprowadzając zmienioną linię i uruchamiając ukierunkowany test.

2) Wzmocnij testy tak, aby asercjonowały stan, nie tylko wartości zwracane.
- Dodaj testy graniczne równości (np. sprawdzenie progu `==`).
- Asercjonuj warunki post-funkcyjne: salda, całkowita podaż, efekty autoryzacji oraz emitowane zdarzenia.

3) Zastąp zbyt pobłażliwe mocki realistycznym zachowaniem.
- Upewnij się, że mocki wymuszają transfery, ścieżki błędów oraz emisję zdarzeń, które występują on-chain.

4) Dodaj inwarianty do fuzz testów.
- Np. zachowanie wartości, salda nieujemne, inwarianty autoryzacji, monotoniczna podaż tam, gdzie ma zastosowanie.

5) Uruchom ponownie slither-mutate, aż przetrwałe mutanty zostaną wyeliminowane lub wyraźnie uzasadnione.

## Studium przypadku: ujawnienie brakujących asercji stanu (Arkis protocol)

Kampania mutacyjna podczas audytu Arkis DeFi protocol ujawniła przetrwałe mutanty takie jak:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Zakomentowanie przypisania nie złamało testów, co dowodzi braku asercji stanu po wykonaniu. Przyczyna źródłowa: kod ufał kontrolowanej przez użytkownika `_cmd.value` zamiast weryfikować rzeczywiste transfery tokenów. Atakujący mógłby wprowadzić rozbieżność między oczekiwanymi a rzeczywistymi transferami, aby wypompować środki. Skutek: wysokie ryzyko zagrażające wypłacalności protokołu.

Guidance: Traktuj przetrwałe mutacje, które wpływają na transfery wartości, rozliczenia lub kontrolę dostępu, jako wysokiego ryzyka, dopóki nie zostaną usunięte.

## Praktyczna lista kontrolna

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Przejrzyj przetrwałe mutacje i napisz testy/inwarianty, które zawiodłyby przy zmienionym zachowaniu.
- Sprawdź salda, podaż, autoryzacje i zdarzenia.
- Dodaj testy brzegowe (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Zamień nierealistyczne mocki; symuluj scenariusze awarii.
- Iteruj, aż wszystkie mutanty zostaną zabite lub uzasadnione komentarzami i racjonalizacją.

## Odniesienia

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
