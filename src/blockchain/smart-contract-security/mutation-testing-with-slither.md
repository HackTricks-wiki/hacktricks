# Mutation Testing dla Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing „testuje twoje testy”, systematycznie wprowadzając małe zmiany (mutants) do kodu kontraktu i ponownie uruchamiając zestaw testów. Jeśli test zakończy się niepowodzeniem, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przetrwa, ujawniając ślepy punkt, którego nie można wykryć za pomocą coverage linii/gałęzi.

Kluczowa idea: Coverage pokazuje, że kod został wykonany; mutation testing pokazuje, czy zachowanie jest faktycznie asertywane.<sup>[[2]](#references)</sup>

## Dlaczego coverage może wprowadzać w błąd

Rozważmy to proste sprawdzenie progu:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Testy jednostkowe, które sprawdzają jedynie wartość poniżej i wartość powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, nie sprawdzając granicy równości (==). Refaktoryzacja do `deposit >= 2 ether` nadal przechodziłaby takie testy, po cichu psując logikę protokołu.<sup>[[2]](#references)</sup>

Mutation testing ujawnia tę lukę poprzez mutowanie warunku i weryfikację, czy testy kończą się niepowodzeniem.

W przypadku smart contracts przetrwałe mutanty często wskazują na brakujące kontrole dotyczące:
- Autoryzacji i granic ról
- Niezmienników księgowania/przekazywania wartości
- Warunków revert i ścieżek błędów
- Warunków brzegowych (`==`, wartości zerowe, puste tablice, wartości maksymalne/minimalne)

## Operatory mutacji o najwyższym znaczeniu dla bezpieczeństwa

Przydatne klasy mutacji podczas audytu kontraktów:<sup>[[1]](#references)[[2]](#references)</sup>
- **Wysoka ważność**: zastępowanie instrukcji przez `revert()` w celu ujawnienia niewykonywanych ścieżek
- **Średnia ważność**: komentowanie linii / usuwanie logiki w celu wykrycia niezweryfikowanych efektów ubocznych
- **Niska ważność**: subtelne zamiany operatorów lub stałych, takie jak `>=` -> `>` albo `+` -> `-`
- Inne typowe zmiany: zastępowanie przypisań, odwracanie wartości logicznych, negowanie warunków oraz zmiany typów

Praktyczny cel: zabić wszystkie istotne mutanty i wyraźnie uzasadnić przetrwanie mutantów nieistotnych lub semantycznie równoważnych.

## Dlaczego mutation testing uwzględniający składnię jest lepszy niż regex

Starsze silniki mutacji opierały się na regex lub przepisywaniu zorientowanym na linie. Działało to, ale miało istotne ograniczenia:<sup>[[1]](#references)</sup>
- Instrukcje wieloliniowe trudno bezpiecznie mutować
- Struktura języka nie jest rozumiana, więc komentarze/tokeny mogą być niewłaściwie wybierane
- Generowanie każdego możliwego wariantu na podstawie słabej linii marnuje duże ilości czasu działania

Narzędzia oparte na AST lub Tree-sitter ulepszają ten proces, wybierając ustrukturyzowane węzły zamiast surowych linii:<sup>[[1]](#references)</sup>
- **slither-mutate** używa AST Solidity z Slither
- **mewt** używa Tree-sitter jako niezależnego od języka rdzenia
- **MuTON** bazuje na `mewt` i dodaje natywną obsługę języków TON, takich jak FunC, Tolk i Tact

Dzięki temu konstrukcje wieloliniowe i mutacje na poziomie wyrażeń są znacznie bardziej niezawodne niż podejścia oparte wyłącznie na regex.

## Uruchamianie mutation testing za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wyświetl opcje i mutatory:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Przykład Foundry (przechwyć wyniki i zachowaj pełny log):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Jeśli nie używasz Foundry, zastąp `--test-cmd` poleceniem używanym do uruchamiania testów (np. `npx hardhat test`, `npm test`).

Artefakty są domyślnie przechowywane w `./mutation_campaign`. Niewykryte (przetrwałe) mutanty są tam kopiowane w celu ich analizy.<sup>[[5]](#references)</sup>

### Zrozumienie danych wyjściowych

Wiersze raportu wyglądają następująco:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- Tag w nawiasach to alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły przy zmienionym zachowaniu → brakująca asercja.

## Ograniczanie czasu wykonywania: priorytetyzacja istotnych mutantów

Kampanie mutacyjne mogą trwać godziny lub dni. Wskazówki dotyczące ograniczenia kosztów:<sup>[[1]](#references)[[2]](#references)</sup>
- Zakres: zacznij tylko od krytycznych kontraktów/katalogów, a następnie rozszerz zakres.
- Priorytetyzuj mutatory: jeśli mutant o wysokim priorytecie w danej linii przetrwa (np. `revert()` lub comment-out), pomiń warianty o niższym priorytecie dla tej linii.
- Używaj kampanii dwuetapowych: najpierw uruchom ukierunkowane/szybkie testy, a następnie ponownie przetestuj wyłącznie mutanty `UNCAUGHT` za pomocą pełnego zestawu testów.
- W miarę możliwości mapuj cele mutacji na konkretne polecenia testów (np. kod uwierzytelniania -> testy uwierzytelniania).
- Gdy czas jest ograniczony, ogranicz kampanie do mutantów o wysokim/średnim poziomie ważności.
- Uruchamiaj testy równolegle, jeśli runner na to pozwala; buforuj dependencies/builds.
- Fail-fast: zatrzymaj się wcześnie, gdy zmiana wyraźnie wskazuje na lukę w asercjach.

Matematyka czasu wykonywania jest brutalna: `1000 mutants x 5-minute tests ~= 83 hours`, dlatego projekt kampanii ma równie duże znaczenie jak sam mutator.

## Persistent campaigns i triage na dużą skalę

Jedną ze słabości starszych workflow było zapisywanie wyników wyłącznie do `stdout`. W przypadku długich kampanii utrudnia to wstrzymywanie/wznawianie, filtrowanie i przeglądanie.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` usprawniają ten proces, przechowując mutanty i wyniki w kampaniach opartych na SQLite. Korzyści:<sup>[[1]](#references)</sup>
- Wstrzymywanie i wznawianie długich uruchomień bez utraty postępów
- Filtrowanie wyłącznie mutantów `UNCAUGHT` w konkretnym pliku lub klasie mutacji
- Eksportowanie/tłumaczenie wyników do SARIF na potrzeby narzędzi do przeglądu
- Przekazywanie AI-assisted triage mniejszych, przefiltrowanych zestawów wyników zamiast surowych logów terminala

Persistent results są szczególnie przydatne, gdy mutation testing staje się częścią pipeline'u audytowego, a nie jednorazowym ręcznym przeglądem.

## Workflow triage dla przetrwałych mutantów

1) Sprawdź zmienioną linię i zachowanie.
- Odtwórz problem lokalnie, stosując zmienioną linię i uruchamiając ukierunkowany test.

2) Wzmocnij testy tak, aby sprawdzały stan, a nie tylko wartości zwracane.
- Dodaj sprawdzanie granic równości (np. przetestuj próg `==`).
- Sprawdzaj post-conditions: salda, całkowitą podaż, skutki autoryzacji i wyemitowane zdarzenia.

3) Zastąp nadmiernie permisywne mocki realistycznym zachowaniem.
- Upewnij się, że mocki wymuszają transfery, ścieżki błędów i emisję zdarzeń występujące on-chain.

4) Dodaj invariants do testów fuzz.
- Np. zachowanie wartości, nieujemne salda, invariants autoryzacji oraz monotoniczną podaż, jeśli ma to zastosowanie.

5) Oddziel true positives od semantic no-ops.
- Przykład: `x > 0` -> `x != 0` nie ma znaczenia, gdy `x` jest unsigned.

6) Ponownie uruchamiaj kampanię, aż przetrwałe mutanty zostaną zabite lub ich przetrwanie zostanie wyraźnie uzasadnione.

## Case study: ujawnienie brakujących asercji stanu (protokół Arkis)

Kampania mutacyjna przeprowadzona podczas audytu protokołu Arkis DeFi ujawniła przetrwałe mutanty, takie jak:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Zakomentowanie przypisania nie przerwało testów, co dowodzi braku asercji stanu końcowego. Przyczyna źródłowa: kod ufał kontrolowanej przez użytkownika wartości `_cmd.value` zamiast weryfikować rzeczywiste transfery tokenów. Atakujący mógł rozbieżnie ustawić oczekiwane i rzeczywiste transfery, aby drenować środki. Rezultat: ryzyko o wysokim poziomie severity dla wypłacalności protokołu.<sup>[[2]](#references)[[3]](#references)</sup>

Wskazówka: Traktuj przetrwałe mutanty wpływające na transfery wartości, księgowanie lub kontrolę dostępu jako wysokiego ryzyka, dopóki nie zostaną zabite.

## Nie generuj bezkrytycznie testów zabijających każdego mutanta

Generowanie testów sterowane mutacjami może przynieść odwrotny skutek, jeśli bieżąca implementacja jest nieprawidłowa. Przykład: mutacja `priority >= 2` na `priority > 2` zmienia zachowanie, ale właściwą poprawką nie zawsze jest „napisz test dla `priority == 2`”. To zachowanie samo w sobie może być błędem.<sup>[[1]](#references)</sup>

Bezpieczniejszy workflow:
- Użyj przetrwałych mutantów do identyfikowania niejednoznacznych wymagań
- Zweryfikuj oczekiwane zachowanie na podstawie specyfikacji, dokumentacji protokołu lub opinii reviewerów
- Dopiero potem zakoduj to zachowanie jako test/invariant

W przeciwnym razie ryzykujesz utrwaleniem przypadkowych cech implementacji w test suite i uzyskaniem fałszywego poczucia pewności.

## Praktyczna checklista

- Uruchom ukierunkowaną kampanię:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Jeśli to możliwe, preferuj mutatory świadome składni (AST/Tree-sitter) zamiast mutacji opartej wyłącznie na regexach.
- Przeanalizuj przetrwałe mutanty i napisz testy/invariants, które zakończyłyby się niepowodzeniem przy zmienionym zachowaniu.
- Aseruj salda, podaż, uprawnienia i events.
- Dodaj testy wartości granicznych (`==`, przepełnienia/niedomiaru, zero-address, zero-amount, puste tablice).
- Zastąp nierealistyczne mocki; symuluj tryby awarii.
- Utrwalaj wyniki, gdy tooling to obsługuje, i odfiltruj mutanty, których nie przechwycono, przed triage.
- Używaj kampanii dwuetapowych lub kampanii per target, aby utrzymać rozsądny czas działania.
- Iteruj, aż wszystkie mutanty zostaną zabite albo uzasadnione komentarzami i uzasadnieniem.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
