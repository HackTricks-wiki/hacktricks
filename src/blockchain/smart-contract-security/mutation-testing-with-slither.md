# Testowanie mutacyjne smart kontraktów (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Testowanie mutacyjne „testuje twoje testy” poprzez systematyczne wprowadzanie niewielkich zmian (mutantów) do kodu kontraktu i ponowne uruchamianie zestawu testów. Jeśli test zakończy się niepowodzeniem, mutant zostaje zabity. Jeśli testy nadal przechodzą, mutant przetrwa, ujawniając martwe pole, którego nie wykryje pokrycie linii ani gałęzi.

Główna idea: pokrycie pokazuje, że kod został wykonany; testowanie mutacyjne pokazuje, czy jego zachowanie jest faktycznie asertowane.<sup>[[2]](#references)</sup>

## Dlaczego pokrycie może wprowadzać w błąd

Rozważmy ten prosty warunek progowy:

```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
    if (deposit >= 1 ether) {
        return true;
    } else {
        return false;
    }
}
```

Testy jednostkowe, które sprawdzają tylko wartość poniżej i powyżej progu, mogą osiągnąć 100% pokrycia linii/gałęzi, nie sprawdzając granicy równości (==). Refaktoryzacja do `deposit >= 2 ether` nadal przechodziłaby takie testy, po cichu zmieniając logikę protokołu.<sup>[[2]](#references)</sup>

Testowanie mutacyjne ujawnia tę lukę przez mutowanie warunku i sprawdzanie, czy testy kończą się niepowodzeniem.

W przypadku smart contracts ocalałe mutanty często wskazują na brakujące kontrole dotyczące:
- Autoryzacji i granic ról
- Niezmienników księgowania/przesyłania wartości
- Warunków revert i ścieżek błędów
- Warunków brzegowych (`==`, wartości zerowe, puste tablice, wartości maksymalne/minimalne)

## Operatory mutacji o najwyższej wartości dla bezpieczeństwa

Przydatne klasy mutacji podczas audytu kontraktów:<sup>[[1]](#references)[[2]](#references)</sup>
- **Wysoki poziom istotności**: zastępowanie instrukcji przez `revert()`, aby ujawnić niewykonane ścieżki
- **Średni poziom istotności**: zakomentowanie linii / usunięcie logiki, aby ujawnić niezweryfikowane efekty uboczne
- **Niski poziom istotności**: subtelna zamiana operatorów lub stałych, np. `>=` -> `>` lub `+` -> `-`
- Inne częste zmiany: zastępowanie przypisań, odwracanie wartości logicznych, negowanie warunków i zmiany typów

Praktyczny cel: wyeliminować wszystkie istotne mutanty i wyraźnie uzasadnić pozostawienie tych nieistotnych lub semantycznie równoważnych.

## Dlaczego mutacje uwzględniające składnię są lepsze niż regex

Starsze silniki mutacji polegały na regex lub przekształceniach opartych na liniach. To działa, ale ma istotne ograniczenia:<sup>[[1]](#references)</sup>
- Instrukcje wieloliniowe trudno bezpiecznie mutować
- Struktura języka nie jest rozpoznawana, więc komentarze/tokeny mogą być błędnie wskazywane
- Generowanie wszystkich możliwych wariantów w słabo pokrytej linii marnuje dużo czasu działania

Narzędzia oparte na AST lub Tree-sitter poprawiają to, wybierając ustrukturyzowane węzły zamiast surowych linii:<sup>[[1]](#references)</sup>
- **slither-mutate** korzysta z AST Solidity Slither.<sup>[[4]](#references)</sup>
- **mewt** korzysta z Tree-sitter jako niezależnego od języka rdzenia.<sup>[[6]](#references)</sup>
- **MuTON** bazuje na `mewt` i dodaje natywną obsługę języków TON, takich jak FunC, Tolk i Tact.<sup>[[7]](#references)</sup>

Dzięki temu mutacje konstrukcji wieloliniowych i wyrażeń są znacznie bardziej niezawodne niż podejścia oparte wyłącznie na regex.

## Uruchamianie testowania mutacyjnego za pomocą slither-mutate

Wymagania: Slither v0.10.2+.

- Wyświetl opcje i operatory mutacji:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Przykład Foundry (zapisz wyniki i zachowaj pełny log):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Jeśli nie używasz Foundry, zastąp `--test-cmd` poleceniem, którego używasz do uruchamiania testów (np. `npx hardhat test`, `npm test`).

Artefakty są domyślnie przechowywane w `./mutation_campaign`. Niezłapane (przetrwałe) mutanty są tam kopiowane do inspekcji.<sup>[[5]](#references)</sup>

### Zrozumienie wyników

Wiersze raportu wyglądają tak:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- Tag w nawiasach oznacza alias mutatora (np. `CR` = Comment Replacement).
- `UNCAUGHT` oznacza, że testy przeszły przy zmienionym zachowaniu → brak asercji.

## Ograniczanie czasu działania: priorytetyzacja istotnych mutantów

Kampanie mutacyjne mogą trwać godzinami lub dniami. Wskazówki, jak ograniczyć koszty:<sup>[[1]](#references)[[2]](#references)</sup>
- Zakres: Zacznij tylko od krytycznych kontraktów/katalogów, a następnie rozszerz zakres.
- Priorytetyzacja mutatorów: Jeśli mutant o wysokim priorytecie w danej linii przetrwa (na przykład `revert()` lub zakomentowanie), pomiń warianty o niższym priorytecie dla tej linii.
- Kampanie dwuetapowe: Najpierw uruchom ukierunkowane/szybkie testy, a następnie ponownie przetestuj pełnym zestawem tylko mutanty, które nie zostały wykryte.
- Jeśli to możliwe, przypisz cele mutacji do konkretnych poleceń testowych (na przykład kod uwierzytelniania -> testy uwierzytelniania).
- Gdy brakuje czasu, ogranicz kampanie do mutantów o wysokiej/średniej istotności.
- Uruchamiaj testy równolegle, jeśli runner na to pozwala; buforuj zależności/kompilacje.
- Fail-fast: przerwij wcześniej, gdy zmiana wyraźnie ujawnia lukę w asercjach.

Obliczenia czasu są bezlitosne: `1000 mutants x 5-minute tests ~= 83 hours`, więc projekt kampanii jest równie ważny jak sam mutator.<sup>[[1]](#references)</sup>

## Trwałe kampanie i triage na dużą skalę

Jedną ze słabości starszych przepływów pracy jest zapisywanie wyników wyłącznie do `stdout`. W przypadku długich kampanii utrudnia to wstrzymywanie/wznawianie, filtrowanie i przeglądanie wyników.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` rozwiązują ten problem, przechowując mutanty i wyniki kampanii w SQLite. Korzyści:<sup>[[1]](#references)</sup>
- Wstrzymywanie i wznawianie długich przebiegów bez utraty postępów
- Filtrowanie mutantów, które nie zostały wykryte, według konkretnego pliku lub klasy mutacji
- Eksportowanie/konwertowanie wyników do SARIF na potrzeby narzędzi do przeglądu
- Przekazywanie AI do triage mniejszych, przefiltrowanych zestawów wyników zamiast surowych logów terminala

Trwałe wyniki są szczególnie przydatne, gdy testowanie mutacyjne staje się częścią procesu audytu, a nie jednorazowym ręcznym przeglądem.

## Przepływ pracy triage dla mutantów, które przetrwały

1) Sprawdź zmodyfikowaną linię i zachowanie.
   - Odtwórz problem lokalnie, wprowadzając zmodyfikowaną linię i uruchamiając ukierunkowany test.

2) Wzmocnij testy, aby weryfikowały stan, a nie tylko wartości zwracane.
   - Dodaj testy granicznych wartości równości (np. przetestuj próg `==`).
   - Sprawdzaj warunki końcowe: salda, całkowitą podaż, skutki autoryzacji i emitowane zdarzenia.

3) Zastąp nadmiernie liberalne mocki realistycznym zachowaniem.
   - Upewnij się, że mocki uwzględniają transfery, ścieżki błędów i emisję zdarzeń występujące w łańcuchu.

4) Dodaj niezmienniki do testów fuzz.
   - Np. zachowanie wartości, nieujemne salda, niezmienniki autoryzacji i monotoniczność podaży, jeśli ma zastosowanie.

5) Oddziel prawdziwe trafienia od semantycznych zmian bez wpływu.
   - Przykład: `x > 0` -> `x != 0` nie ma znaczenia, gdy `x` jest bez znaku.

6) Powtarzaj kampanię, aż mutanty zostaną wykryte lub ich przetrwanie zostanie jawnie uzasadnione.

## Studium przypadku: wykrywanie brakujących asercji stanu (protokół Arkis)

Kampania mutacyjna przeprowadzona podczas audytu protokołu DeFi Arkis ujawniła mutanty, które przetrwały, takie jak:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Zakomentowanie przypisania nie zepsuło testów, co dowodzi braku asercji stanu końcowego. Przyczyna: kod ufał kontrolowanej przez użytkownika wartości `_cmd.value` zamiast weryfikować rzeczywiste transfery tokenów. Atakujący mógł rozregulować zgodność oczekiwanych i rzeczywistych transferów, aby wyprowadzić środki. Skutek: wysokie ryzyko dla wypłacalności protokołu.<sup>[[2]](#references)[[3]](#references)</sup>

Wskazówka: Traktuj przetrwałe mutanty wpływające na transfery wartości, księgowanie lub kontrolę dostępu jako wysokiego ryzyka, dopóki ich nie wyeliminujesz.

## Nie generuj bezrefleksyjnie testów, aby wyeliminować każdego mutanta

Generowanie testów sterowane mutacjami może przynieść odwrotny skutek, jeśli bieżąca implementacja jest błędna. Przykład: zmiana `priority >= 2` na `priority > 2` modyfikuje zachowanie, ale właściwym rozwiązaniem nie zawsze jest „napisanie testu dla `priority == 2`”. Samo to zachowanie może być błędem.<sup>[[1]](#references)</sup>

Bezpieczniejszy proces:
- Wykorzystuj przetrwałe mutanty do wykrywania niejednoznacznych wymagań
- Weryfikuj oczekiwane zachowanie na podstawie specyfikacji, dokumentacji protokołu lub opinii recenzentów
- Dopiero potem zapisuj to zachowanie jako test/inwariant

W przeciwnym razie ryzykujesz utrwalenie przypadkowych cech implementacji w zestawie testów i uzyskanie fałszywego poczucia bezpieczeństwa.

## Praktyczna lista kontrolna

- Uruchom ukierunkowaną kampanię:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Jeśli to możliwe, preferuj mutatory uwzględniające składnię (AST/Tree-sitter) zamiast mutacji opartych wyłącznie na wyrażeniach regularnych.
- Przeanalizuj przetrwałe mutanty i napisz testy/inwarianty, które nie przechodzą przy zmienionym zachowaniu.
- Sprawdzaj salda, podaż, uprawnienia i zdarzenia.
- Dodaj testy przypadków brzegowych (`==`, przepełnienia/niedomiaru, adresu zerowego, zerowej kwoty, pustych tablic).
- Zastąp nierealistyczne mocki; symuluj tryby awarii.
- Utrwalaj wyniki, jeśli narzędzie to umożliwia, i przed analizą odfiltruj mutanty, które nie zostały przechwycone.
- Korzystaj z kampanii dwuetapowych lub kampanii dla poszczególnych celów, aby utrzymać rozsądny czas wykonania.
- Powtarzaj proces, aż wszystkie mutanty zostaną wyeliminowane lub uzasadnione komentarzami i wyjaśnieniem.

## References

- [1] [Testowanie mutacyjne w erze agentów](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Użyj testowania mutacyjnego, aby znaleźć błędy niewykrywane przez testy (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Przegląd bezpieczeństwa Arkis DeFi Prime Brokerage (dodatek C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Dokumentacja Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
