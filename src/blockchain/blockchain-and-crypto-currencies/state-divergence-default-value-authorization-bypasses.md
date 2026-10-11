# Rozbieżność stanu i obejścia autoryzacji oparte na wartościach domyślnych

{{#include ../../banners/hacktricks-training.md}}

Autoryzacja czasami zależy od wyprowadzonego stanu ekonomicznego zamiast od jawnej roli — na przykład: „wywołujący posiada całą podaż”. Jeśli wartości użyte w tym warunku pochodzą z różnych magazynów, nieaktualna kopia może zmienić uzasadnione uproszczenie dotyczące posiadania w obejście autoryzacji. Moduł znaczników Provenance pokazał niebezpieczne połączenie: saldo wywołującego pobierane na bieżąco było porównywane z lokalnymi metadanymi podaży znacznika, które nie były aktualizowane dla zasobów o zmiennej podaży.<sup>[[1]](#references)</sup>

## Audytuj zduplikowany stan jako granicę autoryzacji

Dla każdej wartości używanej przez kontrolę uprawnień wymień **wszystkie jej reprezentacje**: kanoniczny stan modułu, pola obiektów, agregaty w pamięci podręcznej, indeksy, migawki, rekordy mostów i kopie lustrzane poza łańcuchem. Następnie prześledź każdą ścieżkę tworzenia, emisji, spalenia, transferu, resetowania, migracji i synchronizacji, aby ustalić, która kopia jest aktualizowana w każdym trybie obiektu. Pole może być źródłem prawdy w jednym trybie, a w innym pełnić wyłącznie funkcję informacyjną.<sup>[[1]](#references)</sup>

Praktyczny proces przeglądu:<sup>[[1]](#references)</sup>

1. Znajdź chronione akcje i sprowadź każdą gałąź autoryzacji do predykatu logicznego.
2. Dla każdego operandu zapisz jego magazyn, ścieżki aktualizacji, stany cyklu życia i źródło prawdy.
3. Wygeneruj przejścia, które aktualizują tylko jedną reprezentację, a następnie porównaj wszystkie kopie.
4. Po każdym przejściu spróbuj wykonać chronioną akcję z nowego konta.
5. Nie kończ na obejściu: jeśli akcja modyfikuje ACL, nadaj sobie trwale role i wywołaj standardowe uprzywilejowane API.

Podejrzane wzorce obejmują `cachedSupply == balance`, `metadataOwner == caller` lub `snapshotShares == currentShares`, gdy obie strony podlegają różnym regułom synchronizacji. Odczytanie autorytatywnej wartości dla jednego operandu nie sprawia, że porównanie jest bezpieczne, jeśli drugi operand jest nieaktualny.<sup>[[1]](#references)</sup>

## Obejście oparte na równości wartości domyślnych

Predykat równości jest również niebezpieczny, gdy oba operandy mogą niezależnie przyjąć tę samą wartość domyślną. Poniższa kontrola przyznaje „pełną kontrolę nad podażą” każdemu pustemu kontu, gdy `supply` wynosi zero — niezależnie od tego, czy zero wynika z nieaktualnych metadanych, czy z obiektu, któremu zgodnie z prawdą nie przydzielono środków.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Przełączenie na kanoniczny magazyn naprawia rozbieżność, ale **nie** rozwiązuje przypadku pustego obiektu. Właściwość bezpieczeństwa musi obejmować niezależny warunek poprawności; poprawka Provenance używa bieżącej podaży banku i odrzuca nil lub zerową podaż przed porównaniem salda wywołującego.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Zastosuj to samo rozumowanie do liczby głosów wymaganej do kworum, udziałów własnościowych, zadłużenia, zabezpieczeń, epok, nonce, znaczników czasu i liczników: `callerValue == protectedValue` nie może upoważniać wywołującego, dopóki chroniona wartość nie zostanie niezależnie zweryfikowana i nie potwierdzi się, że należy do oczekiwanej domeny.<sup>[[1]](#references)</sup>

## Przejęcie ACL prowadzące do legalnych operacji uprzywilejowanych

Bypass w operacji edycji ACL to trwały prymityw eskalacji uprawnień. W przypadku Provenance konto bez uprawnień i z zerową liczbą tokenów mogło przejść test podaży oparty na nieaktualnej wartości `0 == 0`, nadać sobie uprawnienia administratora, mintowania i wypłat, a następnie użyć zwykłych handlerów komunikatów do mintowania aktywów lub wypłacania środków z escrow. Wykorzystanie luki nie wymagało więc drugiej podatności po zmianie ACL.<sup>[[1]](#references)</sup>

Ogólny przebieg wykorzystania luki:<sup>[[1]](#references)</sup>

1. Znajdź obiekt, którego nieautorytatywne pole różni się od bieżącego stanu albo którego chroniona wartość jest wartością domyślną.
2. Użyj nowej/pustej tożsamości, aby jej lokalna wartość odpowiadała tej nieaktualnej wartości lub wartości domyślnej.
3. Wywołaj endpoint zarządzania rolami, przeniesienia własności lub aktualizacji zasad i nadaj sobie trwałe uprawnienia.
4. Potwierdź trwałość zmiany, odczytując ACL ze stanu kanonicznego.
5. Wywołaj legalną operację o dużym wpływie (mintowanie, wypłatę, aktualizację, przeniesienie własności lub zmianę zasad).

Podczas oceny wpływu sprawdź wszystkie uprawnienia dostępne nowej roli, zamiast poprzestawać na obejściu autoryzacji. Konta podobne do escrow mogą przechowywać aktywa niezwiązane z obiektem, którego nieaktualne metadane umożliwiły przejęcie.<sup>[[1]](#references)</sup>

## Niezmienniki i cele stateful fuzzing

Określ autoryzację niezależnie od implementacji. W przypadku skrótu dla pełnej podaży minimalny niezmiennik to:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Użyj fuzzera modelu/maszyny stanów do generowania sekwencji — nie pojedynczych wywołań — obejmujących tworzenie, inicjalizację wartością zero, aktywację/finalizację, mintowanie, spalanie, transfery, resetowanie, migracje, wywołania sync i zmiany ACL. Po każdym przejściu porównuj zduplikowane reprezentacje i sprawdzaj, czy nowe konto nie może wykonać żadnej chronionej operacji. Dodaj jawne przypadki dla wartości zero, jednej jednostki, częściowego posiadania, pełnego posiadania, wartości zaniżonych i zawyżonych względem aktualnego stanu.<sup>[[1]](#references)[[2]](#references)</sup>

Właściwości regresyjne o wysokiej wartości diagnostycznej:<sup>[[1]](#references)[[2]](#references)</sup>

- Zerowa podaż według źródła autorytatywnego nigdy nie oznacza posiadania ani uprawnień administracyjnych.
- Częściowi posiadacze nie mogą uzyskać uprawnień administratora, gdy zduplikowana podaż jest równa ich saldu.
- Rzeczywisty pełny posiadacz zachowuje zamierzony skrót, gdy bieżąca podaż jest dodatnia.
- Nieudane próby nadania uprawnień samemu sobie nie zmieniają ACL ani nie umożliwiają późniejszych uprzywilejowanych wywołań.
- Zmiany trybu nie mogą po cichu zmieniać tego, którą reprezentację kontrola autoryzacji uznaje za autorytatywną.

## References

- [1] [Rozbieżność stanu umożliwia nieautoryzowany dostęp (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Naprawa nieaktualnych kontroli podaży](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Odrzucanie zerowej podaży w skrócie autoryzacyjnym opartym na całkowitej podaży](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
