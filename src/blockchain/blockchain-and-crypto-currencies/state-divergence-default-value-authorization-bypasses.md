# Ominięcia autoryzacji wynikające z rozbieżności stanu i wartości domyślnych

{{#include ../../banners/hacktricks-training.md}}

Autoryzacja czasami zależy od wyprowadzonego stanu ekonomicznego zamiast od jawnej roli — na przykład „caller posiada całą podaż”. Jeśli wartości użyte w tym predykacie pochodzą z różnych magazynów, nieaktualny duplikat może zmienić uzasadniony skrót własności w obejście autoryzacji. Moduł Provenance marker zademonstrował niebezpieczną kombinację: bieżące saldo callera było porównywane z lokalnymi dla markera metadanymi podaży, które nie były aktualizowane dla aktywów o zmiennej podaży.<sup>[[1]](#references)</sup>

## Audyt zduplikowanego stanu jako granicy autoryzacji

Dla każdej wartości używanej przez check uprawnień wylicz **wszystkie reprezentacje**: kanoniczny stan modułu, pola obiektów, buforowane agregaty, indeksy, snapshoty, rekordy bridge oraz off-chain mirrors. Następnie prześledź każdą ścieżkę tworzenia, mint, burn, transferu, resetowania, migracji i synchronizacji, aby ustalić, która kopia jest aktualizowana w każdym trybie obiektu. Pole może być autorytatywne w jednym trybie, a informacyjne w innym.<sup>[[1]](#references)</sup>

Praktyczny workflow review obejmuje:<sup>[[1]](#references)</sup>

1. Zlokalizuj chronione akcje i sprowadź każdą gałąź autoryzacji do predykatu boolowskiego.
2. Dla każdego operandu zapisz jego magazyn, ścieżki aktualizacji, stany cyklu życia oraz source of truth.
3. Wygeneruj przejścia aktualizujące tylko jedną reprezentację, a następnie porównaj wszystkie kopie.
4. Po każdym przejściu spróbuj wykonać chronioną akcję z nowego konta.
5. Wyjdź poza samo obejście: jeśli akcja modyfikuje ACL, nadaj sobie trwałe role i wywołaj zwykłe uprzywilejowane API.

Podejrzane wzorce obejmują `cachedSupply == balance`, `metadataOwner == caller` lub `snapshotShares == currentShares`, gdy obie strony mają różne reguły synchronizacji. Odczytanie autorytatywnej wartości dla jednego operandu nie sprawia, że porównanie jest bezpieczne, jeśli drugi operand jest nieaktualny.<sup>[[1]](#references)</sup>

## Ominięcie równości wartości domyślnych

Predykat równości jest również niebezpieczny, gdy oba operandy mogą niezależnie przyjąć tę samą wartość domyślną. Poniższy check przyznaje „pełną kontrolę nad podażą” każdemu pustemu kontu, gdy `supply` wynosi zero, niezależnie od tego, czy zero wynika z nieaktualnych metadanych, czy z obiektu, który zgodnie z przeznaczeniem nie został zasilony.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Przełączenie na canonical store naprawia divergence, ale **nie** przypadek pustego obiektu. Właściwość bezpieczeństwa musi obejmować niezależny warunek poprawności; patch Provenance wykorzystuje bieżącą podaż banku i odrzuca nil lub podaż równą zero przed porównaniem salda caller.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Zastosuj to samo rozumowanie do liczby głosów wymaganej do uzyskania quorum, procentów własności, długu, zabezpieczenia, epok, nonce'ów, znaczników czasu i liczników: `callerValue == protectedValue` nie może autoryzować wywołującego, dopóki chroniona wartość nie będzie niezależnie poprawna i nie będzie należeć do oczekiwanej domeny.<sup>[[1]](#references)</sup>

## Przejęcie ACL prowadzące do legalnych operacji uprzywilejowanych

Bypass w operacji edycji ACL jest trwałym prymitywem eskalacji uprawnień. W przypadku Provenance nieuprzywilejowane konto z zerową liczbą tokenów mogło przejść test podaży `0 == 0` oparty na nieaktualnych danych, nadać sobie uprawnienia administracyjne, uprawnienia do mintowania i wypłat, a następnie użyć zwykłych message handlerów do mintowania aktywów lub wypłaty środków z escrow. Exploit nie wymagał więc żadnej drugiej podatności po zmianie ACL.<sup>[[1]](#references)</sup>

Ogólny przebieg exploita:<sup>[[1]](#references)</sup>

1. Znajdź obiekt, którego pole niebędące źródłem prawdy różni się od bieżącego stanu albo którego chroniona wartość jest wartością domyślną.
2. Użyj nowej/pustej tożsamości, aby jej lokalna wartość odpowiadała tej nieaktualnej lub domyślnej wartości.
3. Wywołaj endpoint zarządzania rolami, przekazania własności lub aktualizacji polityki i nadaj sobie trwałe capabilities.
4. Potwierdź trwałość, odczytując ACL ze stanu kanonicznego.
5. Wywołaj legalną operację o dużym wpływie (mintowanie, wypłatę, upgrade, przekazanie własności lub zmianę polityki).

Podczas oceny wpływu przeanalizuj każdą capability dostępną z nowej roli, zamiast kończyć analizę na samym authorization bypass. Konta podobne do escrow mogą przechowywać aktywa niezwiązane z obiektem, którego nieaktualne metadane umożliwiły przejęcie.<sup>[[1]](#references)</sup>

## Cele invariant i stateful-fuzzing

Zdefiniuj autoryzację niezależnie od implementacji. Dla skrótu dotyczącego pełnej podaży minimalny invariant to:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Użyj modelu/state-machine fuzzer, aby generować sekwencje — a nie izolowane wywołania — obejmujące tworzenie, inicjalizację wartością zero, aktywację/finalizację, minting, burning, transfery, resety, migracje, wywołania synchronizacji oraz zmiany ACL. Po każdym przejściu porównuj zduplikowane reprezentacje i sprawdzaj, czy nowe konto nie może wykonać żadnej chronionej operacji. Dodaj jawne przypadki dla wartości zero, jednej jednostki, częściowej własności, pełnej własności, nieaktualnych wartości niższych i nieaktualnych wartości wyższych.<sup>[[1]](#references)[[2]](#references)</sup>

Właściwości regresji o wysokiej wartości sygnału to:<sup>[[1]](#references)[[2]](#references)</sup>

- Autorytatywna podaż równa zero nigdy nie oznacza własności ani uprawnień administracyjnych.
- Posiadacze częściowej własności nie mogą uzyskać uprawnień administratora, gdy zduplikowana podaż jest równa ich saldu.
- Rzeczywisty posiadacz całości zachowuje zamierzony skrót, gdy bieżąca podaż jest dodatnia.
- Nieudane self-grants nie zmieniają ACL ani nie umożliwiają wykonywania kolejnych uprzywilejowanych wywołań.
- Zmiany trybu nie mogą po cichu zmieniać tego, która reprezentacja jest traktowana jako autorytatywna przez sprawdzenie autoryzacji.

## References

- [1] [Rozbieżność stanu umożliwia nieautoryzowany dostęp (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Naprawa sprawdzeń nieaktualnej podaży](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Commit Provenance c81fd65 - Odrzucanie podaży równej zero w skrócie autoryzacji całkowitej podaży](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
