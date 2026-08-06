# Terminy inwestycyjne

{{#include ../banners/hacktricks-training.md}}

## Spot

To najbardziej podstawowy sposób prowadzenia tradingu. Możesz **wskazać ilość aktywa i cenę**, po której chcesz kupić lub sprzedać, a gdy tylko cena ta zostanie osiągnięta, operacja zostanie wykonana.

Zwykle możesz również użyć **bieżącej ceny rynkowej**, aby wykonać transakcję tak szybko, jak to możliwe, po aktualnej cenie.

**Stop Loss - Limit**: Możesz również wskazać ilość i cenę aktywów do kupna lub sprzedaży, a także niższą cenę kupna lub sprzedaży na wypadek jej osiągnięcia (aby ograniczyć straty).

## Futures

Futures to kontrakt, w którym 2 strony uzgadniają **nabycie czegoś w przyszłości po ustalonej cenie**. Na przykład sprzedaż 1 bitcoina za 6 miesięcy po cenie 70 000 USD.

Oczywiście, jeśli po 6 miesiącach wartość bitcoina wyniesie 80 000 USD, strona sprzedająca straci pieniądze, a strona kupująca je zarobi. Jeśli po 6 miesiącach wartość bitcoina wyniesie 60 000 USD, sytuacja będzie odwrotna.

Jest to jednak interesujące na przykład dla firm, które wytwarzają produkt i muszą mieć pewność, że będą mogły sprzedać go po cenie pozwalającej pokryć koszty. Dotyczy to również firm, które chcą zagwarantować sobie stałe ceny w przyszłości, nawet jeśli będą one wyższe.

Chociaż na giełdach rozwiązanie to jest zwykle wykorzystywane do próby osiągnięcia zysku.

* Zauważ, że „Long position” oznacza, że ktoś obstawia wzrost ceny
* Natomiast „short position” oznacza, że ktoś obstawia spadek ceny

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Jeśli zarządzający funduszem obawia się, że niektóre akcje spadną, może zająć krótką pozycję na aktywach takich jak bitcoin lub kontrakty futures na S\&P 500. Byłoby to podobne do kupienia lub posiadania aktywów i zawarcia kontraktu na ich sprzedaż w przyszłości po wyższej cenie.

Jeśli cena spadnie, zarządzający funduszem osiągnie zysk, ponieważ sprzeda aktywa po wyższej cenie. Jeśli cena aktywów wzrośnie, zarządzający nie osiągnie tego zysku, ale nadal zachowa swoje aktywa.

### Perpetual Futures

**Są to „futures”, które będą trwać bezterminowo** (bez daty zakończenia kontraktu). Bardzo często można je znaleźć na przykład na giełdach kryptowalut, gdzie można wchodzić i wychodzić z futures w zależności od ceny kryptowalut.

Zauważ, że w takich przypadkach zyski i straty mogą być naliczane w czasie rzeczywistym: jeśli cena wzrośnie o 1%, zyskasz 1%; jeśli cena spadnie o 1%, stracisz 1%.

### Futures with Leverage

**Dźwignia finansowa** pozwala kontrolować większą pozycję na rynku za pomocą mniejszej kwoty pieniędzy. Zasadniczo pozwala „obstawiać” znacznie większą kwotę, niż posiadasz, ryzykując tylko pieniędzmi, które faktycznie masz.

Na przykład, jeśli otworzysz pozycję futures na BTC/USDT za 100 USD z dźwignią 50x, oznacza to, że jeśli cena wzrośnie o 1%, zarobisz 1x50 = 50% swojej początkowej inwestycji (50 USD). W rezultacie będziesz mieć 150 USD.\
Jeśli jednak cena spadnie o 1%, stracisz 50% swoich środków (w tym przypadku 50 USD). Jeśli cena spadnie o 2%, stracisz całą obstawioną kwotę (2x50 = 100%).

Dźwignia pozwala więc kontrolować kwotę, którą obstawiasz, jednocześnie zwiększając potencjalne zyski i straty.

## Różnice między Futures a Options

Główna różnica między futures a options polega na tym, że wykonanie kontraktu jest opcjonalne dla kupującego: może on zdecydować, czy go wykonać, czy nie (zwykle zrobi to tylko wtedy, gdy będzie to dla niego korzystne). Sprzedający musi sprzedać, jeśli kupujący chce skorzystać z opcji.\
Kupujący zapłaci jednak sprzedającemu opłatę za otwarcie opcji (dzięki czemu sprzedający, który pozornie podejmuje większe ryzyko, zaczyna zarabiać pewne pieniądze).

### 1. **Obowiązek a prawo:**

* **Futures:** Kupując lub sprzedając kontrakt futures, zawierasz **wiążącą umowę** kupna lub sprzedaży aktywa po określonej cenie i w określonym terminie w przyszłości. Zarówno kupujący, jak i sprzedający są **zobowiązani** do realizacji kontraktu w dniu wygaśnięcia (chyba że kontrakt zostanie wcześniej zamknięty).
* **Options:** W przypadku options masz **prawo, ale nie obowiązek**, kupić (w przypadku **call option**) lub sprzedać (w przypadku **put option**) aktywo po określonej cenie przed określonym terminem wygaśnięcia lub w tym terminie. **Kupujący** ma możliwość wykonania opcji, natomiast **sprzedający** jest zobowiązany do realizacji transakcji, jeśli kupujący zdecyduje się wykonać opcję.

### 2. **Ryzyko:**

* **Futures:** Zarówno kupujący, jak i sprzedający ponoszą **nieograniczone ryzyko**, ponieważ są zobowiązani do realizacji kontraktu. Ryzyko stanowi różnica między uzgodnioną ceną a ceną rynkową w dniu wygaśnięcia.
* **Options:** Ryzyko kupującego jest ograniczone do **premii** zapłaconej za zakup opcji. Jeśli rynek nie zmieni się na korzyść posiadacza opcji, może on po prostu pozwolić na jej wygaśnięcie. Jednak **sprzedający** (wystawca) opcji ponosi nieograniczone ryzyko, jeśli rynek znacząco zmieni się na jego niekorzyść.

### 3. **Koszt:**

* **Futures:** Nie ma kosztu początkowego wykraczającego poza depozyt zabezpieczający wymagany do utrzymania pozycji, ponieważ zarówno kupujący, jak i sprzedający są zobowiązani do realizacji transakcji.
* **Options:** Kupujący musi z góry zapłacić **premię opcyjną** za prawo do wykonania opcji. Premia ta stanowi zasadniczo koszt opcji.

### 4. **Potencjał zysku:**

* **Futures:** Zysk lub strata zależy od różnicy między ceną rynkową w dniu wygaśnięcia a uzgodnioną ceną określoną w kontrakcie.
* **Options:** Kupujący osiąga zysk, gdy rynek przesunie się korzystnie poza cenę wykonania o więcej niż zapłacona premia. Sprzedający osiąga zysk, zatrzymując premię, jeśli opcja nie zostanie wykonana.

{{#include ../banners/hacktricks-training.md}}
