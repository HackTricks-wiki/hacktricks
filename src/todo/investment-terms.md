# Warunki Inwestycyjne

{{#include /banners/hacktricks-training.md}}

## Spot

To najprostszy sposób na przeprowadzenie transakcji. Możesz **określić ilość aktywów i cenę**, po której chcesz kupić lub sprzedać, a gdy ta cena zostanie osiągnięta, operacja zostanie zrealizowana.

Zazwyczaj możesz również użyć **aktualnej ceny rynkowej**, aby przeprowadzić transakcję jak najszybciej po bieżącej cenie.

**Stop Loss - Limit**: Możesz również określić ilość i cenę aktywów do kupienia lub sprzedaży, jednocześnie wskazując niższą cenę do kupienia lub sprzedaży w przypadku jej osiągnięcia (aby zatrzymać straty).

## Futures

Futures to kontrakt, w którym 2 strony dochodzą do porozumienia, aby **nabyć coś w przyszłości po ustalonej cenie**. Na przykład sprzedać 1 bitcoina za 6 miesięcy po 70.000$.

Oczywiście, jeśli za 6 miesięcy wartość bitcoina wynosi 80.000$, strona sprzedająca traci pieniądze, a strona kupująca zyskuje. Jeśli za 6 miesięcy wartość bitcoina wynosi 60.000$, dzieje się odwrotnie.

Jednakże, to jest interesujące na przykład dla firm, które generują produkt i potrzebują mieć pewność, że będą mogły go sprzedać po cenie pokrywającej koszty. Lub dla firm, które chcą zapewnić sobie stałe ceny w przyszłości, nawet jeśli będą wyższe.

Chociaż na giełdach zazwyczaj używa się tego, aby spróbować osiągnąć zysk.

* Zauważ, że "Długa pozycja" oznacza, że ktoś stawia na to, że cena wzrośnie.
* Natomiast "krótka pozycja" oznacza, że ktoś stawia na to, że cena spadnie.

### Hedging z Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Jeśli menedżer funduszu obawia się, że niektóre akcje spadną, może zająć krótką pozycję na niektórych aktywach, takich jak bitcoiny lub kontrakty futures na S\&P 500. To byłoby podobne do kupowania lub posiadania niektórych aktywów i stworzenia kontraktu na sprzedaż ich w przyszłości po wyższej cenie.

W przypadku spadku ceny menedżer funduszu zyska, ponieważ sprzeda aktywa po wyższej cenie. Jeśli cena aktywów wzrośnie, menedżer nie zyska tej korzyści, ale nadal zachowa swoje aktywa.

### Perpetual Futures

**To są "futures", które będą trwały w nieskończoność** (bez daty zakończenia kontraktu). Bardzo często można je znaleźć na przykład na giełdach kryptowalut, gdzie możesz wchodzić i wychodzić z futures w zależności od ceny kryptowalut.

Zauważ, że w tych przypadkach zyski i straty mogą być w czasie rzeczywistym, jeśli cena wzrośnie o 1%, wygrywasz 1%, jeśli cena spadnie o 1%, stracisz to.

### Futures z Dźwignią

**Dźwignia** pozwala Ci kontrolować większą pozycję na rynku przy mniejszej kwocie pieniędzy. W zasadzie pozwala Ci "stawiać" znacznie więcej pieniędzy, niż posiadasz, ryzykując tylko pieniądze, które faktycznie masz.

Na przykład, jeśli otworzysz pozycję futures w BTC/USDT z 100$ przy dźwigni 50x, oznacza to, że jeśli cena wzrośnie o 1%, wtedy zyskujesz 1x50 = 50% swojego początkowego inwestycji (50$). I w ten sposób będziesz miał 150$.\
Jednak jeśli cena spadnie o 1%, stracisz 50% swoich funduszy (59$ w tym przypadku). A jeśli cena spadnie o 2%, stracisz całe swoje zakłady (2x50 = 100%).

Dlatego dźwignia pozwala kontrolować kwotę pieniędzy, którą stawiasz, jednocześnie zwiększając zyski i straty.

## Różnice między Futures a Opcjami

Główna różnica między futures a opcjami polega na tym, że kontrakt jest opcjonalny dla kupującego: Może zdecydować, czy go zrealizować, czy nie (zazwyczaj zrobi to tylko wtedy, gdy odniesie z tego korzyść). Sprzedawca musi sprzedać, jeśli kupujący chce skorzystać z opcji.\
Jednak kupujący będzie płacił pewną opłatę sprzedawcy za otwarcie opcji (więc sprzedawca, który podejmuje większe ryzyko, zaczyna zarabiać pieniądze).

### 1. **Obowiązek vs. Prawo:**

* **Futures:** Kiedy kupujesz lub sprzedajesz kontrakt futures, wchodzisz w **wiążące porozumienie** na zakup lub sprzedaż aktywa po określonej cenie w przyszłym terminie. Zarówno kupujący, jak i sprzedający są **zobowiązani** do wypełnienia kontraktu przy wygaśnięciu (chyba że kontrakt zostanie zamknięty wcześniej).
* **Opcje:** W przypadku opcji masz **prawo, ale nie obowiązek**, do zakupu (w przypadku **opcji call**) lub sprzedaży (w przypadku **opcji put**) aktywa po określonej cenie przed lub w dniu wygaśnięcia. **Kupujący** ma opcję wykonania, podczas gdy **sprzedający** jest zobowiązany do zrealizowania transakcji, jeśli kupujący zdecyduje się skorzystać z opcji.

### 2. **Ryzyko:**

* **Futures:** Zarówno kupujący, jak i sprzedający ponoszą **nieograniczone ryzyko**, ponieważ są zobowiązani do zrealizowania kontraktu. Ryzyko to różnica między uzgodnioną ceną a ceną rynkową w dniu wygaśnięcia.
* **Opcje:** Ryzyko kupującego jest ograniczone do **premii** zapłaconej za zakup opcji. Jeśli rynek nie poruszy się na korzyść posiadacza opcji, mogą po prostu pozwolić opcji wygasnąć. Jednak **sprzedający** (wystawca) opcji ma nieograniczone ryzyko, jeśli rynek poruszy się znacząco przeciwko nim.

### 3. **Koszt:**

* **Futures:** Nie ma kosztu początkowego poza marżą wymaganą do utrzymania pozycji, ponieważ zarówno kupujący, jak i sprzedający są zobowiązani do zrealizowania transakcji.
* **Opcje:** Kupujący musi zapłacić **premię opcyjną** z góry za prawo do skorzystania z opcji. Ta premia jest zasadniczo kosztem opcji.

### 4. **Potencjał Zysku:**

* **Futures:** Zysk lub strata opiera się na różnicy między ceną rynkową w dniu wygaśnięcia a uzgodnioną ceną w kontrakcie.
* **Opcje:** Kupujący zyskuje, gdy rynek porusza się korzystnie ponad cenę wykonania o więcej niż zapłacona premia. Sprzedający zyskuje, zatrzymując premię, jeśli opcja nie zostanie zrealizowana.

{{#include /banners/hacktricks-training.md}}
