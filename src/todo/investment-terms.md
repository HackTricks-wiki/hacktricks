# Terminy inwestycyjne

{{#include ../banners/hacktricks-training.md}}

## Spot

Trading spot polega na wymianie aktywa z natychmiastową dostawą. Zlecenie z limitem określa ilość i cenę limitu; jest realizowane tylko wtedy, gdy rynek może spełnić tę cenę lub zaoferować lepszą. Zlecenie rynkowe dąży natomiast do szybkiej realizacji po najlepszych dostępnych cenach i może wiązać się z poślizgiem cenowym.<sup>[[4]](#references)</sup>

Zlecenie stop-limit ma cenę stop, która aktywuje zlecenie z limitem. Może ograniczać cenę realizacji, ale nie gwarantuje realizacji, jeśli rynek przekroczy ustalony limit.<sup>[[4]](#references)</sup>

## Futures

Kontrakt futures to ustandaryzowana umowa kupna lub sprzedaży określonego towaru albo instrumentu finansowego w przyszłym terminie. Przykładowo dwie strony mogą uzgodnić cenę 70 000 USD za jednego bitcoina z rozliczeniem za sześć miesięcy.<sup>[[1]](#references)</sup>

Jeśli cena rozliczeniowa wynosi 80 000 USD, strona długa zyskuje, a strona krótka traci w porównaniu z kontraktową ceną 70 000 USD. Jeśli wynosi 60 000 USD, sytuacja jest odwrotna. Rzeczywiste futures notowane na giełdzie są wyceniane rynkowo i zwykle zamykane lub rolowane przed wygaśnięciem, więc jest to uproszczona ilustracja.<sup>[[2]](#references)</sup>

Producenci i konsumenci używają futures do zabezpieczania ryzyka cenowego; inni uczestnicy wykorzystują je w celu osiągania zysku lub zapewniania płynności.<sup>[[1]](#references)</sup>

- **Pozycja długa** zasadniczo przynosi zysk, gdy cena kontraktu rośnie.
- **Pozycja krótka** zasadniczo przynosi zysk, gdy cena kontraktu spada.<sup>[[2]](#references)</sup>

### Zabezpieczanie za pomocą futures

Jeśli zarządzający funduszem spodziewa się spadku wartości portfela, może otworzyć krótką pozycję w wystarczająco skorelowanym kontrakcie futures na indeks akcji. Zyski z krótkiego zabezpieczenia mogą zrekompensować część strat portfela; ryzyko bazy oznacza, że kompensacja rzadko jest dokładna. Futures na bitcoina zabezpiecza ekspozycję na bitcoina, a nie automatycznie portfel akcji.

Jeśli zabezpieczany rynek spada, krótka pozycja futures może zyskiwać, podczas gdy posiadane aktywa tracą na wartości. Jeśli rynek rośnie, posiadane aktywa mogą zyskiwać, podczas gdy zabezpieczenie przynosi straty. Zabezpieczanie zmniejsza wybrane ryzyko, zamiast zapewniać gwarantowany zysk.<sup>[[1]](#references)</sup>

### Perpetual Futures

Kontrakty perpetual to instrumenty pochodne bez ustalonej daty wygaśnięcia. Platformy kryptowalutowe powszechnie stosują okresowe płatności fundingowe, aby utrzymywać ich cenę blisko bazowej ceny spot; warunki różnią się w zależności od platformy.<sup>[[3]](#references)</sup>

Zysk i strata zmieniają się wraz ze zmianą ceny mark. Zmiana ceny o 1% powoduje w przybliżeniu zmianę o 1% wartości nominalnej pozycji przed uwzględnieniem opłat i funding, ale dźwignia może sprawić, że będzie to znacznie większy procent wniesionego zabezpieczenia.

### Futures z dźwignią

**Dźwignia** pozwala traderowi kontrolować większą pozycję nominalną przy mniejszym depozycie zabezpieczającym. Straty nie zawsze ograniczają się do początkowego depozytu: likwidacja, luki cenowe, opłaty i zasady platformy mogą prowadzić do dodatkowych strat.<sup>[[3]](#references)</sup>

Przykładowo depozyt zabezpieczający w wysokości 100 USD przy dźwigni 50x kontroluje pozycję o wartości 5000 USD. Pomijając opłaty, funding i mechanizmy likwidacji, korzystna zmiana o 1% przynosi zysk 50 USD (50% początkowego depozytu), natomiast niekorzystna zmiana o 1% powoduje stratę 50 USD. Niekorzystna zmiana o 2% odpowiada kwocie 100 USD, jednak platforma zazwyczaj zlikwiduje pozycję, zanim cały depozyt zostanie wykorzystany.

Dźwignia zwiększa zarówno zyski, jak i straty oraz umożliwia likwidację po relatywnie niewielkiej niekorzystnej zmianie ceny.

## Różnice między futures a opcjami

Nabywca opcji otrzymuje prawo, a nie obowiązek, do wykonania jej na warunkach określonych w kontrakcie. Wystawca opcji ma odpowiadający temu obowiązek, jeśli nabywca wykona opcję. Nabywca płaci wystawcy premię za to prawo.<sup>[[4]](#references)</sup>

### 1. **Obowiązek a prawo:**

* **Futures:** Kupując lub sprzedając kontrakt futures, zawierasz **wiążącą umowę** kupna lub sprzedaży aktywa po określonej cenie w przyszłym terminie. Zarówno kupujący, jak i sprzedający są **zobowiązani** do wykonania kontraktu w dniu wygaśnięcia, chyba że kontrakt zostanie wcześniej zamknięty.
* **Opcje:** W przypadku opcji masz **prawo, ale nie obowiązek**, kupna (w przypadku **opcji call**) lub sprzedaży (w przypadku **opcji put**) aktywa po określonej cenie przed określonym terminem wygaśnięcia lub w tym terminie. **Nabywca** ma możliwość wykonania opcji, natomiast **sprzedający** jest zobowiązany do realizacji transakcji, jeśli nabywca zdecyduje się wykonać opcję.

### 2. **Ryzyko:**

* **Futures:** Obie strony mogą ponieść znaczne straty. To, czy strata jest matematycznie nieograniczona, zależy od pozycji i aktywa bazowego: pozycja krótka może wiązać się z teoretycznie nieograniczoną stratą, natomiast pozycja długa nie może przynieść straty większej niż wartość nominalna, jeśli aktywo bazowe nie może spaść poniżej zera.
* **Opcje:** Nabywca, który nie wystawia innej opcji, zasadniczo ryzykuje zapłaconą premię. Wystawca nagiej opcji call może ponieść teoretycznie nieograniczoną stratę; inne strategie wystawiania opcji mają różne profile ryzyka — ograniczone lub nieograniczone.

### 3. **Koszt:**

* **Futures:** Nie ma kosztu początkowego poza depozytem zabezpieczającym wymaganym do utrzymania pozycji, ponieważ kupujący i sprzedający są zobowiązani do sfinalizowania transakcji.
* **Opcje:** Nabywca musi z góry zapłacić **premię opcyjną** za prawo wykonania opcji. Premia ta jest zasadniczo kosztem opcji.

### 4. **Potencjał zysku:**

* **Futures:** Zysk lub strata zależy od różnicy między ceną rynkową w dniu wygaśnięcia a uzgodnioną ceną kontraktu.
* **Opcje:** Nabywca osiąga zysk, gdy rynek porusza się korzystnie poza cenę wykonania o wartość większą niż zapłacona premia. Sprzedający osiąga zysk, zatrzymując premię, jeśli opcja nie zostanie wykonana.

## References

- [1] [CFTC - Ekonomiczny cel rynków futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Podstawy rynku futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Zrozumienie ryzyka handlu wirtualnymi walutami](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Opcja, premia i wykonanie](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
