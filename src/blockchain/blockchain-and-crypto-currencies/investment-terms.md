# Terminy inwestycyjne

{{#include ../../banners/hacktricks-training.md}}

## Handel spot

Handel spot polega na wymianie aktywa z natychmiastową dostawą. Zlecenie z limitem określa ilość i cenę graniczną; zostaje zrealizowane tylko wtedy, gdy rynek może spełnić ten warunek cenowy lub zaoferować lepszą cenę. Zlecenie rynkowe ma na celu szybkie wykonanie po najlepszych dostępnych cenach i może wiązać się z poślizgiem cenowym.<sup>[[4]](#references)</sup>

Zlecenie stop-limit ma cenę stop, która aktywuje zlecenie z limitem. Może ograniczyć cenę realizacji, ale nie gwarantuje realizacji, jeśli rynek przekroczy limit.<sup>[[4]](#references)</sup>

## Kontrakty futures

Kontrakt futures to standaryzowana umowa kupna lub sprzedaży określonego towaru albo instrumentu finansowego w przyszłym terminie. Na przykład dwie strony mogą uzgodnić cenę 70 000 USD za jednego bitcoina, z rozliczeniem za sześć miesięcy.<sup>[[1]](#references)</sup>

Jeśli cena rozliczeniowa wynosi 80 000 USD, strona długa zyskuje, a strona krótka traci względem ceny kontraktowej 70 000 USD. Jeśli wynosi 60 000 USD, sytuacja jest odwrotna. Rzeczywiste kontrakty futures notowane na giełdzie są wyceniane rynkowo i zwykle zamykane lub rolowane przed wygaśnięciem, więc jest to uproszczony przykład.<sup>[[2]](#references)</sup>

Producenci i konsumenci używają kontraktów futures do zabezpieczania się przed ryzykiem cenowym; inni uczestnicy wykorzystują je, by osiągać zyski lub zapewniać płynność.<sup>[[1]](#references)</sup>

- **Pozycja długa** zazwyczaj przynosi zysk, gdy cena kontraktu rośnie.
- **Pozycja krótka** zazwyczaj przynosi zysk, gdy cena kontraktu spada.<sup>[[2]](#references)</sup>

### Zabezpieczanie się za pomocą kontraktów futures

Jeśli zarządzający funduszem spodziewa się spadku wartości portfela, może zająć krótką pozycję w odpowiednio skorelowanym kontrakcie futures na indeks giełdowy. Zyski z krótkiej pozycji zabezpieczającej mogą zrekompensować część strat portfela; ryzyko bazy sprawia, że kompensacja rzadko jest dokładna. Kontrakt futures na bitcoina zabezpiecza ekspozycję na bitcoina, a nie automatycznie portfel akcji.

Jeśli zabezpieczany rynek spada, krótka pozycja w kontrakcie futures może zyskiwać, podczas gdy wartość posiadanych aktywów maleje. Jeśli rynek rośnie, wartość posiadanych aktywów może wzrosnąć, a zabezpieczenie przynieść stratę. Zabezpieczanie ogranicza wybrane rodzaje ryzyka, ale nie gwarantuje zysku.<sup>[[1]](#references)</sup>

### Kontrakty perpetual futures

Kontrakty perpetual to instrumenty pochodne bez ustalonej daty wygaśnięcia. Platformy kryptowalutowe często stosują okresowe płatności fundingowe, aby utrzymać ich cenę w pobliżu bazowej ceny spot; warunki różnią się w zależności od platformy.<sup>[[3]](#references)</sup>

Zysk i strata zmieniają się wraz ze zmianą ceny mark. Ruch ceny o 1% powoduje w przybliżeniu zmianę o 1% wartości nominalnej pozycji, przed uwzględnieniem opłat i płatności fundingowych, ale dźwignia może sprawić, że zmiana ta będzie znacznie większa w stosunku do wniesionego zabezpieczenia.

### Kontrakty futures z dźwignią

**Dźwignia** pozwala traderowi kontrolować pozycję o większej wartości nominalnej przy mniejszym depozycie zabezpieczającym. Straty nie zawsze są ograniczone do początkowego depozytu: likwidacja, luki cenowe, opłaty i zasady platformy mogą prowadzić do dodatkowych strat.<sup>[[3]](#references)</sup>

Na przykład depozyt zabezpieczający w wysokości 100 USD przy dźwigni 50x pozwala kontrolować pozycję o wartości 5 000 USD. Pomijając opłaty, płatności fundingowe i mechanikę likwidacji, korzystny ruch o 1% przynosi zysk w wysokości 50 USD (50% początkowego depozytu zabezpieczającego), a niekorzystny ruch o 1% powoduje stratę w wysokości 50 USD. Niekorzystny ruch o 2% oznacza stratę 100 USD, choć platforma zazwyczaj zlikwiduje pozycję, zanim cały depozyt zabezpieczający zostanie wykorzystany.

Dźwignia powiększa zarówno zyski, jak i straty oraz sprawia, że likwidacja może nastąpić po stosunkowo niewielkim niekorzystnym ruchu ceny.

## Różnice między kontraktami futures a opcjami

Kupujący opcję otrzymuje prawo, ale nie obowiązek, do jej realizacji zgodnie z warunkami kontraktu. Wystawca opcji ma odpowiadający temu obowiązek, jeśli kupujący skorzysta z opcji. Kupujący płaci wystawcy premię za to prawo.<sup>[[4]](#references)</sup>

### 1. **Obowiązek a prawo:**

* **Kontrakty futures:** Kupując lub sprzedając kontrakt futures, zawierasz **wiążącą umowę** kupna lub sprzedaży aktywa po określonej cenie w przyszłym terminie. Zarówno kupujący, jak i sprzedający są **zobowiązani** do wykonania kontraktu w terminie wygaśnięcia (chyba że wcześniej go zamkną).
* **Opcje:** W przypadku opcji masz **prawo, ale nie obowiązek**, kupna (w przypadku **opcji call**) lub sprzedaży (w przypadku **opcji put**) aktywa po określonej cenie przed określonym terminem wygaśnięcia lub w tym terminie. **Kupujący** może zdecydować o realizacji opcji, natomiast **sprzedający** jest zobowiązany do wykonania transakcji, jeśli kupujący zdecyduje się skorzystać z opcji.

### 2. **Ryzyko:**

* **Kontrakty futures:** Obie strony mogą ponieść znaczne straty. To, czy strata jest matematycznie nieograniczona, zależy od pozycji i aktywa bazowego: krótka pozycja może wiązać się z teoretycznie nieograniczoną stratą, natomiast długa pozycja nie może stracić więcej niż wartość nominalna, jeśli wartość aktywa bazowego nie może spaść poniżej zera.
* **Opcje:** Kupujący, który nie wystawia innej opcji, ryzykuje zazwyczaj utratę zapłaconej premii. Wystawca niepokrytej opcji call może ponieść teoretycznie nieograniczoną stratę; inne strategie wystawiania opcji wiążą się z różnymi profilami ryzyka ograniczonego lub nieograniczonego.

### 3. **Koszt:**

* **Kontrakty futures:** Nie ma kosztu początkowego poza depozytem zabezpieczającym wymaganym do utrzymania pozycji, ponieważ zarówno kupujący, jak i sprzedający są zobowiązani do realizacji transakcji.
* **Opcje:** Kupujący musi z góry zapłacić **premię opcyjną** za prawo do realizacji opcji. Premia ta stanowi zasadniczo koszt opcji.

### 4. **Potencjał zysku:**

* **Kontrakty futures:** Zysk lub strata zależą od różnicy między ceną rynkową w terminie wygaśnięcia a ceną uzgodnioną w kontrakcie.
* **Opcje:** Kupujący osiąga zysk, gdy rynek porusza się w korzystnym kierunku i przekracza cenę wykonania o więcej niż zapłacona premia. Sprzedający osiąga zysk, zatrzymując premię, jeśli opcja nie zostanie zrealizowana.

## References

- [1] [CFTC - Cel ekonomiczny rynków futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Podstawy rynku futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Zrozum ryzyko handlu wirtualnymi walutami](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC Glossary - Opcja, premia i realizacja](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
