# Terminologia inwestycyjna

{{#include ../../banners/hacktricks-training.md}}

## Rynek spot

Handel spot polega na wymianie aktywów z natychmiastową dostawą. Zlecenie z limitem określa ilość i cenę graniczną; jest realizowane tylko wtedy, gdy rynek może zaoferować tę cenę lub lepszą. Zlecenie rynkowe ma na celu natychmiastową realizację po najlepszych dostępnych cenach i może wiązać się z poślizgiem cenowym.<sup>[[4]](#references)</sup>

Zlecenie stop-limit ma cenę stop, która aktywuje zlecenie z limitem. Może ograniczyć cenę realizacji, ale nie gwarantuje realizacji, jeśli rynek przekroczy limit.<sup>[[4]](#references)</sup>

## Kontrakty futures

Kontrakt futures to standardowa umowa kupna lub sprzedaży określonego towaru albo instrumentu finansowego w przyszłym terminie. Na przykład dwie strony mogą uzgodnić cenę 70 000 USD za jednego bitcoina, z rozliczeniem za sześć miesięcy.<sup>[[1]](#references)</sup>

Jeśli cena rozliczeniowa wynosi 80 000 USD, strona długa zyskuje, a krótka traci w stosunku do ceny kontraktowej 70 000 USD. Jeśli wynosi 60 000 USD, sytuacja jest odwrotna. Kontrakty futures notowane na giełdzie są na bieżąco wyceniane według rynku i zwykle zamykane lub rolowane przed wygaśnięciem, więc jest to uproszczony przykład.<sup>[[2]](#references)</sup>

Producenci i konsumenci używają kontraktów futures do zabezpieczania się przed ryzykiem cenowym; inni uczestnicy wykorzystują je, by szukać zysku lub zapewniać płynność.<sup>[[1]](#references)</sup>

- **Pozycja długa** zwykle przynosi zysk, gdy cena kontraktu rośnie.
- **Pozycja krótka** zwykle przynosi zysk, gdy cena kontraktu spada.<sup>[[2]](#references)</sup>

### Zabezpieczanie się za pomocą kontraktów futures

Jeśli zarządzający funduszem przewiduje spadek wartości portfela, może zająć krótką pozycję w kontrakcie futures na indeks giełdowy, który jest z nim dostatecznie skorelowany. Zyski z krótkiej pozycji zabezpieczającej mogą zrównoważyć część strat portfela; ryzyko bazy sprawia, że kompensacja rzadko jest dokładna. Kontrakt futures na bitcoina zabezpiecza ekspozycję na bitcoina, a nie automatycznie portfel akcji.

Jeśli zabezpieczany rynek spada, krótka pozycja w kontraktach futures może przynieść zysk, podczas gdy wartość aktywów w portfelu spada. Jeśli rynek rośnie, wartość aktywów może wzrosnąć, a zabezpieczenie przynieść stratę. Zabezpieczanie ogranicza wybrane ryzyko, ale nie gwarantuje zysku.<sup>[[1]](#references)</sup>

### Kontrakty perpetual futures

Kontrakty perpetual to instrumenty pochodne bez ustalonej daty wygaśnięcia. Platformy kryptowalutowe często stosują okresowe płatności fundingowe, aby utrzymać ich cenę blisko bazowej ceny spot; warunki różnią się w zależności od platformy.<sup>[[3]](#references)</sup>

Testy nadużyć związanych ze stopą fundingową w on-chain protokołach perpetual znajdziesz w sekcji [Wykorzystywanie stopy fundingowej w kontraktach perpetual](perpetual-funding-rate-exploitation.md).

Zysk i strata zmieniają się wraz ze zmianą ceny mark. Zmiana ceny o 1% powoduje w przybliżeniu zmianę o 1% wartości nominalnej pozycji przed uwzględnieniem opłat i funding, ale dźwignia może sprawić, że będzie to znacznie większy procent wniesionego zabezpieczenia.

### Kontrakty futures z dźwignią

**Dźwignia finansowa** pozwala traderowi kontrolować pozycję o większej wartości nominalnej przy mniejszym depozycie zabezpieczającym. Straty nie zawsze są ograniczone do początkowego depozytu: likwidacja, luki cenowe, opłaty i zasady platformy mogą prowadzić do dodatkowych strat.<sup>[[3]](#references)</sup>

Na przykład depozyt w wysokości 100 USD przy dźwigni 50x pozwala kontrolować pozycję o wartości 5 000 USD. Pomijając opłaty, funding i mechanizmy likwidacji, korzystna zmiana o 1% przynosi zysk w wysokości 50 USD (50% początkowego depozytu), a niekorzystna zmiana o 1% powoduje stratę 50 USD. Niekorzystna zmiana o 2% odpowiada kwocie 100 USD, ale platforma zazwyczaj zlikwiduje pozycję, zanim cały depozyt zostanie wyczerpany.

Dźwignia powiększa zarówno zyski, jak i straty, a przy stosunkowo niewielkim niekorzystnym ruchu może doprowadzić do likwidacji.

## Różnice między kontraktami futures a opcjami

Kupujący opcję otrzymuje prawo, a nie obowiązek, do jej wykonania zgodnie z warunkami kontraktu. Wystawca opcji ma odpowiadający mu obowiązek, jeśli kupujący zdecyduje się ją wykonać. Kupujący płaci wystawcy premię za to prawo.<sup>[[4]](#references)</sup>

### 1. **Obowiązek a prawo:**

* **Kontrakty futures:** Kupując lub sprzedając kontrakt futures, zawierasz **wiążącą umowę** kupna lub sprzedaży aktywa po określonej cenie w przyszłym terminie. Zarówno kupujący, jak i sprzedający są **zobowiązani** do realizacji kontraktu w dniu wygaśnięcia (chyba że zostanie on wcześniej zamknięty).
* **Opcje:** W przypadku opcji masz **prawo, ale nie obowiązek**, do kupna (w przypadku **opcji call**) lub sprzedaży (w przypadku **opcji put**) aktywa po określonej cenie przed upływem określonego terminu lub w tym terminie. **Kupujący** może zdecydować o wykonaniu opcji, a **sprzedający** jest zobowiązany do realizacji transakcji, jeśli kupujący postanowi ją wykonać.

### 2. **Ryzyko:**

* **Kontrakty futures:** Obie strony mogą ponieść znaczne straty. To, czy strata jest matematycznie nieograniczona, zależy od pozycji i aktywa bazowego: krótka pozycja może wiązać się z teoretycznie nieograniczoną stratą, natomiast na długiej pozycji nie można stracić więcej niż jej wartość nominalna, jeśli wartość aktywa bazowego nie może spaść poniżej zera.
* **Opcje:** Kupujący, który nie wystawia innej opcji, ryzykuje zazwyczaj utratę zapłaconej premii. Wystawca niepokrytej opcji call może ponieść teoretycznie nieograniczoną stratę; inne strategie wystawiania opcji wiążą się z różnymi ograniczonymi lub nieograniczonymi profilami ryzyka.

### 3. **Koszt:**

* **Kontrakty futures:** Nie ma kosztu początkowego poza depozytem zabezpieczającym wymaganym do utrzymania pozycji, ponieważ zarówno kupujący, jak i sprzedający są zobowiązani do realizacji transakcji.
* **Opcje:** Kupujący musi z góry zapłacić **premię opcyjną** za prawo do wykonania opcji. Premia ta stanowi koszt opcji.

### 4. **Potencjał zysku:**

* **Kontrakty futures:** Zysk lub strata zależą od różnicy między ceną rynkową w dniu wygaśnięcia a ceną uzgodnioną w kontrakcie.
* **Opcje:** Kupujący osiąga zysk, gdy rynek poruszy się w korzystnym kierunku o więcej niż wartość zapłaconej premii, przekraczając cenę wykonania. Sprzedający osiąga zysk, zatrzymując premię, jeśli opcja nie zostanie wykonana.

## References

- [1] [CFTC - Cel ekonomiczny rynków futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Podstawy rynku futures](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Poznaj ryzyko związane z handlem wirtualnymi walutami](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Słownik CFTC - Opcja, premia i wykonanie](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
