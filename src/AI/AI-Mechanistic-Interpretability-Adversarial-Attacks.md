# Adwersarialne ataki kierowane interpretowalnością mechanistyczną

{{#include ../banners/hacktricks-training.md}}

## Superpozycja jako powierzchnia ataku

Niedostatecznie sparametryzowana przestrzeń aktywacji może kodować więcej cech semantycznych, niż ma wymiarów, przypisując cechom nieortogonalne wektory. W rezultacie aktywowana cecha rzutuje się również na kierunki innych cech. Trening może kompensować kombinacje obserwowane w rozkładzie danych, ale nietypowa kombinacja poprawnych skądinąd cech może konstruktywnie wzmocnić sygnał w kierunku cechy docelowej, której nie ma w wejściu.<sup>[[1]](#references)[[2]](#references)</sup>

Dla wektorów cech `v_i ∈ R^D`, aktywacji `a_i` i celu `t` poniższa wartość jest przydatna do znajdowania potencjalnych kombinacji:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

To jedynie heurystyka wstępnej selekcji. Exploit musi zachować znaki i wartości oraz uwzględniać działanie rzeczywistego dekodera, na przykład `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` w liniowym dekoderze ze współdzielonymi wagami. Ujemne składniki mogą zniwelować atak, a bias dekodera, normy wektorów cech, progi aktywacji i bramkowanie ReLU mogą sprawić, że duża bezwzględna wartość cosinusa nie doprowadzi do aktywacji cechy docelowej.<sup>[[1]](#references)</sup>

## Przepływ pracy ataku white-box

Praktyczna ocena może wykorzystywać wąskie gardło modelu, rzadki autoenkoder (SAE) lub inny interpretowalny słownik cech. Celem nie jest jedynie zmiana klasy końcowej, lecz sprawienie, by rekonstrukcja wprowadziła wybraną cechę wewnętrzną, która nie była aktywna przed kompresją. Proponowany przepływ pracy:<sup>[[1]](#references)</sup>

1. **Odzyskaj kierunki cech:** wyodrębnij odpowiednie wektory enkodera/dekodera, usuń martwe cechy i powiąż aktywne kierunki z pojęciami za pomocą próbek maksymalizujących aktywację lub analizy obwodów cech.
2. **Uszereguj interferencje:** znormalizuj kopię wektorów, oblicz ich macierz podobieństwa cosinusowego, wyzeruj diagonalę i sprawdź najsilniej powiązane cechy poza diagonalą względem cechy docelowej. Ponownie oblicz wyniki dla kandydatów, używając rzeczywistych wartości aktywacji i surowych iloczynów skalarnych z uwzględnieniem znaków.
3. **Wymuś jednoczesną aktywację:** zachowaj niewielki zbiór cech o dodatnim wkładzie, które mogą być aktywowane w tej samej warstwie lub strumieniu resztowym. Preferuj kombinacje rzadkie lub nieobecne w danych treningowych; zwykłe, skorelowane kombinacje z większym prawdopodobieństwem zostały skompensowane podczas treningu.
4. **Zsyntetyzuj dane wejściowe:** połącz przykłady ze zbioru danych lub wzorce maksymalizujące aktywację dla wybranych składników. W przypadku ograniczonego liniowego detektora pikseli ustaw piksel na wysoką wartość dla dodatniej wagi, a na niską dla ujemnej, po czym nałóż na siebie uzyskane wzorce. Ręczne zachowanie struktury zgodnej z rozkładem danych i hamującej **negatywnej przestrzeni** może stłumić niezwiązane cechy.
5. **Zweryfikuj mechanizm:** zarejestruj aktywacje przed kompresją, współrzędne po kompresji, zrekonstruowane aktywacje i wynik dalszego przetwarzania w jednym przebiegu forward. Pomyślny test wykaże, że cecha docelowa jest nieaktywna przed rekonstrukcją, ale aktywna po niej, a przewidywana zmiana znika po ablacji składników.

Poniższa minimalna procedura selekcji szereguje składniki dla dekodera ze współdzielonymi wagami, którego **wiersze** są wektorami cech (jeśli cechy są kolumnami, najpierw wykonaj transpozycję). Do obliczenia wyniku z uwzględnieniem znaków używaj surowych wag, a do rankingu cosinusowego — wag znormalizowanych.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Nie wnioskuj o możliwości wykorzystania podatności wyłącznie na podstawie podobieństwa cosinusowego. Przetestuj cały dekoder wraz z jego biasem i nieliniowością, potwierdź, że elementy wnoszące wkład mogą rzeczywiście współwystępować, i porównaj je z dopasowanymi kombinacjami z rozkładu wejściowego. Podobne kierunki mogą kodować uzasadnioną relację semantyczną, a nie podatne na wykorzystanie zakłócenia wynikające z upakowania.<sup>[[1]](#references)</sup>

## Zademonstrowany atak na modelu zabawkowym

W proof of concept wykorzystano celowo łatwy do interpretacji klasyfikator MNIST z dwiema gałęziami. Rzadki, 128-wymiarowy wektor cech ReLU był bezpośrednio klasyfikowany w jednej gałęzi, a w drugiej kompresowany do dwuwymiarowej przestrzeni superpozycji; ten sam klasyfikator przetwarzał zarówno oryginalne, jak i odtworzone cechy.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Dwa kierunki cech związane z kształtami podobnymi do 3/0 były geometrycznie otoczone kierunkami klasy 5. Dodanie ich obrazów maksymalnie aktywujących sprawiło, że cechy tych kierunków były najsilniejsze przed kompresją, ale rekonstrukcja aktywowała kilka cech klasy 5, a gałąź superpozycji przewidziała 5. Ręcznie narysowane wejście, wykorzystujące wyłącznie minimalne i maksymalne wartości pikseli, dało ten sam efekt, co pokazało, że w tym toy setting nie były potrzebne dokładne perturbacje pikseli zoptymalizowane za pomocą gradientu.<sup>[[1]](#references)</sup>

## Większy model: geometryczna selekcja

W pracy zbadano również SAE Gemma Scope `layer 20 / width 65k / average L0 20`. Pomnożono znormalizowaną do długości jednostkowej macierz dekodera przez jej transpozycję, wyzerowano przekątną, posortowano sąsiadów każdej cechy i obliczono średnią dla każdej rangi. Średnie cosinusowe podobieństwo do najsilniejszego sąsiada wyniosło `0.49`, a średnie podobieństwo do 27. sąsiada — `0.25`; geometrycznie cztery takie kierunki mogłyby dopasować się do projekcji docelowej jednostki. Wartości te wskazują jedynie kandydatów — nie dowodzą, że można wspólnie aktywować cztery odpowiednie cechy ani że cel przekroczy próg dekodera.<sup>[[1]](#references)</sup>

## Zakres i ograniczenia

Jest to technika na etapie badań, typu **white-box**, a nie zademonstrowany atak na wdrożony CNN lub czołowy LLM. Wymaga superpozycji, użytecznych nieortogonalnych kierunków, interpretowalnego dostępu do cech wewnętrznych, możliwości kontrolowania aktywacji cech składowych oraz ich współwystępowania w tej samej warstwie podczas jednego przebiegu forward pass.<sup>[[1]](#references)</sup>

MLP w modelach obrazowych sprawiają, że składanie cech jest wyjątkowo bezpośrednie. W transformerze jest to trudniejsze, ponieważ attention musi zebrać wybrane aktywacje cech w tym samym strumieniu resztkowym; praca nie pokazuje, jak wymusić to dla kombinacji spoza rozkładu. Twierdzenia dotyczące manipulowania kierunkami behawioralnymi lub odmowy, fizycznych systemów wizyjnych bądź czołowych modeli pozostają zatem hipotezami.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson i Anley — Wstępne badanie interpretowalnych ataków adwersarialnych poprzez interferencję cech w superpozycji (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretowalne ataki adwersarialne w superpozycji](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
