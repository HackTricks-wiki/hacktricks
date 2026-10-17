# Ataki Side-Channel Analysis

{{#include ../../banners/hacktricks-training.md}}

Ataki side-channel odzyskują sekrety przez obserwowanie fizycznego lub mikroarchitektonicznego „leakage”, które jest *skorelowane* ze stanem wewnętrznym, ale nie należy do logicznego interfejsu urządzenia. Przykłady obejmują pomiar chwilowego poboru prądu przez kartę inteligentną oraz wykorzystywanie przez sieć efektów zarządzania energią procesora.

W przypadku celu z dostępnym sprzętem debugującym ARM, [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md) może dostarczyć odniesienie do ścieżki wykonania, które można zestawić z pomiarami poboru mocy lub emisji EM; jest to ślad debugowania, a nie kanał leakage.<sup>[[17]](#references)</sup>

---

## Główne kanały leakage

| Kanał | Typowy cel | Aparatura pomiarowa |
|---------|---------------|-----------------|
| Pobór mocy | Karty inteligentne, mikrokontrolery IoT, FPGA | Oscyloskop oraz rezystor bocznikowy lub sonda różnicowa; CW503 to zasilacz do sond/LNA, a nie sama sonda<sup>[[11]](#references)</sup> |
| Pole elektromagnetyczne (EM) | Procesory, RFID, akceleratory AES | Sonda pola H/bliskiego pola oraz wzmacniacz niskoszumowy i oscyloskop lub odbiornik SDR, taki jak RTL-SDR<sup>[[13]](#references)</sup> |
| Czas wykonania / cache | Procesory komputerów stacjonarnych i chmurowe | Precyzyjne zegary (`rdtsc`/`rdtscp`) lub zdalny pomiar czasu przelotu |
| Akustyka / mechanika | Klawiatury, drukarki 3D, drukarki, przekaźniki i regulatory napięcia procesora | Mikrofon MEMS lub wibrometr laserowy<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optyka i temperatura | Diody LED stanu, wyświetlacze, DRAM i urządzenia sprzężone termicznie | Fotodioda, kamera szybkoklatkowa lub kamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Kryptografia ASIC/MCU | Glitch zegara/napięcia, EMFI lub iniekcja laserowa |

---

## Analiza poboru mocy

### Simple Power Analysis (SPA)
Obserwuj *pojedynczy* ślad i przypisuj widoczne cechy do operacji, takich jak skoki, mnożenie modularne lub różne sekwencje instrukcji.<sup>[[1]](#references)</sup>

Dokładna konfiguracja zależy od celu. Poniższy przykład korzysta z aktualnego, wysokopoziomowego API przechwytywania ChipWhisperer po podłączeniu i skonfigurowaniu oscyloskopu oraz celu:<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
Pozyskaj wiele trace’ów, postaw hipotezę dotyczącą bajtu klucza `k`, oblicz model wycieku oparty na wadze Hamminga (HW) lub odległości Hamminga (HD) i skoreluj go z każdą próbką. Wymagana liczba trace’ów zależy od celu, szumu, wyrównania, środków zaradczych i modelu leakage; nie jest stałym progiem.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA to standardowa metoda bazowa. Template attacks, analiza wzajemnej informacji i metody uczenia maszynowego mogą być przydatne, gdy wyciek ma charakter nieliniowy lub ślady są słabo wyrównane.

---

## Analiza elektromagnetyczna (EMA)
Analiza pola bliskiego może wykrywać aktywność zależną od danych bez wstawiania bocznika w tor zasilania. Niekoniecznie ujawnia ten sam sygnał co ślad poboru mocy: znaczenie mają położenie i orientacja sondy, szerokość pasma, wzmocnienie toru wejściowego, jakość wyzwalania i odległość.

---

## Ataki czasowe i mikroarchitektoniczne
Nowoczesne procesory ujawniają sekrety przez współdzielone zasoby:
* **Hertzbleed (2022)** – zależne od danych dynamiczne skalowanie napięcia i częstotliwości tworzy zdalny kanał czasowy. Pierwotna demonstracja odzyskiwania klucza w scenariuszu end-to-end dotyczyła SIKE; późniejsze prace omawiają inne prymitywy kryptograficzne.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – wykonanie spekulatywne może ujawnić dane używane przez instrukcje wektorowe gather ponad granicami zabezpieczeń.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – nieprawidłowa obsługa spekulatywnego stanu rejestrów wektorowych może ujawnić dane z tego samego fizycznego rdzenia.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – atak wykorzystujący wykonanie spekulatywne łączy phantom execution z trenowaniem w ramach wykonania spekulatywnego, aby utworzyć gadżety błędnej predykcji kontrolowane przez atakującego.<sup>[[5]](#references)</sup>

---

## Ataki akustyczne i optyczne
W kontrolowanym eksperymencie wykorzystano wyciek akustyczny do odzyskania kluczy RSA z szumu laptopa, także za pomocą mikrofonu pobliskiego telefonu komórkowego.<sup>[[6]](#references)</sup> W odrębnym badaniu klawiatur z 2023 r. sklasyfikowano naciśnięcia klawiszy z dokładnością 95% po wytrenowaniu na nagraniach z pobliskiego telefonu oraz 93% po wytrenowaniu na dźwięku z Zooma; wartości te dotyczą eksperymentu z wytrenowanym urządzeniem opisanego w tej pracy, a nie dowolnej klawiatury lub ofiary.<sup>[[9]](#references)</sup> Emisje optyczne diod sygnalizacyjnych można również korelować z przetwarzanymi danymi. Wyniki te zależą od celu i konfiguracji; nie należy uogólniać ich zasięgu ani skuteczności na niepowiązane urządzenia.<sup>[[7]](#references)</sup>

---

## Fault Injection i Differential Fault Analysis (DFA)
Połączenie kontrolowanego wstrzykiwania błędów z obserwacjami kanału bocznego może ograniczyć zakres poszukiwania klucza dla niektórych algorytmów i implementacji. Do typowych platform laboratoryjnych należą funkcje glitchingu napięcia i zegara w ChipWhisperer oraz dedykowane narzędzia do wstrzykiwania błędów EM, takie jak ChipSHOUTER lub PicoEMP. Opisu „poniżej 1 ns” z wcześniejszej wersji nie należy traktować jako specyfikacji: opublikowana instrukcja ChipSHOUTER podaje typowe szerokości impulsów wprowadzanych do układu: **15–80 ns** dla końcówki 1 mm i **24–480 ns** dla końcówki 4 mm (choć jitter wyzwalania/impulsu jest określony w pikosekundach). Wymagana rozdzielczość czasowa, położenie sondy i liczba błędnych wyników zależą od celu i modelu błędu.<sup>[[1]](#references)[[10]](#references)</sup>

## Niezweryfikowane tropy badawcze zachowane z wcześniejszej wersji

We wcześniejszej wersji twierdzono również, że: konfiguracja EM **500 MHz–3 GHz** odzyskała klucz STM32 z odległości ponad **10 cm** przy użyciu RTL-SDR; dioda LED aktywności DDR4 ujawniła klucz rundy AES w czasie krótszym niż minuta podczas „Black Hat 2023”; oraz że w 2025 r. powstała otwartoźródłowa platforma glitchingu RISC-V o nazwie **GlitchKit-R5**. Podczas tego audytu nie udało się znaleźć odpowiadającej tym twierdzeniom publikacji pierwotnej, materiałów konferencyjnych ani repozytorium projektu. Te szczegółowe informacje zachowano jako tropy do wyszukiwania i odtworzenia, a nie jako potwierdzone wyniki ani rekomendacje narzędzi.

---

## Typowy przebieg ataku
1. Zidentyfikuj kanał wycieku i punkt pomiarowy (pin VCC, kondensator odsprzęgający, punkt pola bliskiego).
2. Wprowadź sygnał wyzwalający (GPIO lub oparty na wzorcu).
3. Zbierz wystarczającą liczbę śladów dla wybranego testu statystycznego, zapisując tekst jawny/szyfrogram i inne metadane.
4. Wstępnie przetwórz dane (wyrównanie, usunięcie średniej, filtr LP/HP, falki, PCA).
5. Odzyskaj klucz metodami statystycznymi lub ML (CPA, MIA, DL-SCA).
6. Zweryfikuj wyniki i powtarzaj analizę dla wartości odstających.

---

## Zabezpieczenia i wzmacnianie odporności
* Implementacje **constant-time** i algorytmy wymagające dużej ilości pamięci.
* **Masking/shuffling** – podziel sekrety na losowe udziały; odporność pierwszego rzędu certyfikowana za pomocą TVLA.
* **Ukrywanie** – pokładowe regulatory napięcia, losowy zegar, logika dual-rail, ekrany EM.
* **Wykrywanie błędów** – nadmiarowe obliczenia, podpisy progowe.
* **Operacyjne** – wyłącz DVFS/turbo w jądrach kryptograficznych, izoluj SMT, zabroń współlokowania w chmurach wielodostępnych.

---

## Narzędzia i frameworki
* **ChipWhisperer-Husky** (2024) – oscyloskop 500 MS/s + wyzwalanie Cortex-M; API Pythona jak wyżej.<sup>[[1]](#references)</sup>
* **Riscure Inspector i produkty do wstrzykiwania błędów** – komercyjne narzędzia do analizy i automatyzacji testów.
* **scaaml** – narzędzia SCA oparte na TensorFlow i zbiory danych do deep learningu.<sup>[[12]](#references)</sup>
* **pyecsca** – otwartoźródłowy zestaw narzędzi do inżynierii wstecznej implementacji ECC typu black-box za pomocą kanałów bocznych.<sup>[[8]](#references)</sup>

---

## References

- [1] [Dokumentacja ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artykuł o ataku Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: wykorzystywanie spekulatywnego pobierania danych](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: ujawnianie nowych powierzchni ataku za pomocą trenowania w ramach wykonania spekulatywnego](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Odzyskiwanie klucza RSA za pomocą akustycznej kryptoanalizy o niskiej przepustowości](https://eprint.iacr.org/2013/857.pdf)
- [7] [Wyciek informacji z emisji optycznych](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Dokumentacja artefaktu pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktyczny atak akustycznym kanałem bocznym na klawiatury oparty na deep learningu](https://arxiv.org/abs/2308.01074)
- [10] [NewAE — instrukcja obsługi ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Dokumentacja ChipWhisperer — zasilacz sondy CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Dokumentacja Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — przeprowadzanie tanich ataków elektromagnetycznym kanałem bocznym przy użyciu RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodowanie własności intelektualnej: akustyczny i magnetyczny atak kanałem bocznym na drukarkę 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — akustyczne ataki kanałem bocznym na drukarki](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Szpiegowanie temperatury za pomocą DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [Śledzenie instrukcji: śledzenie ARM na żywo za pomocą ETM, ITM i TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
