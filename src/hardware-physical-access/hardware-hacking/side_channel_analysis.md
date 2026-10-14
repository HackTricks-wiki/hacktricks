# Ataki z wykorzystaniem analizy kanałów bocznych

{{#include ../../banners/hacktricks-training.md}}

Ataki kanałami bocznymi pozwalają odzyskiwać sekrety przez obserwację fizycznych lub mikroarchitektonicznych „wycieków”, które są *skorelowane* ze stanem wewnętrznym, ale nie stanowią części logicznego interfejsu urządzenia. Przykłady obejmują pomiar chwilowego poboru prądu przez kartę inteligentną oraz wykorzystywanie efektów zarządzania energią CPU przez sieć.

---

## Główne kanały wycieków

| Kanał | Typowy cel | Aparatura |
|---------|---------------|-----------------|
| Pobór mocy | Karty inteligentne, mikrokontrolery IoT, FPGA | Oscyloskop i rezystor pomiarowy lub sonda różnicowa; CW503 to zasilacz sond/LNA, a nie sonda<sup>[[11]](#references)</sup> |
| Pole elektromagnetyczne (EM) | CPU, RFID, akceleratory AES | Sonda pola H/bliskiego pola, wzmacniacz niskoszumowy i oscyloskop lub odbiornik SDR, taki jak RTL-SDR<sup>[[13]](#references)</sup> |
| Czas wykonania / pamięci podręczne | Komputery stacjonarne i CPU w chmurze | Precyzyjne timery (`rdtsc`/`rdtscp`) lub zdalny pomiar czasu przelotu |
| Akustyka / mechanika | Klawiatury, drukarki 3D, drukarki, przekaźniki i regulatory napięcia CPU | Mikrofon MEMS lub wibrometr laserowy<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optyka i temperatura | Diody LED stanu, wyświetlacze, DRAM i urządzenia sprzężone termicznie | Fotodioda, kamera szybkoklatkowa lub kamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Wstrzykiwanie błędów | Kryptografia ASIC/MCU | Zakłócenia zegara/napięcia, EMFI lub wstrzykiwanie laserem |

---

## Analiza poboru mocy

### Simple Power Analysis (SPA)
Obserwuj *pojedynczy* przebieg i powiąż widoczne cechy z operacjami, takimi jak rozgałęzienia, mnożenie modularne lub różne sekwencje instrukcji.<sup>[[1]](#references)</sup>

Dokładna konfiguracja zależy od celu. Poniższy przykład wykorzystuje aktualne API przechwytywania wysokiego poziomu ChipWhisperer po podłączeniu i skonfigurowaniu oscyloskopu oraz celu:<sup>[[1]](#references)</sup>

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
Zarejestruj wiele śladów, postaw hipotezę dotyczącą bajtu klucza `k`, oblicz model wycieku oparty na wadze Hamminga (HW) lub odległości Hamminga (HD) i skoreluj go z każdą próbką. Wymagana liczba śladów zależy od celu, szumu, wyrównania, mechanizmów przeciwdziałania i modelu wycieku; nie ma stałego progu.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA to standardowy punkt odniesienia. Ataki szablonowe, analiza wzajemnej informacji oraz metody uczenia maszynowego mogą być przydatne, gdy wyciek jest nieliniowy lub ślady są słabo wyrównane.

---

## Analiza elektromagnetyczna (EMA)
Analiza pola bliskiego EM pozwala obserwować aktywność zależną od danych bez wstawiania bocznika w tor zasilania. Nie musi ujawniać tego samego sygnału co ślad poboru mocy: znaczenie mają położenie i orientacja sondy, szerokość pasma, wzmocnienie toru wejściowego, jakość wyzwalania oraz odległość.

---

## Ataki czasowe i mikroarchitektoniczne
Nowoczesne procesory ujawniają sekrety przez współdzielone zasoby:
* **Hertzbleed (2022)** – zależne od danych dynamiczne skalowanie napięcia i częstotliwości tworzy zdalny kanał czasowy. Oryginalna demonstracja odzyskania klucza od początku do końca dotyczyła SIKE; późniejsze prace omawiają inne prymitywy.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – wykonanie spekulatywne może ujawniać dane używane przez instrukcje wektorowe gather, przekraczając granice bezpieczeństwa.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – nieprawidłowa obsługa spekulatywnego stanu rejestrów wektorowych może ujawniać dane z tego samego rdzenia fizycznego.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – atak z wykorzystaniem wykonania spekulatywnego łączy phantom execution z trenowaniem w wykonaniu spekulatywnym, aby tworzyć gadżety błędnej predykcji kontrolowane przez atakującego.<sup>[[5]](#references)</sup>

---

## Ataki akustyczne i optyczne
W kontrolowanym eksperymencie wykorzystano wyciek akustyczny do odzyskania kluczy RSA na podstawie odgłosów laptopa, także przy użyciu mikrofonu pobliskiego telefonu komórkowego.<sup>[[6]](#references)</sup> W odrębnym badaniu klawiatur z 2023 r. rozpoznawano naciśnięcia klawiszy z dokładnością 95% po wytrenowaniu modelu na nagraniach z pobliskiego telefonu oraz 93% po wytrenowaniu na dźwięku z Zoom; wartości te dotyczą eksperymentu z urządzeniem użytym do trenowania, a nie dowolnej klawiatury lub ofiary.<sup>[[9]](#references)</sup> Z emisją przetwarzanych danych można też korelować emisje optyczne diod statusu. Wyniki te zależą od celu i konfiguracji; nie należy uogólniać ich zasięgu ani skuteczności na inne urządzenia.<sup>[[7]](#references)</sup>

---

## Wstrzykiwanie błędów i różnicowa analiza błędów (DFA)
Połączenie kontrolowanego wstrzykiwania błędów z obserwacjami side-channel może ograniczyć przeszukiwanie klucza w przypadku niektórych algorytmów i implementacji. Popularne platformy laboratoryjne obejmują funkcje wstrzykiwania zakłóceń napięcia/zegara w ChipWhisperer oraz dedykowane narzędzia do wstrzykiwania błędów EM, takie jak ChipSHOUTER lub PicoEMP. Opisu z wcześniejszej wersji „poniżej 1 ns” nie należy traktować jako specyfikacji: opublikowana instrukcja ChipSHOUTER podaje typowe szerokości wprowadzanych impulsów **15–80 ns** dla końcówki 1 mm oraz **24–480 ns** dla końcówki 4 mm (choć jitter wyzwalania/impulsu jest określony w pikosekundach). Wymagana rozdzielczość czasowa, położenie sondy i liczba błędnych wyników zależą od celu oraz modelu błędu.<sup>[[1]](#references)[[10]](#references)</sup>

## Niezweryfikowane tropy badawcze zachowane z wcześniejszej wersji

Wcześniejsza wersja zawierała również twierdzenia o: konfiguracji EM **500 MHz–3 GHz**, która odzyskała klucz STM32 z odległości ponad **10 cm** przy użyciu RTL-SDR; diodzie aktywności DDR4 ujawniającej klucz rundy AES w mniej niż minutę podczas „Black Hat 2023”; oraz platformie open source do glitchingu RISC-V z 2025 r. o nazwie **GlitchKit-R5**. Podczas tego audytu nie udało się znaleźć odpowiadającej im publikacji źródłowej, materiałów konferencyjnych ani repozytorium projektu. Te dokładne szczegóły pozostawiono jako tropy do wyszukiwania i odtworzenia, a nie jako potwierdzone wyniki czy rekomendacje dotyczące narzędzi.

---

## Typowy przebieg ataku
1. Zidentyfikuj kanał wycieku i punkt pomiaru (pin VCC, kondensator odsprzęgający, punkt pola bliskiego).
2. Dodaj sygnał wyzwalający (GPIO lub oparty na wzorcu).  
3. Zbierz wystarczającą liczbę śladów dla wybranego testu statystycznego, zapisując tekst jawny/szyfrogram oraz inne metadane.
4. Wykonaj wstępne przetwarzanie (wyrównanie, usunięcie średniej, filtr LP/HP, falki, PCA).
5. Odzyskaj klucz metodami statystycznymi lub ML (CPA, MIA, DL-SCA).
6. Zweryfikuj wynik i ponów analizę dla wartości odstających.

---

## Zabezpieczenia i utwardzanie
* Implementacje **constant-time** i algorytmy wymagające dużej ilości pamięci.
* **Maskowanie/losowe przestawianie** – podział sekretów na losowe udziały; odporność na ataki pierwszego rzędu potwierdzona certyfikatem TVLA.
* **Ukrywanie** – stabilizatory napięcia na chipie, losowy zegar, logika dual-rail, ekrany EM.
* **Wykrywanie błędów** – obliczenia redundantne, podpisy progowe.
* **Operacyjne** – wyłącz DVFS/turbo w jądrach kryptograficznych, odizoluj SMT, zabroń współlokacji w chmurach wielodostępnych.

---

## Narzędzia i frameworki
* **ChipWhisperer-Husky** (2024) – oscyloskop 500 MS/s + wyzwalanie Cortex-M; API Pythona jak wyżej.<sup>[[1]](#references)</sup>
* **Riscure Inspector i produkty do wstrzykiwania błędów** – komercyjne narzędzia do analizy i automatycznego testowania.
* **scaaml** – oparte na TensorFlow narzędzia i zbiory danych do deep-learning SCA.<sup>[[12]](#references)</sup>
* **pyecsca** – zestaw narzędzi open source do inżynierii wstecznej implementacji ECC typu black-box z użyciem side-channel.<sup>[[8]](#references)</sup>

---

## References

- [1] [Dokumentacja ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Publikacja o ataku Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: wykorzystywanie spekulatywnego pobierania danych](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: ujawnianie nowych powierzchni ataku za pomocą trenowania w wykonaniu spekulatywnym](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Odzyskiwanie klucza RSA za pomocą kryptanalizy akustycznej o niskiej przepustowości](https://eprint.iacr.org/2013/857.pdf)
- [7] [Wyciek informacji z emisji optycznych](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Dokumentacja artefaktu pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktyczny atak akustyczny side-channel na klawiatury oparty na deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE — instrukcja obsługi ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Dokumentacja ChipWhisperer — zasilacz sondy CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Dokumentacja Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — przeprowadzanie niskokosztowych ataków elektromagnetycznych side-channel za pomocą RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodowanie własności intelektualnej: akustyczny i magnetyczny atak side-channel na drukarkę 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — akustyczne ataki side-channel na drukarki](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Szpiegowanie temperatury za pomocą DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
