# Ataki analizy kanałów bocznych

{{#include ../../banners/hacktricks-training.md}}

Ataki kanałów bocznych odzyskują sekrety poprzez obserwowanie fizycznego lub mikroarchitektonicznego „leakage”, który jest *skorelowany* ze stanem wewnętrznym, ale *nie* jest częścią logicznego interfejsu urządzenia. Przykłady obejmują zarówno pomiar chwilowego prądu pobieranego przez kartę inteligentną, jak i wykorzystywanie efektów zarządzania energią CPU przez sieć.

---

## Główne kanały leakage

| Kanał | Typowy cel | Instrumentacja |
|---------|---------------|-----------------|
| Pobór mocy | Karty inteligentne, IoT MCU, FPGA | Oscyloskop oraz rezystor bocznikowy lub sonda różnicowa; CW503 jest zasilaczem dla sond/LNA, a nie samą sondą<sup>[[11]](#references)</sup> |
| Pole elektromagnetyczne (EM) | CPU, RFID, akceleratory AES | Sonda H-field/near-field wraz z niskoszumowym wzmacniaczem i oscyloskopem lub odbiornikiem SDR, takim jak RTL-SDR<sup>[[13]](#references)</sup> |
| Czas wykonywania / cache | CPU komputerów desktopowych i chmurowych | Timery o wysokiej precyzji (`rdtsc`/`rdtscp`) lub zdalny pomiar czasu przelotu |
| Akustyka / mechanika | Klawiatury, drukarki 3D, drukarki, przekaźniki i regulatory napięcia CPU | Mikrofon MEMS lub wibrometr laserowy<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| Optyka i temperatura | Diody statusu, wyświetlacze, DRAM i urządzenia połączone termicznie | Fotodioda, kamera o wysokiej szybkości nagrywania lub kamera IR<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | Kryptografia ASIC/MCU | Glitch zegara/napięcia, EMFI lub wstrzykiwanie laserowe |

---

## Analiza mocy

### Simple Power Analysis (SPA)
Obserwuj *pojedynczy* przebieg i powiąż widoczne cechy z operacjami takimi jak rozgałęzienia, mnożenie modularne lub różne sekwencje instrukcji.<sup>[[1]](#references)</sup>

Dokładna konfiguracja zależy od celu. Poniżej użyto wysokopoziomowego API przechwytywania ChipWhisperer po podłączeniu i skonfigurowaniu scope oraz targetu:<sup>[[1]](#references)</sup>
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
Zbierz wiele śladów, postaw hipotezę dotyczącą bajtu klucza `k`, oblicz model wycieku Hamming-weight (HW) lub Hamming-distance (HD) i skoreluj go z każdą próbką. Wymagana liczba śladów zależy od celu, szumu, wyrównania, mechanizmów przeciwdziałania oraz modelu wycieku; nie jest stałym progiem.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA to standardowy punkt odniesienia. Template attacks, mutual-information analysis oraz podejścia oparte na machine learning mogą być przydatne, gdy leakage jest nieliniowy lub traces są słabo wyrównane.

---

## Analiza elektromagnetyczna (EMA)
Analiza EM w polu bliskim może obserwować aktywność zależną od danych bez wprowadzania shunta w ścieżce zasilania. Nie musi ujawniać tego samego sygnału co power trace: znaczenie mają położenie i orientacja sondy, bandwidth, wzmocnienie front-endu, jakość triggera oraz odległość.

---

## Ataki czasowe i mikroarchitektoniczne
Nowoczesne CPU ujawniają sekrety przez współdzielone zasoby:
* **Hertzbleed (2022)** – Zależne od danych dynamiczne skalowanie napięcia i częstotliwości tworzy zdalny kanał czasowy. Oryginalna demonstracja odzyskiwania klucza end-to-end była wymierzona w SIKE; późniejsze prace omawiają inne prymitywy.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution może ujawnić dane używane przez instrukcje vector gather ponad granicami bezpieczeństwa.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Nieprawidłowa obsługa spekulatywnego stanu rejestrów wektorowych może ujawnić dane z tego samego fizycznego rdzenia.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Atak transient-execution łączy phantom execution z trainingiem w transient execution, aby tworzyć kontrolowane przez atakującego gadżety błędnej predykcji.<sup>[[5]](#references)</sup>

---

## Ataki akustyczne i optyczne
Acoustic leakage wykorzystano do odzyskania kluczy RSA z hałasu laptopa w kontrolowanym eksperymencie, także przy użyciu mikrofonu znajdującego się w pobliżu telefonu komórkowego.<sup>[[6]](#references)</sup> W odrębnym badaniu klawiatur z 2023 roku sklasyfikowano naciśnięcia klawiszy z dokładnością 95% po wytrenowaniu na nagraniach z pobliskiego telefonu oraz 93% po wytrenowaniu na dźwięku z Zoom; wartości te opisują eksperyment tego artykułu z urządzeniem użytym do treningu, a nie dowolną klawiaturę ani ofiarę.<sup>[[9]](#references)</sup> Emisje optyczne z diod statusu również można korelować z przetwarzanymi danymi. Wyniki te zależą od celu i konfiguracji; nie należy uogólniać ich zasięgu ani współczynnika skuteczności na niezwiązane z nimi urządzenia.<sup>[[7]](#references)</sup>

---

## Fault Injection i Differential Fault Analysis (DFA)
Połączenie kontrolowanych faultów z obserwacjami side-channel może ograniczyć przeszukiwanie klucza dla niektórych algorytmów i implementacji. Typowe platformy laboratoryjne obejmują funkcje voltage/clock glitching w ChipWhisperer oraz dedykowane narzędzia do EM fault-injection, takie jak ChipSHOUTER lub PicoEMP. Opisu „sub-1 ns” z wcześniejszej wersji nie należy traktować jako specyfikacji: opublikowana instrukcja ChipSHOUTER podaje typowe szerokości wprowadzanych impulsów **15–80 ns** z końcówką 1 mm oraz **24–480 ns** z końcówką 4 mm (choć jitter triggera/impulsu jest określany w pikosekundach). Wymagana rozdzielczość czasowa, położenie sondy i liczba błędnych wyników zależą od celu oraz modelu fault.<sup>[[1]](#references)[[10]](#references)</sup>

## Niezweryfikowane kierunki badań zachowane z wcześniejszej wersji

Wcześniejsza wersja twierdziła również, że: konfiguracja EM **500 MHz–3 GHz** odzyskała klucz STM32 z odległości ponad **10 cm** przy użyciu RTL-SDR; dioda aktywności DDR4 ujawniła klucz rundy AES w czasie krótszym niż jedna minuta podczas „Black Hat 2023”; oraz że w 2025 roku powstała open-source platforma glitchingowa RISC-V o nazwie **GlitchKit-R5**. Podczas tego audytu nie udało się znaleźć odpowiadającego tym twierdzeniom pierwotnego artykułu, materiałów konferencyjnych ani repozytorium projektu. Te dokładne informacje zachowano jako wskazówki do wyszukiwania i reprodukcji, a nie jako potwierdzone wyniki lub rekomendacje narzędzi.

---

## Typowy przebieg ataku
1. Zidentyfikuj kanał leakage i punkt podłączenia (pin VCC, kondensator odsprzęgający, punkt w polu bliskim).
2. Wstaw trigger (GPIO lub oparty na wzorcu).
3. Zbierz wystarczającą liczbę traces dla wybranego testu statystycznego, zapisując plaintext/ciphertext oraz inne metadane.
4. Wykonaj preprocessing (wyrównanie, usunięcie średniej, filtr LP/HP, wavelet, PCA).
5. Odzyskiwanie klucza metodami statystycznymi lub ML (CPA, MIA, DL-SCA).
6. Zweryfikuj wyniki i iteruj na wartościach odstających.

---

## Zabezpieczenia i hardening
* Implementacje **constant-time** i algorytmy memory-hard.
* **Masking/shuffling** – podziel sekrety na losowe udziały; odporność pierwszego rzędu certyfikowana przez TVLA.
* **Hiding** – regulatory napięcia on-chip, losowy zegar, logika dual-rail, osłony EM.
* **Fault detection** – redundantne obliczenia, threshold signatures.
* **Operacyjne** – wyłącz DVFS/turbo w kernelach kryptograficznych, odizoluj SMT, zabroń co-location w multi-tenant clouds.

---

## Narzędzia i frameworki
* **ChipWhisperer-Husky** (2024) – oscyloskop 500 MS/s + trigger Cortex-M; Python API jak wyżej.<sup>[[1]](#references)</sup>
* **Riscure Inspector i produkty fault-injection** – komercyjne narzędzia do analizy i automatyzacji testów.
* **scaaml** – oparte na TensorFlow narzędzia i datasety do deep-learning SCA.<sup>[[12]](#references)</sup>
* **pyecsca** – open-source toolkit do reverse engineeringu implementacji ECC typu black-box za pomocą side channels.<sup>[[8]](#references)</sup>

---

## References

- [1] [Dokumentacja ChipWhisperer](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Artykuł o ataku Hertzbleed](https://www.hertzbleed.com/)
- [3] [Downfall: wykorzystywanie spekulatywnego gromadzenia danych](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: ujawnianie nowych powierzchni ataku za pomocą trainingu w transient execution](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Ekstrakcja klucza RSA za pomocą akustycznej kryptanalizy o niskiej przepustowości](https://eprint.iacr.org/2013/857.pdf)
- [7] [Wyciek informacji z emisji optycznych](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [Dokumentacja artefaktu pyecsca](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Praktyczny atak akustyczny side-channel na klawiatury oparty na deep learning](https://arxiv.org/abs/2308.01074)
- [10] [NewAE — instrukcja użytkownika ChipSHOUTER](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [Dokumentacja ChipWhisperer — zasilanie sondy CW503](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Dokumentacja Google SCAAML](https://google.github.io/scaaml/)
- [13] [FOSDEM — przeprowadzanie niskokosztowych elektromagnetycznych ataków side-channel z użyciem RTL-SDR](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Dekodowanie własności intelektualnej: akustyczny i magnetyczny atak side-channel na drukarkę 3D](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — akustyczne ataki side-channel na drukarki](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [Szpiegowanie temperatury za pomocą DRAM](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
