# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#introduction" id="introduction"></a>

Flipper Zero może **odbierać i nadawać na częstotliwościach radiowych z zakresu 300–928 MHz** za pomocą wbudowanego modułu, z zastrzeżeniem ograniczeń częstotliwości obowiązujących w skonfigurowanym regionie. Może odczytywać, zapisywać i emulować zgodne piloty używane do obsługi bram, szlabanów, zamków radiowych, przełączników, bezprzewodowych dzwonków do drzwi, inteligentnych świateł i innych urządzeń.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sprzęt Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero ma wbudowany moduł sub-1 GHz oparty na transceiverze CC1101 i antenie radiowej. Rzeczywisty zasięg zależy od częstotliwości, anteny, otoczenia i nadajnika; według dokumentacji Flippera w sprzyjających warunkach wynosi on do około 50 metrów. Sprzęt obsługuje zakresy 300–348 MHz, 387–464 MHz i 779–928 MHz, natomiast firmware i przepisy regionalne dodatkowo ograniczają nadawanie.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Czynności

### Analizator częstotliwości

> [!TIP]
> Jak znaleźć częstotliwość używaną przez pilot

Podczas analizy Flipper Zero skanuje siłę sygnału (RSSI) na wszystkich częstotliwościach dostępnych w konfiguracji częstotliwości. Flipper Zero wyświetla częstotliwość o najwyższej wartości RSSI, przy sile sygnału większej niż -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Aby ustalić częstotliwość pilota:

1. Umieść pilot bardzo blisko lewej strony Flipper Zero.
2. Przejdź do **Main Menu** **→ Sub-GHz**.
3. Wybierz **Frequency Analyzer**, a następnie naciśnij i przytrzymaj przycisk na pilocie, który chcesz przeanalizować.
4. Odczytaj wartość częstotliwości na ekranie.

### Read

> [!TIP]
> Znajdź informacje o używanej częstotliwości (to także inny sposób na jej ustalenie)

Opcja **Read** nasłuchuje na skonfigurowanej częstotliwości i z użyciem skonfigurowanej modulacji (domyślnie 433,92 MHz AM). Gdy rozpozna obsługiwany sygnał, na ekranie wyświetli informacje, które można zapisać i później odtworzyć.<sup>[[1]](#references)</sup>

Podczas korzystania z Read możesz nacisnąć **lewy przycisk** i **zmienić konfigurację**.\
Obecnie dostępne są **4 modulacje** (AM270, AM650, FM328 i FM476) oraz **kilka istotnych częstotliwości**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Możesz wybrać dowolną dozwoloną częstotliwość. Jeśli nie wiesz, jakiej częstotliwości używa pilot, ustaw **Hopping na ON** (domyślnie wyłączone), a następnie naciśnij przycisk pilota kilka razy, aż Flipper przechwyci sygnał i poda częstotliwość.

> [!CAUTION]
> Przełączanie między częstotliwościami zajmuje trochę czasu, dlatego sygnały nadawane w chwili przełączania mogą zostać pominięte. Aby uzyskać lepszy odbiór, ustaw stałą częstotliwość ustaloną za pomocą analizatora częstotliwości.

### **Read Raw**

> [!TIP]
> Przechwyć (i odtwórz) sygnał na skonfigurowanej częstotliwości

Opcja **Read Raw** nagrywa sygnały nadawane na wybranej częstotliwości. Można jej użyć do przechwycenia i odtworzenia sygnału podczas autoryzowanych testów.<sup>[[1]](#references)</sup>

Domyślnie **Read Raw również używa częstotliwości 433,92 MHz i modulacji AM650**. Jeśli opcja Read wykryła sygnał o innej częstotliwości lub modulacji, naciśnij Left w trybie Read Raw, aby zmienić te ustawienia.

### Brute-Force

Jeśli znasz protokół używany przez urządzenie, takie jak brama garażowa, możesz **wygenerować potencjalne kody i nadawać je za pomocą Flipper Zero**. Projekt `flipperzero-bruteforce` obsługuje kilka popularnych protokołów ze statycznym kodem.<sup>[[3]](#references)</sup>

### Dodaj ręcznie

> [!TIP]
> Dodawaj sygnały z skonfigurowanej listy protokołów

#### Lista obsługiwanych protokołów <a href="#id-3iglu" id="id-3iglu"></a>

Menu Add Manually udostępnia ustawienia protokołów opisane w dokumentacji Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (działa z większością systemów ze statycznym kodem) | 433.92 | Statyczny |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statyczny |
| Nice Flo 24bit_433                                             | 433.92 | Statyczny |
| CAME 12bit_433                                                 | 433.92 | Statyczny |
| CAME 24bit_433                                                 | 433.92 | Statyczny |
| Linear_300                                                     | 300.00 | Statyczny |
| CAME TWEE                                                      | 433.92 | Statyczny |
| Gate TX_433                                                    | 433.92 | Statyczny |
| DoorHan_315                                                    | 315.00 | Dynamiczny |
| DoorHan_433                                                    | 433.92 | Dynamiczny |
| LiftMaster_315                                                 | 315.00 | Dynamiczny |
| LiftMaster_390                                                 | 390.00 | Dynamiczny |
| Security+2.0_310                                               | 310.00 | Dynamiczny |
| Security+2.0_315                                               | 315.00 | Dynamiczny |
| Security+2.0_390                                               | 390.00 | Dynamiczny |

### Obsługiwani dostawcy Sub-GHz

Sprawdź listę obsługiwanych dostawców Flipper Zero.<sup>[[5]](#references)</sup>

### Obsługiwane częstotliwości w poszczególnych regionach

Przed nadawaniem sprawdź oficjalną listę częstotliwości regionalnych.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Sprawdź wartości dBm zapisanych częstotliwości

## References

- [1] [Sub-GHz - Dokumentacja użytkownika Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Karta katalogowa Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Dodawanie ręcznie utworzonego pilota](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Obsługiwani dostawcy Sub-GHz](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regionalne częstotliwości Sub-GHz](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
