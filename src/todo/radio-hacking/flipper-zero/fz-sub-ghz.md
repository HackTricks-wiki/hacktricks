# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero może **odbierać i transmitować częstotliwości radiowe w zakresie 300-928 MHz** za pomocą wbudowanego modułu, który może odczytywać, zapisywać i emulować piloty. Piloty te służą do obsługi bram, szlabanów, zamków radiowych, przełączników zdalnego sterowania, bezprzewodowych dzwonków do drzwi, inteligentnych świateł i innych urządzeń. Flipper Zero może pomóc sprawdzić, czy Twoje zabezpieczenia zostały naruszone.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ma wbudowany moduł sub-1 GHz oparty na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chipie CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) oraz antenę radiową (maksymalny zasięg wynosi 50 metrów). Zarówno chip CC1101, jak i antena są zaprojektowane do pracy w pasmach 300-348 MHz, 387-464 MHz oraz 779-928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Działania

### Analizator częstotliwości

> [!TIP]
> Jak sprawdzić, z jakiej częstotliwości korzysta pilot

Podczas analizy Flipper Zero skanuje siłę sygnału (RSSI) na wszystkich częstotliwościach dostępnych w konfiguracji częstotliwości. Flipper Zero wyświetla częstotliwość o najwyższej wartości RSSI, przy sile sygnału większej niż -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Aby określić częstotliwość pilota, wykonaj następujące czynności:

1. Umieść pilot bardzo blisko, po lewej stronie Flipper Zero.
2. Przejdź do **Main Menu** **→ Sub-GHz**.
3. Wybierz **Frequency Analyzer**, a następnie naciśnij i przytrzymaj przycisk na pilocie, który chcesz przeanalizować.
4. Sprawdź wartość częstotliwości na ekranie.

### Odczyt

> [!TIP]
> Znajdź informacje o używanej częstotliwości (to także sposób na sprawdzenie, z jakiej częstotliwości się korzysta)

Opcja **Read** **nasłuchuje skonfigurowanej częstotliwości** przy wskazanej modulacji: domyślnie 433.92 AM. Jeśli podczas odczytu **coś zostanie znalezione**, na ekranie zostaną wyświetlone **informacje**. Informacje te mogą być użyte do odtworzenia sygnału w przyszłości.<sup>[[1]](#references)</sup>

Podczas korzystania z funkcji Read można nacisnąć **lewy przycisk** i **skonfigurować ją**.\
Obecnie dostępne są **4 modulacje** (AM270, AM650, FM328 i FM476) oraz zapisanych jest **kilka istotnych częstotliwości**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Możesz ustawić **dowolną interesującą Cię częstotliwość**, jednak jeśli **nie masz pewności, z jakiej częstotliwości** korzysta posiadany pilot, **włącz Hopping** (domyślnie wyłączony) i naciśnij przycisk kilka razy, aż Flipper przechwyci sygnał i poda informacje potrzebne do ustawienia częstotliwości.

> [!CAUTION]
> Przełączanie między częstotliwościami zajmuje trochę czasu, dlatego sygnały transmitowane w momencie przełączania mogą zostać pominięte. Aby uzyskać lepszy odbiór sygnału, ustaw stałą częstotliwość określoną za pomocą Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Przechwyć (i odtwórz) sygnał na skonfigurowanej częstotliwości

Opcja **Read Raw** **rejestruje sygnały** wysyłane na nasłuchiwanej częstotliwości. Można jej użyć do **przechwycenia** sygnału i **odtworzenia** go.

Domyślnie **Read Raw również działa na częstotliwości 433.92 w AM650**, ale jeśli za pomocą opcji Read znajdziesz, że interesujący Cię sygnał korzysta z **innej częstotliwości lub modulacji, możesz ją również zmienić**, naciskając lewy przycisk (wewnątrz opcji Read Raw).

### Brute-Force

Jeśli znasz protokół używany na przykład przez bramę garażową, możesz **wygenerować wszystkie kody i wysłać je za pomocą Flipper Zero.** Oto przykład obsługujący popularne typy bram garażowych: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Dodaj ręcznie

> [!TIP]
> Dodaj sygnały z skonfigurowanej listy protokołów

#### Lista [obsługiwanych protokołów](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (działa z większością systemów korzystających ze statycznych kodów) | 433.92 | Statyczny |
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

Sprawdź listę na stronie [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Obsługiwane częstotliwości według regionu

Sprawdź listę na stronie [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Uzyskaj wartości dBm zapisanych częstotliwości

## Odnośniki

- [1] [Dokumentacja Flipper Zero Sub-GHz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
