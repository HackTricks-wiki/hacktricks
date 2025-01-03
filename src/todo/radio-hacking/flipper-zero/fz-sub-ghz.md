# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero może **odbierać i transmitować częstotliwości radiowe w zakresie 300-928 MHz** dzięki wbudowanemu modułowi, który potrafi odczytywać, zapisywać i emulować piloty. Te piloty są używane do interakcji z bramami, barierami, zamkami radiowymi, przełącznikami zdalnego sterowania, bezprzewodowymi dzwonkami, inteligentnymi światłami i innymi. Flipper Zero może pomóc Ci dowiedzieć się, czy Twoje bezpieczeństwo jest zagrożone.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ma wbudowany moduł sub-1 GHz oparty na [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chipie CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) oraz antenę radiową (maksymalny zasięg to 50 metrów). Zarówno chip CC1101, jak i antena są zaprojektowane do pracy na częstotliwościach w pasmach 300-348 MHz, 387-464 MHz i 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!NOTE]
> Jak znaleźć, która częstotliwość jest używana przez pilot

Podczas analizy Flipper Zero skanuje siłę sygnału (RSSI) na wszystkich dostępnych częstotliwościach w konfiguracji częstotliwości. Flipper Zero wyświetla częstotliwość z najwyższą wartością RSSI, z siłą sygnału wyższą niż -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Aby określić częstotliwość pilota, wykonaj następujące kroki:

1. Umieść pilot bardzo blisko lewej strony Flipper Zero.
2. Przejdź do **Main Menu** **→ Sub-GHz**.
3. Wybierz **Frequency Analyzer**, a następnie naciśnij i przytrzymaj przycisk na pilocie, który chcesz przeanalizować.
4. Sprawdź wartość częstotliwości na ekranie.

### Read

> [!NOTE]
> Znajdź informacje o używanej częstotliwości (to także inny sposób na znalezienie, która częstotliwość jest używana)

Opcja **Read** **nasłuchuje na skonfigurowanej częstotliwości** na wskazanej modulacji: 433.92 AM domyślnie. Jeśli **coś zostanie znalezione** podczas odczytu, **informacje są podawane** na ekranie. Te informacje mogą być użyte do replikacji sygnału w przyszłości.

Podczas korzystania z Read, można nacisnąć **lewy przycisk** i **skonfigurować go**.\
W tym momencie ma **4 modulacje** (AM270, AM650, FM328 i FM476) oraz **kilka istotnych częstotliwości** zapisanych:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Możesz ustawić **dowolną, która Cię interesuje**, jednak jeśli **nie jesteś pewien, która częstotliwość** może być używana przez posiadany pilot, **ustaw Hopping na ON** (domyślnie Off) i naciśnij przycisk kilka razy, aż Flipper ją przechwyci i poda Ci informacje potrzebne do ustawienia częstotliwości.

> [!CAUTION]
> Przełączanie między częstotliwościami zajmuje trochę czasu, dlatego sygnały transmitowane w czasie przełączania mogą zostać pominięte. Aby uzyskać lepszy odbiór sygnału, ustaw stałą częstotliwość określoną przez Frequency Analyzer.

### **Read Raw**

> [!NOTE]
> Skopiuj (i powtórz) sygnał na skonfigurowanej częstotliwości

Opcja **Read Raw** **rejestruje sygnały** wysyłane na nasłuchiwanej częstotliwości. Może to być użyte do **skopiowania** sygnału i **powtórzenia** go.

Domyślnie **Read Raw jest również na 433.92 w AM650**, ale jeśli przy użyciu opcji Read odkryłeś, że interesujący Cię sygnał jest na **innej częstotliwości/modulacji, możesz to również zmodyfikować** naciskając lewy przycisk (będąc w opcji Read Raw).

### Brute-Force

Jeśli znasz protokół używany na przykład przez bramę garażową, możliwe jest **wygenerowanie wszystkich kodów i wysłanie ich za pomocą Flipper Zero.** To przykład, który obsługuje ogólne typy garaży: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!NOTE]
> Dodaj sygnały z skonfigurowanej listy protokołów

#### Lista [obsługiwanych protokołów](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (działa z większością systemów kodów statycznych) | 433.92 | Statyczny  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statyczny  |
| Nice Flo 24bit_433                                             | 433.92 | Statyczny  |
| CAME 12bit_433                                                 | 433.92 | Statyczny  |
| CAME 24bit_433                                                 | 433.92 | Statyczny  |
| Linear_300                                                     | 300.00 | Statyczny  |
| CAME TWEE                                                      | 433.92 | Statyczny  |
| Gate TX_433                                                    | 433.92 | Statyczny  |
| DoorHan_315                                                    | 315.00 | Dynamiczny |
| DoorHan_433                                                    | 433.92 | Dynamiczny |
| LiftMaster_315                                                 | 315.00 | Dynamiczny |
| LiftMaster_390                                                 | 390.00 | Dynamiczny |
| Security+2.0_310                                               | 310.00 | Dynamiczny |
| Security+2.0_315                                               | 315.00 | Dynamiczny |
| Security+2.0_390                                               | 390.00 | Dynamiczny |

### Obsługiwani dostawcy Sub-GHz

Sprawdź listę w [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Obsługiwane częstotliwości według regionu

Sprawdź listę w [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Uzyskaj dBms zapisanych częstotliwości

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
