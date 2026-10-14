# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to asynchroniczny interfejs szeregowy, który przesyła ramkowany strumień bitów bez wspólnego zegara. Nie należy mylić UART na poziomie logicznym z RS-232: RS-232 wykorzystuje inne, często ujemne poziomy napięcia i wymaga transceivera.<sup>[[1]](#references)[[3]](#references)</sup>

Zazwyczaj linia jest utrzymywana w stanie wysokim (wartość logiczna 1), gdy UART jest w stanie bezczynności. Następnie, aby zasygnalizować rozpoczęcie przesyłania danych, nadajnik wysyła do odbiornika bit startu, podczas którego sygnał jest utrzymywany w stanie niskim (wartość logiczna 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających właściwą wiadomość, po których następuje opcjonalny bit parzystości i jeden lub dwa bity stopu (o wartości logicznej 1), zależnie od konfiguracji. Bit parzystości, używany do wykrywania błędów, rzadko występuje w praktyce. Bit (lub bity) stopu oznacza koniec transmisji.

Najczęściej stosowaną konfiguracją jest 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. UART wysyła najpierw najmniej znaczący bit danych, więc znak ASCII `C` (`0x43`) jest przesyłany jako: start `0`; dane `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcemy wysłać znak C, czyli 0x43 w ASCII, przez UART w konfiguracji 8N1](<../../images/image (764).png>)

Narzędzia sprzętowe do komunikacji przez UART:

- Adapter USB-to-serial
- Adaptery z układami CP2102 lub PL2303
- Narzędzia wielofunkcyjne, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikowanie portów UART

Typowe złącze debugowania udostępnia piny **TX**, **RX** i **GND**; może też udostępniać pin **Vcc/Vref**, reset lub piny kontroli przepływu. Vcc nie jest sygnałem UART i zazwyczaj powinno służyć wyłącznie jako odniesienie napięcia — nie należy podłączać go jako źródła zasilania, chyba że znane są schemat płytki i wymagania dotyczące prądu.<sup>[[2]](#references)[[3]](#references)</sup>

Zacznij od **wyłączonego** i odłączonego urządzenia:

- Zidentyfikuj **GND** w trybie testu ciągłości, sprawdzając połączenie ze znaną masą, ekranem złącza lub masą zasilania. Nigdy nie używaj trybu testu ciągłości ani pomiaru rezystancji na zasilanej płytce.
- Przed włączeniem zasilania badanego urządzenia przełącz multimetr w tryb pomiaru napięcia stałego. Zmierz napięcie na podejrzanych pinach względem masy, aby określić napięcie logiczne. Stabilne napięcie może oznaczać Vcc/Vref; nie zakładaj, że można je bezpiecznie podłączyć.
- Obserwuj podejrzane piny za pomocą analizatora logicznego lub oscyloskopu podczas uruchamiania urządzenia. **TX** zwykle pozostaje w stanie wysokim w bezczynności i wysyła serie ramek danych. Multimetr może wskazać zmienną wartość średnią, ale nie pozwoli zweryfikować ramek ani szybkości transmisji.
- **RX** może pozostawać w stanie bezczynności i nie da się go bezpiecznie zidentyfikować wyłącznie na podstawie sąsiedztwa z TX. Prześledź ścieżki na PCB, sprawdź dokumentację SoC lub użyj analizatora o wysokiej impedancji, zanim zaczniesz wysyłać sygnał na ten pin.

Zamiana TX i RX zwykle uniemożliwia komunikację; pomylenie zasilania, masy lub poziomów sygnału może trwale uszkodzić urządzenie docelowe albo adapter. Najpierw podłącz masę i rozpocznij od trybu **wyłącznie odbioru** (TX urządzenia docelowego do RX adaptera).

Producenci mogą pomijać złącze, nie montować rezystorów szeregowych, wyłączać konsolę w firmware lub udostępniać tylko TX. Prześledź połączenia pobliskich pól testowych i miejsc na rezystory do SoC; tymczasowe połączenie o wysokiej impedancji dodaj dopiero po potwierdzeniu poziomu elektrycznego. Gwarancja nie oznacza, że urządzenie musi mieć dostępny port UART.

### Identyfikowanie szybkości transmisji UART

Najłatwiej określić prawidłową szybkość transmisji, obserwując sygnał wyjściowy pinu **TX** i próbując odczytać dane. Jeśli odebrane dane są nieczytelne, wybieraj kolejne możliwe szybkości, aż dane staną się czytelne. Możesz użyć adaptera USB-to-serial lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, w połączeniu ze skryptem pomocniczym, np. [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej stosowane szybkości transmisji to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Pamiętaj, że w tym protokole należy połączyć TX jednego urządzenia z RX drugiego!

## Adapter CP210X UART do TTY

Mostki CP210x USB-to-UART są stosowane na wielu płytkach prototypowych i niedrogich adapterach. Typowe moduły udostępniają piny zasilania obok GND, RXD i TXD, ale ich złącza i poziomy wejścia/wyjścia mogą się różnić. Sprawdź rzeczywiste napięcie na podstawie projektu płytki lub dokumentacji układu. Zazwyczaj wystarczy podłączyć GND i RX adaptera do TX urządzenia docelowego, a po sprawdzeniu działania w trybie wyłącznie odbioru — TX adaptera do RX urządzenia docelowego. Nie podłączaj pinu zasilania 5 V/3,3 V adaptera, chyba że celowo zasilasz urządzenie, o którym wiadomo, że toleruje takie napięcie.<sup>[[3]](#references)</sup>

Jeśli adapter nie zostanie wykryty, upewnij się, że w systemie hosta zainstalowano sterowniki CP210X. Po wykryciu i podłączeniu adaptera można użyć narzędzi takich jak picocom, minicom lub screen.

Aby wyświetlić listę urządzeń podłączonych do systemów Linux/MacOS:

```
ls /dev/
```

Do podstawowej interakcji z interfejsem UART użyj następującego polecenia:

```
picocom /dev/<adapter> --baud <baudrate>
```

W przypadku minicom użyj następującego polecenia, aby go skonfigurować:

```
minicom -s
```

Skonfiguruj ustawienia, takie jak prędkość transmisji i nazwa urządzenia, w opcji `Serial port setup`.

Po konfiguracji uruchom `minicom`, aby otworzyć konsolę UART.

## UART przez Arduino UNO R3 (płytki z wyjmowanym układem Atmel 328p)

Jeśli adaptery UART Serial-to-USB nie są dostępne, można skorzystać z szybkiego obejścia z użyciem Arduino UNO R3. Arduino UNO R3 jest zwykle łatwo dostępne, więc pozwala zaoszczędzić sporo czasu.

Arduino UNO R3 ma wbudowany adapter USB-to-Serial. Aby uzyskać połączenie UART, wystarczy wyjąć z płytki mikrokontroler Atmel 328p. To obejście działa z wariantami Arduino UNO R3, w których układ Atmel 328p nie jest przylutowany do płytki (zastosowano w nich wersję SMD). Połącz pin RX Arduino (Digital Pin 0) z pinem TX interfejsu UART, a pin TX Arduino (Digital Pin 1) z pinem RX interfejsu UART.

Użyj **Serial Monitor** w Arduino IDE lub dedykowanego terminala ustawionego na docelową prędkość transmisji. Klasyczne sygnały szeregowe Uno R3 mają poziom logiczny 5 V, więc przed podłączeniem ich do urządzenia docelowego 3,3 V lub o niższym napięciu użyj konwertera poziomów logicznych albo dzielnika napięcia.

## Bus Pirate

Poniższy zapis używa starszego interfejsu firmware Bus Pirate do monitorowania wyjścia UART. Nowszy firmware Bus Pirate używa poleceń takich jak `m uart`, `{`/`}`, `monitor` lub `bridge`; sprawdź dokumentację dla zainstalowanej wersji.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## Zrzucanie firmware’u przez konsolę UART

Konsola UART zapewnia dostęp w czasie działania do logów rozruchowych, a czasami także do bootloadera lub powłoki systemu operacyjnego. Nawet konsola tylko do odczytu ujawnia mapy pamięci, sterowniki pamięci flash, argumenty rozruchowe, układ partycji i wersje firmware’u. Firmware może znajdować się w pamięci SPI NOR/NAND, eMMC lub innym urządzeniu; zazwyczaj nie jest wykonywany z pamięci EEPROM, a pliki zapisane w zamontowanym trwałym systemie plików niekoniecznie znikają po ponownym uruchomieniu.

Istnieje kilka sposobów pozyskania danych, a sekcja SPI opisuje bezpośredni odczyt z zewnętrznej pamięci flash. Pozyskiwanie danych z pomocą konsoli może być mniej inwazyjne, jeśli bootloader udostępnia bezpieczne polecenie odczytu. Przerwanie rozruchu lub użycie polecenia dotyczącego pamięci flash może jednak wpłynąć na dostępność urządzenia, dlatego należy zapisać jego stan początkowy i unikać operacji zapisu lub kasowania.

Zrzucanie firmware’u z pomocą konsoli często zaczyna się od przerwania działania bootloadera. Wiele urządzeń z wbudowanym systemem Linux używa **Das U-Boot**, ale inne korzystają z własnościowych bootloaderów lub mają wyłączoną interaktywną konsolę.

Aby sprawdzić, czy bootloader jest interaktywny, podłącz ścieżkę odbiorczą UART i terminal, gdy urządzenie docelowe jest wyłączone, rozpocznij logowanie, a następnie włącz urządzenie. Postępuj zgodnie z wyświetlanym komunikatem autoboot; zależnie od wersji może być konieczne naciśnięcie klawisza, krótkiej sekwencji klawiszy albo przerwanie może być całkowicie wyłączone.

Jeśli uda się przerwać rozruch, użyj poleceń `help`, `printenv` oraz poleceń rozpoznawczych tylko do odczytu, aby poznać układ pamięci i nośników danych danego producenta przed uzyskaniem dostępu do adresów.

W U-Boot polecenie `md` wyświetla **pamięć adresowalną**, a nie automatycznie „pamięć EEPROM”. Najpierw użyj poleceń właściwych dla danej płyty, takich jak `mtd list`, `sf probe`, `mmc info`, `part list`, zmiennych środowiskowych i logów rozruchowych, aby ustalić właściwy zmapowany adres lub załadować obszar pamięci flash do RAM. Następnie wyświetl znany zakres bajt po bajcie:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zapisz wyjście szeregowe przed rozpoczęciem. Wyjście `md.b` zawiera adresy i kolumnę ASCII, więc jest reprezentacją tekstową, a nie surowym obrazem ROM.

Usuń kolumny adresów i ASCII, połącz wyłącznie pola bajtów zapisane szesnastkowo i zdekoduj je do postaci binarnej (na przykład za pomocą `xxd -r -p`). Sprawdź oczekiwaną liczbę bajtów i zapisz hash przed analizą:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identyfikuje następnie znane sygnatury w odtworzonym pliku binarnym. Bezpośredni odczyt pamięci flash przez odpowiedni interfejs SPI/eMMC/NAND jest zwykle szybszy i mniej podatny na błędy, gdy konsola nie może niezawodnie przesyłać danych.

U-Boot może wyłączyć możliwość przerwania autobootu, wymagać sekwencji klawiszy specyficznej dla producenta albo blokować polecenia dotyczące pamięci lub flash. Kieruj się komunikatem autobootu i logiem rozruchowym, zamiast bez namysłu wysyłać znaki. Jeśli nie można przerwać działania konsoli, zachowaj log rozruchowy i skorzystaj z nieinwazyjnej metody pozyskania firmware’u.

## References

- [1] [Podręcznik referencyjny rodziny Microchip PIC32 — UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacja Bus Pirate — tryb UART i limity elektryczne](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs — karta katalogowa CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacja U-Boot — polecenie `md` do wyświetlania zawartości pamięci](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
