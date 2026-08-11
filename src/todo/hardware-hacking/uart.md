# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to asynchroniczny interfejs szeregowy, który przesyła ramkowany strumień bitów bez współdzielonego zegara. Nie należy mylić UART na poziomie logicznym z RS-232: RS-232 wykorzystuje inne, często ujemne poziomy napięcia i wymaga transceivera.<sup>[[1]](#references)[[3]](#references)</sup>

Zazwyczaj linia jest utrzymywana w stanie wysokim (o wartości logicznej 1), gdy UART znajduje się w stanie bezczynności. Następnie, aby zasygnalizować rozpoczęcie transferu danych, nadajnik wysyła do odbiornika bit startu, podczas którego sygnał jest utrzymywany w stanie niskim (o wartości logicznej 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających właściwą wiadomość, po których następuje opcjonalny bit parzystości oraz jeden lub dwa bity stopu (o wartości logicznej 1), zależnie od konfiguracji. Bit parzystości, używany do sprawdzania błędów, rzadko występuje w praktyce. Bit stopu (lub bity stopu) oznacza koniec transmisji.

Najczęściej stosowaną konfiguracją jest 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. UART wysyła najpierw najmniej znaczący bit danych, więc znak ASCII `C` (`0x43`) jest transmitowany jako: start `0`; dane `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład jeśli chcielibyśmy wysłać znak C, czyli 0x43 w ASCII, w UART 8N1](<../../images/image (764).png>)

Narzędzia hardware do komunikacji z UART:

- Adapter USB-to-serial
- Adaptery z układami CP2102 lub PL2303
- Narzędzie wielofunkcyjne, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikacja portów UART

Typowe złącze debug udostępnia **TX**, **RX** i **GND**; może również udostępniać pin **Vcc/Vref**, reset lub piny kontroli przepływu. Vcc nie jest sygnałem UART i zwykle powinien być używany wyłącznie jako odniesienie napięcia — a nie podłączany jako źródło zasilania — chyba że znany jest schemat ideowy płytki i wymagania dotyczące prądu.<sup>[[2]](#references)[[3]](#references)</sup>

Rozpocznij od urządzenia **wyłączonego** i odłączonego:

- Zidentyfikuj **GND** w trybie testu ciągłości względem znanej płaszczyzny masy, ekranu złącza lub masy zasilania. Nigdy nie używaj trybu testu ciągłości/pomiaru rezystancji na zasilanej płytce.
- Przed włączeniem zasilania celu przełącz multimetr w tryb pomiaru napięcia stałego. Zmierz potencjalne piny względem masy, aby określić napięcie logiczne. Stabilna szyna może być Vcc/Vref; nie zakładaj, że można ją bezpiecznie podłączyć.
- Obserwuj potencjalne piny za pomocą analizatora logicznego lub oscyloskopu podczas uruchamiania. **TX** zwykle pozostaje w stanie wysokim i pokazuje serie ramkowanych danych. Multimetr może wskazać średnie wahania, ale nie pozwala zweryfikować ramkowania ani baud rate.
- **RX** może pozostawać w stanie bezczynności i nie można go bezpiecznie zidentyfikować wyłącznie na podstawie sąsiedztwa z TX. Prześledź ścieżki PCB, sprawdź datasheet SoC lub użyj analizatora o wysokiej impedancji przed wymuszeniem na nim sygnału.

Zamiana TX i RX zwykle powoduje brak komunikacji; pomylenie zasilania, masy lub poziomów sygnałów może trwale uszkodzić cel albo adapter. Najpierw podłącz masę i rozpocznij od trybu **receive-only** (TX celu do RX adaptera).

Producenci mogą pominąć złącze, pozostawić nieobsadzone rezystory szeregowe, wyłączyć konsolę w firmware albo udostępnić wyłącznie TX. Prześledź pobliskie pady testowe i miejsca na rezystory do SoC oraz dodaj tymczasowe połączenie o wysokiej impedancji dopiero po potwierdzeniu poziomu elektrycznego. Obecność gwarancji nie oznacza, że musi istnieć dostępny UART.

### Identyfikacja baud rate UART

Najłatwiejszym sposobem identyfikacji poprawnego baud rate jest obserwacja **wyjścia pinu TX i próba odczytania danych**. Jeśli odebrane dane nie są czytelne, przełącz się na kolejną możliwą wartość baud rate, aż dane staną się czytelne. Możesz użyć adaptera USB-to-serial lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, w połączeniu ze skryptem pomocniczym, np. [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej stosowane wartości baud rate to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Należy pamiętać, że w tym protokole trzeba połączyć TX jednego urządzenia z RX drugiego!

## Adapter CP210X UART do TTY

Mostki CP210x USB-to-UART występują na wielu płytkach prototypowych i niedrogich adapterach. Typowe moduły udostępniają piny zasilania obok GND, RXD i TXD, ale ich złącza oraz poziomy I/O mogą się różnić. Potwierdź rzeczywiste napięcie na podstawie projektu płytki lub datasheetu. Zwykle należy podłączyć tylko GND, RX adaptera do TX celu, a — po sprawdzeniu w trybie receive-only — TX adaptera do RX celu. Nie podłączaj pinu zasilania 5 V/3,3 V adaptera, chyba że cel ma być celowo zasilany i wiadomo, że toleruje dane napięcie.<sup>[[3]](#references)</sup>

Jeśli adapter nie zostanie wykryty, upewnij się, że w systemie hosta zainstalowano sterowniki CP210X. Po wykryciu i podłączeniu adaptera można użyć narzędzi takich jak picocom, minicom lub screen.

Aby wyświetlić urządzenia podłączone do systemów Linux/MacOS:
```
ls /dev/
```
Do podstawowej interakcji z interfejsem UART użyj następującego polecenia:
```
picocom /dev/<adapter> --baud <baudrate>
```
W przypadku minicom użyj następującego polecenia, aby je skonfigurować:
```
minicom -s
```
Skonfiguruj ustawienia, takie jak baudrate i nazwa urządzenia, w opcji `Serial port setup`.

Po konfiguracji uruchom `minicom`, aby otworzyć konsolę UART.

## UART przez Arduino UNO R3 (płytki z wyjmowanym układem Atmel 328p)

Jeśli adaptery UART Serial do USB nie są dostępne, Arduino UNO R3 można wykorzystać dzięki szybkiemu hackowi. Ponieważ Arduino UNO R3 jest zwykle dostępne wszędzie, może to zaoszczędzić dużo czasu.

Arduino UNO R3 ma wbudowany na płytce adapter USB do Serial. Aby uzyskać połączenie UART, wystarczy wyjąć z płytki mikrokontroler Atmel 328p. Ten hack działa w wariantach Arduino UNO R3, w których Atmel 328p nie jest przylutowany do płytki (zastosowano wersję SMD). Połącz pin RX Arduino (Digital Pin 0) z pinem TX interfejsu UART oraz pin TX Arduino (Digital Pin 1) z pinem RX interfejsu UART.

Użyj **Serial Monitor** w Arduino IDE lub dedykowanego terminala ustawionego na docelowy baudrate. Klasyczne sygnały Serial w Uno R3 wykorzystują logikę 5 V, dlatego przed podłączeniem ich do urządzenia docelowego 3,3 V lub o niższym napięciu użyj konwertera poziomów logicznych albo dzielnika napięcia.

## Bus Pirate

Poniższy zapis sesji używa interfejsu legacy firmware Bus Pirate do monitorowania wyjścia UART. Nowszy firmware Bus Pirate używa poleceń takich jak `m uart`, `{`/`}`, `monitor` lub `bridge`; zapoznaj się z dokumentacją zainstalowanej wersji.<sup>[[2]](#references)</sup>
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
## Zrzucanie firmware'u za pomocą konsoli UART

Konsola UART zapewnia dostęp w czasie działania do logów uruchamiania oraz, czasami, do powłoki bootloadera lub systemu operacyjnego. Nawet konsola tylko do odczytu ujawnia mapy pamięci, sterowniki flash, argumenty uruchamiania, układy partycji i wersje firmware'u. Firmware może znajdować się w SPI NOR/NAND, eMMC lub innym urządzeniu; zasadniczo nie jest wykonywany z EEPROM-u, a pliki zapisane w zamontowanym trwałym systemie plików niekoniecznie znikają po ponownym uruchomieniu.

Istnieje kilka ścieżek pozyskiwania danych, a sekcja SPI opisuje bezpośrednie odczyty z zewnętrznej pamięci flash. Pozyskiwanie danych za pomocą konsoli może być mniej inwazyjne, gdy bootloader udostępnia już bezpieczne polecenie odczytu, jednak każde przerwanie uruchamiania lub polecenie dotyczące flash może wpłynąć na dostępność, dlatego należy zapisać pierwotny stan i unikać operacji zapisu/wymazywania.

Zrzucanie firmware'u za pomocą konsoli często rozpoczyna się od przerwania działania bootloadera. Wiele urządzeń z wbudowanym systemem Linux używa **Das U-Boot**, ale inne korzystają z własnych bootloaderów lub wyłączają interaktywną konsolę.

Aby sprawdzić, czy bootloader jest interaktywny, podłącz ścieżkę odbiorczą UART i terminal, gdy cel jest wyłączony, rozpocznij rejestrowanie, a następnie włącz urządzenie. Postępuj zgodnie z wyświetlanym monitem autobootu; w zależności od kompilacji przerwanie może wymagać naciśnięcia klawisza, krótkiej sekwencji klawiszy albo być całkowicie wyłączone.

Jeśli przerwanie się powiedzie, użyj `help`, `printenv` oraz poleceń rozpoznawczych tylko do odczytu, aby zrozumieć układ pamięci i pamięci masowej danego dostawcy przed uzyskaniem dostępu do adresów.

W U-Boot `md` wyświetla **adresowalną pamięć**, a nie automatycznie „EEPROM”. Najpierw użyj poleceń właściwych dla danej płyty, takich jak `mtd list`, `sf probe`, `mmc info`, `part list`, zmiennych środowiskowych i logów uruchamiania, aby zidentyfikować właściwy zmapowany adres lub załadować region flash do RAM-u. Następnie wyświetl znany zakres bajt po bajcie:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Zapisz dane wyjściowe portu szeregowego przed rozpoczęciem. Dane wyjściowe `md.b` zawierają adresy i kolumnę ASCII, więc są reprezentacją tekstową, a nie surowym obrazem ROM.

Usuń kolumny adresów i ASCII, połącz wyłącznie szesnastkowe pola bajtów i zdekoduj je do postaci binarnej (na przykład za pomocą `xxd -r -p`). Zweryfikuj oczekiwaną liczbę bajtów i przed analizą zapisz hash:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Następnie Binwalk identyfikuje znane sygnatury w zrekonstruowanym pliku binarnym. Bezpośredni odczyt flash przez odpowiedni interfejs SPI/eMMC/NAND jest zwykle szybszy i mniej podatny na błędy, gdy konsola nie może niezawodnie przesyłać danych.

U-Boot może wyłączać możliwość przerwania uruchamiania, wymagać sekwencji klawiszy specyficznej dla producenta albo blokować polecenia pamięci/flash. Śledź monit autoboot i log uruchamiania zamiast bezmyślnie wysyłać znaki. Jeśli nie można przerwać uruchamiania, zachowaj log uruchamiania i przejdź do nieinwazyjnej ścieżki pozyskiwania firmware.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacja Bus Pirate - tryb UART i ograniczenia elektryczne](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - karta katalogowa CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacja U-Boot - polecenie `md` do wyświetlania zawartości pamięci](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
