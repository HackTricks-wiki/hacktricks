# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to asynchroniczny interfejs szeregowy, który przesyła ramkowany strumień bitów bez wspólnego zegara. Nie należy mylić UART na poziomie logicznym z RS-232: RS-232 używa innych, często ujemnych poziomów napięcia i wymaga transceivera.<sup>[[1]](#references)[[3]](#references)</sup>

Zazwyczaj linia jest utrzymywana w stanie wysokim (wartość logiczna 1), gdy UART znajduje się w stanie bezczynności. Aby zasygnalizować rozpoczęcie transferu danych, nadajnik wysyła do odbiornika bit startu, podczas którego sygnał jest utrzymywany w stanie niskim (wartość logiczna 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających właściwy komunikat, po których następuje opcjonalny bit parzystości oraz jeden lub dwa bity stopu (o wartości logicznej 1), zależnie od konfiguracji. Bit parzystości, używany do wykrywania błędów, rzadko występuje w praktyce. Bit (lub bity) stopu oznaczają koniec transmisji.

Najczęściej stosowana konfiguracja to 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. UART wysyła najpierw najmniej znaczący bit danych, więc znak ASCII `C` (`0x43`) jest przesyłany jako: start `0`; dane `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcemy wysłać znak C, czyli 0x43 w ASCII, przez UART w konfiguracji 8N1](<../../images/image (764).png>)

Narzędzia sprzętowe do komunikacji przez UART:

- Adapter USB-to-serial
- Adaptery z układami CP2102 lub PL2303
- Narzędzie wielofunkcyjne, takie jak Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikowanie portów UART

Typowe złącze debugowania udostępnia piny **TX**, **RX** i **GND**; może również udostępniać pin **Vcc/Vref**, reset lub piny kontroli przepływu. Vcc nie jest sygnałem UART i zwykle powinno służyć wyłącznie jako napięcie odniesienia — nie należy podłączać go jako źródła zasilania, chyba że znane są schemat płytki i wymagania dotyczące prądu.<sup>[[2]](#references)[[3]](#references)</sup>

Zacznij od **wyłączonego** i odłączonego urządzenia:

- Użyj trybu pomiaru ciągłości, aby zidentyfikować **GND** względem znanej płaszczyzny masy, ekranu złącza lub masy zasilania. Nigdy nie używaj trybu pomiaru ciągłości/rezystancji na zasilanej płytce.
- Przed włączeniem zasilania urządzenia przełącz multimetr w tryb pomiaru napięcia stałego. Zmierz napięcie na kandydackich pinach względem masy, aby ustalić napięcie logiczne. Stabilne napięcie może oznaczać Vcc/Vref; nie zakładaj, że jego podłączenie jest bezpieczne.
- Obserwuj kandydackie piny analizatorem stanów logicznych lub oscyloskopem podczas rozruchu. **TX** zwykle pozostaje w stanie wysokim w stanie bezczynności i emituje serie ramek danych. Multimetr może wskazać zmiany wartości średniej, ale nie pozwala zweryfikować ramkowania ani szybkości transmisji.
- **RX** może pozostawać w stanie bezczynności i nie da się go bezpiecznie zidentyfikować wyłącznie na podstawie sąsiedztwa z TX. Prześledź ścieżki na płytce PCB, sprawdź dokumentację SoC lub użyj analizatora o wysokiej impedancji, zanim zaczniesz podawać na niego sygnał.

Zamiana TX i RX zwykle uniemożliwia komunikację; pomylenie zasilania, masy lub poziomów sygnału może trwale uszkodzić urządzenie lub adapter. Najpierw podłącz masę i rozpocznij od **samego odbioru** (TX urządzenia do RX adaptera).

Producenci mogą pominąć złącze, nie zamontować rezystorów szeregowych, wyłączyć konsolę w firmware lub udostępnić tylko TX. Prześledź pobliskie pola testowe i miejsca na rezystory do SoC, a tymczasowe połączenie o wysokiej impedancji dodaj dopiero po potwierdzeniu poziomu elektrycznego. Istnienie gwarancji nie oznacza, że dostępny port UART musi być obecny.

### Identyfikowanie szybkości transmisji UART

Najłatwiejszym sposobem ustalenia prawidłowej szybkości transmisji jest sprawdzenie sygnału wyjściowego pinu **TX** i próba odczytania danych. Jeśli odebrane dane są nieczytelne, zmień szybkość transmisji na kolejną możliwą wartość, aż dane staną się czytelne. Możesz użyć adaptera USB-to-serial lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, w połączeniu ze skryptem pomocniczym, np. [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej stosowane szybkości transmisji to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Pamiętaj, że w tym protokole należy połączyć TX jednego urządzenia z RX drugiego!

### Automatyczne przechwytywanie UART podczas rozruchu za pomocą SCPI

Jeśli komunikat rozruchowy jest krótki lub położenie padu TX jest nieznane, zautomatyzuj wielokrotne uruchamianie zamiast ręcznie obsługiwać zasilacz i oscyloskop. Podłącz programowalny zasilacz z ograniczeniem prądu do sprawdzonego wejścia zasilania urządzenia. Mierz sygnał na każdym kandydackim padzie TX za pomocą wejścia oscyloskopu o wysokiej impedancji i wspólnej masy; nie podawaj sygnału na pad.<sup>[[5]](#references)</sup>

VISA otwiera sesje instrumentów przez port szeregowy lub Ethernet, a SCPI steruje wyjściem, wyzwalaniem i odczytem przebiegów.<sup>[[5]](#references)[[6]](#references)</sup> Zainstaluj `pyvisa` i `pyvisa-py` (oraz `pyserial` dla zasobów VISA korzystających z portu szeregowego); `ResourceManager('@py')` jawnie wybiera backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Zastąp ciągi zasobów i komendy tymi, które obsługują używane instrumenty.<sup>[[5]](#references)</sup>

W przykładzie z Rigol MSO5000 uzbrój wyzwalanie jednokrotne na zbocze opadające przed włączeniem zasilania płytki: sygnał UART TX, który w stanie bezczynności jest wysoki, najpierw opada przy bicie startu.<sup>[[5]](#references)</sup> Ustaw próg wyzwalania między zmierzonymi poziomami stanu bezczynności i stanu niskiego, a podstawę czasu tak, aby objęła interesujący Cię przedział rozruchu.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` może ograniczyć wielokrotne wyzwalanie na kolejnych zboczach przy ciągłym przechwytywaniu, ale nie zastępuje sprawdzenia, czy przechwytywanie jednokrotne rzeczywiście się zakończyło.<sup>[[5]](#references)</sup> Poniższy przykład przechwytuje jeden rozruch i zapisuje zarówno próbki w postaci bajtów bez znaku, jak i metadane skalowania; po przekroczeniu limitu czasu wyłącza zasilanie urządzenia zamiast czekać bez końca.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Włączanie zasilania za pomocą PyVISA i jednokrotne przechwytywanie przebiegu UART</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

W przypadku przeglądu padów powtórz pojedynczy zapis po przesunięciu sondy albo pozostaw sesję zasilania otwartą i cyklicznie przełączaj wyjście, stosując czas podtrzymania zasilania podczas rozruchu i przerwę bez zasilania. Uzbrój oscyloskop ponownie przed każdym włączeniem zasilania, aby każdy plik odpowiadał jednemu uruchomieniu i jednemu padowi.<sup>[[5]](#references)</sup>

Preambuła Rigola ma postać `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> **Trzecia** wartość oznacza liczbę punktów, a nie częstotliwość próbkowania, jak podano w artykule.<sup>[[5]](#references)[[6]](#references)</sup> W podanym przykładzie `25,000,000` punktów i `xincrement = 2e-8` sekund oznaczają `1 / xincrement = 50,000,000` próbek na sekundę, a nie 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Zachowaj preambułę razem z plikiem binarnym i sprawdź, czy długość odczytu odpowiada wartości `<points>`; przewodnik opisuje odczyty segmentowane/wsadowe dla dużych rekordów.<sup>[[6]](#references)</sup>

Aby zdekodować przechwycony sygnał, zaimportuj `capture.bin` do PulseView jako **Raw Analog Data Without Header**, wybierz wartości bez znaku 8-bitowe (`U8`) i wprowadź częstotliwość próbkowania obliczoną na podstawie `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Zastosuj **Logic via Threshold** do kanału analogowego, wybierając próg między niskimi i wysokimi wartościami próbek.<sup>[[5]](#references)</sup> Zmierz szerokość czystego bitu startu, aby oszacować baud rate (około 17,36 µs dla 57 600 baud), a następnie zastosuj dekoder UART w PulseView i sprawdź, czy kilka ramek dekoduje się spójnie.<sup>[[5]](#references)</sup> Samo zbocze opadające nie dowodzi, że pad to UART.

## Adapter CP210X UART do TTY

Mostki CP210x USB-to-UART są stosowane na wielu płytkach prototypowych i niedrogich adapterach. Typowe moduły udostępniają piny zasilania obok GND, RXD i TXD, ale ich złącza i poziomy I/O są różne. Sprawdź rzeczywiste napięcie w projekcie płytki lub arkuszu danych. Zwykle podłącz tylko GND, RX adaptera do TX urządzenia docelowego oraz — po potwierdzeniu odbioru bez nadawania — TX adaptera do RX urządzenia docelowego. Nie podłączaj pinu zasilania 5 V/3,3 V adaptera, chyba że celowo zasilasz urządzenie docelowe, o którym wiadomo, że toleruje takie napięcie.<sup>[[3]](#references)</sup>

Jeśli adapter nie jest wykrywany, upewnij się, że w systemie hosta zainstalowano sterowniki CP210X. Po wykryciu i podłączeniu adaptera można użyć narzędzi takich jak picocom, minicom lub screen.

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

Skonfiguruj ustawienia, takie jak szybkość transmisji i nazwa urządzenia, w opcji `Serial port setup`.

Po konfiguracji uruchom `minicom`, aby otworzyć konsolę UART.

## UART przez Arduino UNO R3 (płytki z wyjmowanym układem Atmel 328p)

Jeśli adaptery UART Serial-to-USB są niedostępne, można użyć Arduino UNO R3, stosując prosty hack. Arduino UNO R3 jest zwykle łatwo dostępne, więc to rozwiązanie może zaoszczędzić sporo czasu.

Arduino UNO R3 ma wbudowany na płytce adapter USB-to-Serial. Aby uzyskać połączenie UART, wystarczy wyjąć z płytki mikrokontroler Atmel 328p. Ten hack działa z wariantami Arduino UNO R3, w których układ Atmel 328p nie jest przylutowany do płytki (w tym wariancie zastosowano wersję SMD). Połącz pin RX Arduino (Digital Pin 0) z pinem TX interfejsu UART, a pin TX Arduino (Digital Pin 1) z pinem RX interfejsu UART.

Użyj **Serial Monitor** w Arduino IDE lub dedykowanego terminala ustawionego na szybkość transmisji urządzenia docelowego. Klasyczne sygnały szeregowe Uno R3 mają logikę 5 V, dlatego przed podłączeniem do urządzenia docelowego pracującego z napięciem 3,3 V lub niższym użyj konwertera poziomów logicznych albo dzielnika napięcia.

## Bus Pirate

Poniższy zapis pokazuje użycie interfejsu starszej wersji firmware Bus Pirate do monitorowania wyjścia UART. Nowsze wersje firmware Bus Pirate używają poleceń takich jak `m uart`, `{`/`}`, `monitor` lub `bridge`; zapoznaj się z dokumentacją wersji zainstalowanej na urządzeniu.<sup>[[2]](#references)</sup>

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

## Zrzucanie firmware’u za pomocą konsoli UART

Konsola UART zapewnia dostęp w czasie działania do logów rozruchowych, a czasem także do bootloadera lub powłoki systemu operacyjnego. Nawet konsola tylko do odczytu ujawnia mapy pamięci, sterowniki flash, argumenty rozruchowe, układ partycji i wersje firmware’u. Firmware może znajdować się w SPI NOR/NAND, eMMC lub innym urządzeniu; zazwyczaj nie jest wykonywany z EEPROM-u, a pliki zapisane w zamontowanym trwałym systemie plików niekoniecznie znikają po ponownym uruchomieniu.

Istnieje kilka sposobów pozyskania danych, a sekcja dotycząca SPI opisuje bezpośredni odczyt z zewnętrznej pamięci flash. Pozyskiwanie danych za pomocą konsoli może być mniej inwazyjne, jeśli bootloader udostępnia bezpieczne polecenie odczytu, ale przerwanie rozruchu lub użycie polecenia flash może wpłynąć na dostępność urządzenia, dlatego należy zapisać stan początkowy i unikać operacji zapisu lub kasowania.

Zrzucanie firmware’u za pomocą konsoli często zaczyna się od przerwania pracy bootloadera. Wiele urządzeń z wbudowanym systemem Linux korzysta z **Das U-Boot**, ale inne używają zastrzeżonych bootloaderów lub mają wyłączoną interaktywną konsolę.

Aby sprawdzić, czy bootloader jest interaktywny, podłącz ścieżkę odbiorczą UART i terminal, gdy urządzenie docelowe jest wyłączone, rozpocznij rejestrowanie, a następnie włącz zasilanie. Postępuj zgodnie z wyświetlanym komunikatem o automatycznym rozruchu; zależnie od kompilacji przerwanie może wymagać naciśnięcia klawisza, krótkiej sekwencji albo być całkowicie wyłączone.

Jeśli uda się przerwać rozruch, użyj poleceń `help`, `printenv` i innych poleceń rozpoznawczych tylko do odczytu, aby poznać układ pamięci i nośników danego producenta przed uzyskaniem dostępu do adresów.

W U-Boot polecenie `md` wyświetla **pamięć adresowalną**, a nie automatycznie „EEPROM”. Najpierw użyj poleceń specyficznych dla danej płyty, takich jak `mtd list`, `sf probe`, `mmc info`, `part list`, zmiennych środowiskowych i logów rozruchowych, aby ustalić prawidłowy zmapowany adres lub załadować region pamięci flash do RAM. Następnie wyświetl znany zakres bajt po bajcie:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zapisz wyjście portu szeregowego przed rozpoczęciem. Wyjście `md.b` zawiera adresy i kolumnę ASCII, więc jest reprezentacją tekstową, a nie surowym obrazem ROM.

Usuń kolumny adresów i ASCII, połącz wyłącznie pola bajtów zapisane szesnastkowo i zdekoduj je do postaci binarnej (na przykład za pomocą `xxd -r -p`). Przed analizą sprawdź oczekiwaną liczbę bajtów i zapisz hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identyfikuje następnie znane sygnatury w zrekonstruowanym pliku binarnym. Bezpośredni odczyt pamięci flash przez odpowiedni interfejs SPI/eMMC/NAND jest zwykle szybszy i mniej podatny na błędy, gdy konsola nie może niezawodnie przesyłać danych.

U-Boot może wyłączać możliwość przerwania rozruchu, wymagać specyficznej dla producenta sekwencji klawiszy lub blokować polecenia dotyczące pamięci i flash. Kieruj się monitem autoboot i logiem rozruchu, zamiast bezmyślnie wysyłać znaki. Jeśli nie można przerwać pracy konsoli, zachowaj log rozruchu i skorzystaj z nieinwazyjnej metody pozyskania firmware.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacja Bus Pirate - tryb UART i limity elektryczne](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - karta katalogowa CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacja U-Boot - polecenie `md` do wyświetlania zawartości pamięci](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI i oprzyrządowanie sprzętowe dla inżynierów odwrotnej analizy, część 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Przewodnik programowania Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — konfiguracja backendu](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
