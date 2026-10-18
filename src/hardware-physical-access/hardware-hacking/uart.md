# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to asynchroniczny interfejs szeregowy, który przesyła strumień bitów w ramkach bez wspólnego zegara. Nie należy mylić UART o poziomach logicznych z RS-232: RS-232 używa innych, często ujemnych poziomów napięcia i wymaga transceivera.<sup>[[1]](#references)[[3]](#references)</sup>

Zwykle linia jest utrzymywana w stanie wysokim (wartość logiczna 1), gdy UART jest w stanie bezczynności. Aby zasygnalizować rozpoczęcie transmisji danych, nadajnik wysyła do odbiornika bit startu, podczas którego sygnał jest utrzymywany w stanie niskim (wartość logiczna 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających właściwą wiadomość, po których następuje opcjonalny bit parzystości i jeden lub dwa bity stopu (o wartości logicznej 1), zależnie od konfiguracji. Bit parzystości, używany do wykrywania błędów, rzadko występuje w praktyce. Bit (lub bity) stopu oznacza koniec transmisji.

Najczęściej stosowana konfiguracja to 8N1: osiem bitów danych, brak parzystości i jeden bit stopu. UART wysyła najpierw najmniej znaczący bit danych, więc znak ASCII `C` (`0x43`) jest przesyłany jako: start `0`; dane `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najczęściej stosowaną konfigurację nazywamy 8N1: osiem bitów danych, brak parzystości i jeden bit stopu. Na przykład, jeśli chcemy wysłać znak C, czyli 0x43 w ASCII, za pomocą UART 8N1](<../../images/image (764).png>)

Narzędzia sprzętowe do komunikacji przez UART:

- Adapter USB-to-serial
- Adaptery z układami CP2102 lub PL2303
- Narzędzia wielofunkcyjne, takie jak Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikowanie portów UART

Typowe złącze debugowania udostępnia piny **TX**, **RX** i **GND**; może też udostępniać pin **Vcc/Vref**, reset lub piny sterowania przepływem. Vcc nie jest sygnałem UART i zwykle należy go używać wyłącznie jako napięcia odniesienia — a nie źródła zasilania — chyba że znane są schemat płyty i wymagania dotyczące prądu.<sup>[[2]](#references)[[3]](#references)</sup>

Zacznij od wyłączenia urządzenia i odłączenia go od zasilania:

- Zidentyfikuj **GND** w trybie pomiaru ciągłości, sprawdzając połączenie ze znaną masą, ekranem złącza lub masą zasilania. Nigdy nie używaj trybu pomiaru ciągłości/rezystancji na zasilanej płycie.
- Przed włączeniem zasilania urządzenia przełącz multimetr w tryb pomiaru napięcia stałego. Zmierz napięcie na potencjalnych pinach względem masy, aby ustalić poziom logiczny. Stabilne napięcie może oznaczać Vcc/Vref; nie zakładaj, że można bezpiecznie podłączyć ten pin.
- Obserwuj potencjalne piny analizatorem logicznym lub oscyloskopem podczas uruchamiania urządzenia. **TX** zwykle pozostaje w stanie wysokim w spoczynku i pokazuje serie ramek danych. Multimetr może wskazywać zmiany wartości średniej, ale nie pozwala zweryfikować ramek ani szybkości transmisji.
- **RX** może pozostawać w stanie spoczynku i nie da się go bezpiecznie zidentyfikować wyłącznie na podstawie sąsiedztwa z TX. Prześledź ścieżki na PCB, sprawdź dokumentację SoC lub użyj analizatora o wysokiej impedancji, zanim zaczniesz sterować tym pinem.

Zamiana TX z RX zwykle uniemożliwia komunikację; pomylenie zasilania, masy lub poziomów sygnału może trwale uszkodzić urządzenie albo adapter. Najpierw podłącz masę i rozpocznij od odbioru bez nadawania (TX urządzenia do RX adaptera).

Producenci mogą pominąć złącze, pozostawić nieobsadzone rezystory szeregowe, wyłączyć konsolę w firmware lub udostępnić tylko TX. Prześledź ścieżki pobliskich padów testowych i miejsc na rezystory do SoC, a tymczasowe połączenie o wysokiej impedancji wykonaj dopiero po potwierdzeniu poziomu elektrycznego. Gwarancja nie oznacza, że urządzenie musi mieć dostępny port UART.

### Odzyskiwanie padu TX, który wydaje się utrzymywać stan niski

To, że oznaczony pad TX pozostaje w stanie niskim w pierwszym zarejestrowanym przebiegu oscyloskopu, nie wystarczy, by wykluczyć UART. Po potwierdzeniu napięcia logicznego urządzenia i wspólnej masy spróbuj użyć słabego podciągania do zasilania (w udokumentowanym przykładzie użyto **10 kΩ do 3.3 V**) i ponownie zarejestruj przebieg podczas naciskania przycisków lub uruchamiania urządzenia. Używaj wyłącznie zweryfikowanej szyny zasilającej urządzenia; nie podłączaj rezystora podciągającego do nieznanego ani aktywnie sterowanego sygnału. Jeśli pojawią się przejścia tworzące ramki, zmierz najkrótszy czysty okres bitu, aby oszacować szybkość transmisji, zanim podłączysz pad do adaptera szeregowego wyłącznie w trybie odbioru. W przykładzie odzyskano w ten sposób logi zdarzeń przycisków z szybkością 115200 bodów, ale nie uzyskano zrzutu firmware.<sup>[[8]](#references)</sup>

### Identyfikowanie szybkości transmisji UART

Najłatwiej ustalić prawidłową szybkość transmisji, obserwując wyjście pinu **TX** i próbując odczytać dane. Jeśli odebrane dane są nieczytelne, przełącz się na kolejną możliwą szybkość, aż dane staną się czytelne. Możesz użyć adaptera USB-to-serial lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, w połączeniu ze skryptem pomocniczym, na przykład [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej stosowane szybkości transmisji to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Pamiętaj, że w tym protokole należy połączyć TX jednego urządzenia z RX drugiego!

### Automatyzacja przechwytywania UART podczas uruchamiania za pomocą SCPI

Jeśli komunikaty podczas uruchamiania są krótkie lub pad TX jest nadal nieznany, zautomatyzuj wielokrotne uruchamianie zamiast ręcznie obsługiwać zasilacz i oscyloskop. Podłącz programowalny zasilacz z ograniczeniem prądu do zweryfikowanego wejścia zasilania urządzenia. Obserwuj każdy potencjalny pad TX za pomocą wejścia oscyloskopu o wysokiej impedancji i wspólnej masy; nie steruj tym padem.<sup>[[5]](#references)</sup>

VISA otwiera sesje instrumentów przez port szeregowy lub Ethernet, natomiast SCPI steruje wyjściem, wyzwalaniem i odczytem przebiegów.<sup>[[5]](#references)[[6]](#references)</sup> Zainstaluj `pyvisa` i `pyvisa-py` (oraz `pyserial` dla zasobów VISA korzystających z portu szeregowego); `ResourceManager('@py')` jawnie wybiera backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Zastąp ciągi zasobów i polecenia wartościami obsługiwanymi przez używane instrumenty.<sup>[[5]](#references)</sup>

W przykładzie z Rigol MSO5000 przed włączeniem zasilania płyty uzbrój pojedyncze wyzwalanie zboczem opadającym: bezczynny sygnał UART TX w stanie wysokim najpierw opada, wysyłając bit startu.<sup>[[5]](#references)</sup> Ustaw próg wyzwalania między zmierzonymi poziomami stanu wysokiego i niskiego oraz dobierz podstawę czasu tak, by objęła interesujący Cię okres uruchamiania.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` może ograniczyć wielokrotne wyzwalanie na zboczach podczas ciągłego przechwytywania, ale nie zastępuje sprawdzenia, czy przechwytywanie pojedyncze rzeczywiście zostało zakończone.<sup>[[5]](#references)</sup> Poniższy przykład przechwytuje jedno uruchomienie i zapisuje zarówno próbki jako bajty bez znaku, jak i metadane skalowania; po przekroczeniu limitu czasu wyłącza zasilanie urządzenia zamiast czekać bez końca.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Włączenie zasilania za pomocą PyVISA i przechwytywanie przebiegu UART w trybie pojedynczym</summary>

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

W ramach przeglądu padów powtórz pojedynczy zapis po przesunięciu sondy albo pozostaw sesję zasilania otwartą i cyklicznie włączaj wyjście, stosując czas podtrzymania po uruchomieniu i przerwę po wyłączeniu. Uzbrój oscyloskop ponownie przed każdym włączeniem zasilania, aby każdy plik odpowiadał jednemu uruchomieniu i jednemu padowi.<sup>[[5]](#references)</sup>

Preambuła Rigola ma postać `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> **Trzecia** wartość oznacza liczbę punktów, a nie częstotliwość próbkowania, jak podano w artykule.<sup>[[5]](#references)[[6]](#references)</sup> W podanym przykładzie `25,000,000` punktów i `xincrement = 2e-8` sekundy oznaczają `1 / xincrement = 50,000,000` próbek na sekundę, a nie 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Zachowaj preambułę razem z plikiem binarnym i sprawdź, czy długość odczytu odpowiada wartości `<points>`; poradnik opisuje odczyty segmentowane/partiami dla dużych rekordów.<sup>[[6]](#references)</sup>

Aby zdekodować zarejestrowany sygnał, zaimportuj `capture.bin` do PulseView jako **Raw Analog Data Without Header**, wybierz wartości bez znaku 8-bitowe (`U8`) i podaj częstotliwość próbkowania obliczoną na podstawie `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Zastosuj **Logic via Threshold** do kanału analogowego, wybierając próg pomiędzy niskimi i wysokimi wartościami próbek.<sup>[[5]](#references)</sup> Zmierz szerokość czystego bitu startu, aby oszacować baud rate (około 17.36 µs dla 57,600 baud), a następnie zastosuj dekoder UART PulseView i sprawdź, czy kilka ramek jest dekodowanych spójnie.<sup>[[5]](#references)</sup> Samo zbocze opadające nie dowodzi, że pad jest UART.

## Adapter CP210X UART do TTY

Mostki CP210x USB-to-UART są stosowane na wielu płytkach prototypowych i niedrogich adapterach. Typowe moduły udostępniają piny zasilania obok GND, RXD i TXD, ale ich złącza i poziomy I/O są różne. Sprawdź rzeczywiste napięcie w projekcie płytki lub karcie katalogowej. Zwykle należy podłączyć tylko GND i RX adaptera do TX urządzenia docelowego, a po walidacji odbioru również TX adaptera do RX urządzenia docelowego. Nie podłączaj pinu zasilania 5 V/3.3 V adaptera, chyba że celowo zasilasz urządzenie docelowe, o którym wiadomo, że toleruje takie napięcie.<sup>[[3]](#references)</sup>

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

Skonfiguruj ustawienia, takie jak baudrate i nazwa urządzenia, w opcji `Serial port setup`.

Po konfiguracji uruchom `minicom`, aby otworzyć konsolę UART.

## UART przez Arduino UNO R3 (płyty z wyjmowanym układem Atmel 328p)

Jeśli adaptery UART Serial-to-USB nie są dostępne, można zastosować szybki hack z użyciem Arduino UNO R3. Ponieważ Arduino UNO R3 jest zwykle łatwo dostępne, może to zaoszczędzić sporo czasu.

Arduino UNO R3 ma wbudowany na płytce adapter USB-to-Serial. Aby uzyskać połączenie UART, wystarczy wyjąć z płytki mikrokontroler Atmel 328p. Ten hack działa z wariantami Arduino UNO R3, w których układ Atmel 328p nie jest przylutowany do płytki (zastosowano wersję SMD). Połącz pin RX Arduino (pin cyfrowy 0) z pinem TX interfejsu UART, a pin TX Arduino (pin cyfrowy 1) z pinem RX interfejsu UART.

Użyj **Serial Monitor** w Arduino IDE lub dedykowanego terminala ustawionego na docelową prędkość transmisji. Klasyczne sygnały szeregowe Uno R3 używają logiki 5 V, dlatego przed podłączeniem do urządzenia docelowego pracującego z napięciem 3,3 V lub niższym zastosuj konwerter poziomów logicznych albo dzielnik napięcia.

## Bus Pirate

Poniższy zapis sesji używa starszego interfejsu firmware Bus Pirate do monitorowania wyjścia UART. Nowsze wersje firmware Bus Pirate używają poleceń takich jak `m uart`, `{`/`}`, `monitor` lub `bridge`; zapoznaj się z dokumentacją dla zainstalowanej wersji.<sup>[[2]](#references)</sup>

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

Konsola UART zapewnia dostęp w czasie działania do logów rozruchowych, a czasem także do bootloadera lub powłoki systemu operacyjnego. Nawet konsola tylko do odczytu ujawnia mapy pamięci, sterowniki pamięci flash, argumenty rozruchowe, układ partycji i wersje firmware’u. Firmware może znajdować się w SPI NOR/NAND, eMMC lub innym urządzeniu; zasadniczo nie jest wykonywany z EEPROM, a pliki zapisane w zamontowanym trwałym systemie plików niekoniecznie znikają po ponownym uruchomieniu.

Istnieje kilka sposobów pozyskania firmware’u, a sekcja SPI omawia bezpośredni odczyt z zewnętrznej pamięci flash. Pozyskanie danych za pomocą konsoli może być mniej inwazyjne, jeśli bootloader udostępnia bezpieczne polecenie odczytu. Każde przerwanie rozruchu lub polecenie dotyczące pamięci flash może jednak wpłynąć na dostępność urządzenia, dlatego należy zapisać jego pierwotny stan i unikać operacji zapisu/kasowania.

Zrzucanie firmware’u za pomocą konsoli często zaczyna się od przerwania działania bootloadera. Wiele urządzeń z wbudowanym systemem Linux korzysta z **Das U-Boot**, ale inne używają zastrzeżonych bootloaderów lub mają wyłączoną interaktywną konsolę.

Aby sprawdzić, czy bootloader jest interaktywny, podłącz ścieżkę odbiorczą UART i terminal, gdy urządzenie docelowe jest wyłączone, rozpocznij logowanie i włącz urządzenie. Postępuj zgodnie z wyświetlanym monitem autoboot; w zależności od kompilacji przerwanie może wymagać naciśnięcia klawisza, krótkiej sekwencji albo być całkowicie wyłączone.

Jeśli uda się przerwać rozruch, użyj `help`, `printenv` i poleceń rozpoznawczych tylko do odczytu, aby poznać układ pamięci i nośników danego producenta, zanim uzyskasz dostęp do adresów.

W U-Boot polecenie `md` wyświetla **adresowalną pamięć**, a nie automatycznie „EEPROM”. Najpierw użyj poleceń właściwych dla danej płyty, takich jak `mtd list`, `sf probe`, `mmc info`, `part list`, zmiennych środowiskowych i logów rozruchowych, aby zidentyfikować prawidłowy mapowany adres lub załadować obszar pamięci flash do RAM. Następnie wyświetl znany zakres bajt po bajcie:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zapisz wyjście portu szeregowego przed rozpoczęciem. Wyjście `md.b` zawiera adresy i kolumnę ASCII, więc jest reprezentacją tekstową, a nie surowym obrazem ROM.

Usuń kolumny adresów i ASCII, połącz wyłącznie pola bajtów szesnastkowych i zdekoduj je do postaci binarnej (na przykład za pomocą `xxd -r -p`). Zweryfikuj oczekiwaną liczbę bajtów i przed analizą zapisz hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identyfikuje następnie znane sygnatury w odtworzonym pliku binarnym. Bezpośredni odczyt pamięci flash przez odpowiedni interfejs SPI/eMMC/NAND jest zwykle szybszy i mniej podatny na błędy, gdy konsola nie może niezawodnie przesyłać danych.

U-Boot może wyłączyć możliwość przerwania, wymagać specyficznej dla producenta sekwencji klawiszy lub zablokować polecenia dotyczące pamięci RAM/pamięci flash. Reaguj na komunikat autoboot i log rozruchu, zamiast bezmyślnie wysyłać znaki. Jeśli nie można przerwać działania konsoli, zachowaj log rozruchu i przejdź do nieinwazyjnej metody pozyskiwania firmware’u.

## References

- [1] [Podręcznik referencyjny rodziny Microchip PIC32 — UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacja Bus Pirate — tryb UART i limity elektryczne](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs — karta katalogowa CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacja U-Boot — polecenie wyświetlania pamięci `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI i oprzyrządowanie sprzętowe dla inżynierów wstecznych, część 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Przewodnik programowania Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — konfiguracja backendu](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — odświeżenie wiedzy z hackingu sprzętowego, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
