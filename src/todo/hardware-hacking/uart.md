# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to protokół szeregowy, co oznacza, że przesyła dane między komponentami jeden bit na raz. W przeciwieństwie do tego, protokoły komunikacji równoległej przesyłają dane jednocześnie przez wiele kanałów. Do powszechnych protokołów szeregowych należą RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express i USB.

Ogólnie rzecz biorąc, linia jest utrzymywana w stanie wysokim (na wartości logicznej 1), gdy UART jest w stanie bezczynności. Następnie, aby sygnalizować początek transferu danych, nadajnik wysyła bit startowy do odbiornika, podczas którego sygnał jest utrzymywany w stanie niskim (na wartości logicznej 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających rzeczywistą wiadomość, po czym następuje opcjonalny bit parzystości i jeden lub dwa bity stopu (z wartością logiczną 1), w zależności od konfiguracji. Bit parzystości, używany do sprawdzania błędów, rzadko występuje w praktyce. Bit stopu (lub bity) oznaczają koniec transmisji.

Najczęściej spotykaną konfigurację nazywamy 8N1: osiem bitów danych, brak parzystości i jeden bit stopu. Na przykład, jeśli chcielibyśmy wysłać znak C, czyli 0x43 w ASCII, w konfiguracji UART 8N1, wysłalibyśmy następujące bity: 0 (bit startowy); 0, 1, 0, 0, 0, 0, 1, 1 (wartość 0x43 w systemie binarnym) i 0 (bit stopu).

![](<../../images/image (764).png>)

Narzędzia sprzętowe do komunikacji z UART:

- adapter USB-do-szeregowego
- adaptery z chipami CP2102 lub PL2303
- wielofunkczne narzędzie, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikacja portów UART

UART ma 4 porty: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) i **GND**(Ground). Możesz być w stanie znaleźć 4 porty z literami **`TX`** i **`RX`** **napisanymi** na PCB. Ale jeśli nie ma żadnych wskazówek, możesz potrzebować spróbować znaleźć je samodzielnie, używając **multimetru** lub **analizatora logicznego**.

Z użyciem **multimetru** i urządzenia wyłączonego:

- Aby zidentyfikować pin **GND**, użyj trybu **Testu Ciągłości**, umieść czarny przewód w ziemi i testuj czerwonym, aż usłyszysz dźwięk z multimetru. Na PCB można znaleźć kilka pinów GND, więc możesz znaleźć lub nie ten, który należy do UART.
- Aby zidentyfikować port **VCC**, ustaw tryb **DC voltage** i ustaw go na 20 V. Czarny przewód na ziemi, a czerwony przewód na pinie. Włącz urządzenie. Jeśli multimetr mierzy stałe napięcie wynoszące 3,3 V lub 5 V, znalazłeś pin Vcc. Jeśli otrzymasz inne napięcia, spróbuj ponownie z innymi portami.
- Aby zidentyfikować port **TX**, ustaw tryb **DC voltage** na 20 V, czarny przewód na ziemi, a czerwony przewód na pinie, a następnie włącz urządzenie. Jeśli zauważysz, że napięcie waha się przez kilka sekund, a następnie stabilizuje się na wartości Vcc, najprawdopodobniej znalazłeś port TX. Dzieje się tak, ponieważ podczas włączania wysyła pewne dane debugowania.
- Port **RX** będzie najbliższy pozostałym 3, ma najmniejsze wahania napięcia i najniższą ogólną wartość ze wszystkich pinów UART.

Możesz pomylić porty TX i RX i nic się nie stanie, ale jeśli pomylisz porty GND i VCC, możesz uszkodzić obwód.

W niektórych urządzeniach docelowych port UART jest wyłączany przez producenta poprzez wyłączenie RX lub TX lub nawet obu. W takim przypadku może być pomocne prześledzenie połączeń na płytce drukowanej i znalezienie punktu wyjścia. Silnym wskazaniem na potwierdzenie braku wykrycia UART i przerwania obwodu jest sprawdzenie gwarancji urządzenia. Jeśli urządzenie zostało wysłane z jakąś gwarancją, producent pozostawia pewne interfejsy debugowania (w tym przypadku UART) i dlatego musiał odłączyć UART i ponownie go podłączyć podczas debugowania. Te piny wyjściowe można połączyć przez lutowanie lub przewody zworkowe.

### Identyfikacja prędkości baud UART

Najłatwiejszym sposobem na zidentyfikowanie odpowiedniej prędkości baud jest spojrzenie na **wyjście pinu TX i próba odczytania danych**. Jeśli dane, które otrzymujesz, nie są czytelne, przełącz się na następną możliwą prędkość baud, aż dane staną się czytelne. Możesz użyć adaptera USB-do-szeregowego lub wielofunkcyjnego urządzenia, takiego jak Bus Pirate, aby to zrobić, w połączeniu z pomocnym skryptem, takim jak [baudrate.py](https://github.com/devttys0/baudrate/). Najczęściej spotykane prędkości baud to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Ważne jest, aby zauważyć, że w tym protokole musisz połączyć TX jednego urządzenia z RX drugiego!

## Adapter CP210X UART do TTY

Chip CP210X jest używany w wielu płytkach prototypowych, takich jak NodeMCU (z esp8266) do komunikacji szeregowej. Te adaptery są stosunkowo niedrogie i mogą być używane do łączenia z interfejsem UART docelowego urządzenia. Urządzenie ma 5 pinów: 5V, GND, RXD, TXD, 3.3V. Upewnij się, że podłączasz napięcie zgodnie z wymaganiami docelowego urządzenia, aby uniknąć uszkodzeń. Na koniec podłącz pin RXD adaptera do TXD docelowego urządzenia, a pin TXD adaptera do RXD docelowego urządzenia.

W przypadku, gdy adapter nie jest wykrywany, upewnij się, że sterowniki CP210X są zainstalowane w systemie gospodarza. Gdy adapter zostanie wykryty i podłączony, można używać narzędzi takich jak picocom, minicom lub screen.

Aby wylistować urządzenia podłączone do systemów Linux/MacOS:
```
ls /dev/
```
Aby uzyskać podstawową interakcję z interfejsem UART, użyj następującego polecenia:
```
picocom /dev/<adapter> --baud <baudrate>
```
Aby skonfigurować minicom, użyj następującego polecenia:
```
minicom -s
```
Skonfiguruj ustawienia, takie jak baudrate i nazwa urządzenia w opcji `Serial port setup`.

Po konfiguracji użyj polecenia `minicom`, aby uruchomić konsolę UART.

## UART przez Arduino UNO R3 (wymienny chip Atmel 328p)

W przypadku braku adapterów UART Serial do USB, Arduino UNO R3 można użyć z szybkim hackiem. Ponieważ Arduino UNO R3 jest zazwyczaj dostępne wszędzie, może to zaoszczędzić dużo czasu.

Arduino UNO R3 ma wbudowany adapter USB do Serial na samej płycie. Aby uzyskać połączenie UART, wystarczy wyjąć chip mikrokontrolera Atmel 328p z płyty. Ten hack działa na wariantach Arduino UNO R3, w których Atmel 328p nie jest przylutowany do płyty (używana jest wersja SMD). Podłącz pin RX Arduino (pin cyfrowy 0) do pinu TX interfejsu UART i pin TX Arduino (pin cyfrowy 1) do pinu RX interfejsu UART.

Na koniec zaleca się użycie Arduino IDE, aby uzyskać konsolę szeregową. W sekcji `tools` w menu wybierz opcję `Serial Console` i ustaw baud rate zgodnie z interfejsem UART.

## Bus Pirate

W tym scenariuszu zamierzamy podsłuchiwać komunikację UART Arduino, które wysyła wszystkie wydruki programu do Serial Monitor.
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
## Zrzut oprogramowania układowego za pomocą konsoli UART

Konsola UART zapewnia doskonały sposób na pracę z podstawowym oprogramowaniem układowym w środowisku uruchomieniowym. Jednak gdy dostęp do konsoli UART jest tylko do odczytu, może to wprowadzać wiele ograniczeń. W wielu urządzeniach wbudowanych oprogramowanie układowe jest przechowywane w EEPROM i wykonywane w procesorach, które mają pamięć ulotną. Dlatego oprogramowanie układowe jest utrzymywane w trybie tylko do odczytu, ponieważ oryginalne oprogramowanie układowe podczas produkcji znajduje się wewnątrz EEPROM, a wszelkie nowe pliki mogłyby zostać utracone z powodu pamięci ulotnej. Dlatego zrzut oprogramowania układowego jest cennym wysiłkiem podczas pracy z wbudowanym oprogramowaniem układowym.

Istnieje wiele sposobów, aby to zrobić, a sekcja SPI obejmuje metody ekstrakcji oprogramowania układowego bezpośrednio z EEPROM za pomocą różnych urządzeń. Zaleca się jednak najpierw spróbować zrzutu oprogramowania układowego za pomocą UART, ponieważ zrzut oprogramowania układowego za pomocą urządzeń fizycznych i interakcji zewnętrznych może być ryzykowny.

Zrzut oprogramowania układowego z konsoli UART wymaga najpierw uzyskania dostępu do bootloaderów. Wiele popularnych dostawców korzysta z uboot (Universal Bootloader) jako swojego bootloadera do ładowania systemu Linux. Dlatego uzyskanie dostępu do uboot jest konieczne.

Aby uzyskać dostęp do bootloadera, podłącz port UART do komputera i użyj dowolnego narzędzia konsoli szeregowej, a zasilanie urządzenia powinno być odłączone. Gdy konfiguracja jest gotowa, naciśnij klawisz Enter i przytrzymaj go. Na koniec podłącz zasilanie do urządzenia i pozwól mu się uruchomić.

Zrobienie tego przerwie ładowanie uboot i wyświetli menu. Zaleca się zrozumienie poleceń uboot i użycie menu pomocy do ich wylistowania. Może to być polecenie `help`. Ponieważ różni dostawcy używają różnych konfiguracji, konieczne jest zrozumienie każdej z nich osobno.

Zazwyczaj polecenie do zrzutu oprogramowania układowego to:
```
md
```
które oznacza "zrzut pamięci". To zrzuci pamięć (zawartość EEPROM) na ekran. Zaleca się zapisanie wyjścia z konsoli szeregowej przed rozpoczęciem procedury, aby uchwycić zrzut pamięci.

Na koniec wystarczy usunąć wszystkie niepotrzebne dane z pliku dziennika i zapisać plik jako `filename.rom`, a następnie użyć binwalk do wyodrębnienia zawartości:
```
binwalk -e <filename.rom>
```
To będzie lista możliwych zawartości z EEPROM zgodnie z podpisami znalezionymi w pliku hex.

Należy jednak zauważyć, że nie zawsze jest tak, że uboot jest odblokowany, nawet jeśli jest używany. Jeśli klawisz Enter nie działa, sprawdź inne klawisze, takie jak klawisz Spacji itp. Jeśli bootloader jest zablokowany i nie zostanie przerwany, ta metoda nie zadziała. Aby sprawdzić, czy uboot jest bootloaderem dla urządzenia, sprawdź wyjście na konsoli UART podczas uruchamiania urządzenia. Może wspominać o uboot podczas uruchamiania.

{{#include ../../banners/hacktricks-training.md}}
