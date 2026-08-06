# UART

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

UART to protokół szeregowy, co oznacza, że przesyła dane między komponentami bit po bicie. W przeciwieństwie do tego, protokoły komunikacji równoległej przesyłają dane jednocześnie przez wiele kanałów. Do popularnych protokołów szeregowych należą RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express oraz USB.

Zazwyczaj linia jest utrzymywana w stanie wysokim (o logicznej wartości 1), gdy UART znajduje się w stanie bezczynności. Następnie, aby zasygnalizować rozpoczęcie transmisji danych, nadajnik wysyła do odbiornika bit startu, podczas którego sygnał jest utrzymywany w stanie niskim (o logicznej wartości 0). Następnie nadajnik wysyła od pięciu do ośmiu bitów danych zawierających właściwą wiadomość, opcjonalnie bit parzystości oraz jeden lub dwa bity stopu (o logicznej wartości 1), zależnie od konfiguracji. Bit parzystości, używany do sprawdzania błędów, jest rzadko spotykany w praktyce. Bit stopu (lub bity stopu) oznacza koniec transmisji.

Najpopularniejszą konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcielibyśmy wysłać znak C, czyli 0x43 w ASCII, w konfiguracji UART 8N1, wysłalibyśmy następujące bity: 0 (bit startu); 0, 1, 0, 0, 0, 0, 1, 1 (wartość 0x43 w systemie binarnym) oraz 0 (bit stopu).

![UART: Najpopularniejszą konfigurację nazywamy 8N1: osiem bitów danych, brak bitu parzystości i jeden bit stopu. Na przykład, jeśli chcielibyśmy wysłać znak C, czyli 0x43 w ASCII, w konfiguracji UART 8N1](<../../images/image (764).png>)

Narzędzia sprzętowe do komunikacji z UART:

- Adapter USB-to-serial
- Adaptery z układami CP2102 lub PL2303
- Narzędzie wielofunkcyjne, takie jak: Bus Pirate, Adafruit FT232H, Shikra lub Attify Badge

### Identyfikowanie portów UART

UART ma 4 porty: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) oraz **GND** (Ground). Możliwe, że znajdziesz 4 porty z literami **`TX`** i **`RX`** **zapisanymi** na PCB. Jeśli jednak nie ma żadnych oznaczeń, może być konieczne samodzielne ich znalezienie za pomocą **multimetru** lub **analizatora logicznego**.

Za pomocą **multimetru** i przy wyłączonym urządzeniu:

- Aby zidentyfikować pin **GND**, użyj trybu **Continuity Test**, przyłóż czarną sondę do masy i sprawdzaj piny czerwoną sondą, aż usłyszysz dźwięk z multimetru. Na PCB można znaleźć kilka pinów GND, więc mogłeś znaleźć pin należący do UART albo nie.
- Aby zidentyfikować port **VCC**, ustaw tryb napięcia **DC** i zakres do 20 V. Czarną sondę przyłóż do masy, a czerwoną do pinu. Włącz urządzenie. Jeśli multimetr zmierzy stałe napięcie wynoszące 3,3 V lub 5 V, znaleziono pin Vcc. Jeśli uzyskasz inne napięcia, ponów próbę z innymi portami.
- Aby zidentyfikować **port** **TX**, ustaw tryb napięcia **DC** i zakres do 20 V, czarną sondę przyłóż do masy, a czerwoną do pinu, po czym włącz urządzenie. Jeśli napięcie będzie się zmieniać przez kilka sekund, a następnie ustabilizuje się na poziomie wartości Vcc, najprawdopodobniej znaleziono port TX. Dzieje się tak, ponieważ podczas uruchamiania urządzenie wysyła dane debugowania.
- **Port RX** będzie najbliżej pozostałych 3 portów, będzie charakteryzować się najmniejszymi wahaniami napięcia i najniższą ogólną wartością spośród wszystkich pinów UART.

Możesz pomylić porty TX i RX i nic się nie stanie, ale jeśli pomylisz porty GND i VCC, możesz spalić układ.

W niektórych urządzeniach docelowych port UART jest wyłączony przez producenta poprzez wyłączenie RX, TX albo obu tych portów. W takim przypadku pomocne może być prześledzenie połączeń na płytce drukowanej i znalezienie punktu breakout. Istotną wskazówką potwierdzającą brak wykrywania UART i przerwanie obwodu jest sprawdzenie gwarancji urządzenia. Jeśli urządzenie zostało dostarczone z gwarancją, producent pozostawia niektóre interfejsy debugowania (w tym przypadku UART), a zatem musiał odłączyć UART i ponownie go podłączyć podczas debugowania. Te piny breakout można połączyć przez lutowanie lub przewody jumper.

### Identyfikowanie szybkości transmisji UART

Najłatwiejszym sposobem zidentyfikowania prawidłowej szybkości transmisji jest obserwowanie **wyjścia pinu TX i próba odczytania danych**. Jeśli odebrane dane nie są czytelne, przełącz się na kolejną możliwą szybkość transmisji, aż dane staną się czytelne. Możesz użyć adaptera USB-to-serial lub urządzenia wielofunkcyjnego, takiego jak Bus Pirate, wraz ze skryptem pomocniczym, na przykład [baudrate.py](https://github.com/devttys0/baudrate/). Najpopularniejsze szybkości transmisji to 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Należy pamiętać, że w tym protokole trzeba połączyć TX jednego urządzenia z RX drugiego!

## Adapter CP210X UART do TTY

Układ CP210X jest używany na wielu płytkach prototypingowych, takich jak NodeMCU (z esp8266), do komunikacji szeregowej. Adaptery te są stosunkowo niedrogie i można ich używać do łączenia się z interfejsem UART urządzenia docelowego. Urządzenie ma 5 pinów: 5V, GND, RXD, TXD, 3.3V. Upewnij się, że napięcie jest zgodne z napięciem obsługiwanym przez urządzenie docelowe, aby uniknąć uszkodzeń. Na koniec połącz pin RXD adaptera z TXD urządzenia docelowego, a pin TXD adaptera z RXD urządzenia docelowego.

Jeśli adapter nie zostanie wykryty, upewnij się, że sterowniki CP210X są zainstalowane w systemie hosta. Po wykryciu i podłączeniu adaptera można użyć narzędzi takich jak picocom, minicom lub screen.

Aby wyświetlić listę urządzeń podłączonych do systemów Linux/MacOS:
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

Po konfiguracji użyj komendy `minicom`, aby uruchomić UART Console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Jeśli adaptery UART Serial to USB nie są dostępne, Arduino UNO R3 można wykorzystać po wykonaniu szybkiego hacku. Ponieważ Arduino UNO R3 jest zwykle dostępne wszędzie, może to zaoszczędzić dużo czasu.

Arduino UNO R3 ma wbudowany na płytce adapter USB to Serial. Aby uzyskać połączenie UART, wystarczy wyjąć z płytki układ mikrokontrolera Atmel 328p. Ten hack działa z wariantami Arduino UNO R3, w których Atmel 328p nie jest przylutowany do płytki (zastosowano w nich wersję SMD). Połącz pin RX Arduino (Digital Pin 0) z pinem TX interfejsu UART, a pin TX Arduino (Digital Pin 1) z pinem RX interfejsu UART.

Na koniec zaleca się użycie Arduino IDE w celu uzyskania Serial Console. W sekcji `tools` menu wybierz opcję `Serial Console` i ustaw baud rate zgodnie z interfejsem UART.

## Bus Pirate

W tym scenariuszu będziemy przechwytywać komunikację UART Arduino, które wysyła wszystkie komunikaty programu do Serial Monitor.
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
## Dumping Firmware with UART Console

UART Console zapewnia świetny sposób pracy z bazowym firmware w środowisku runtime. Jednak gdy dostęp do UART Console jest tylko do odczytu, może to wprowadzać wiele ograniczeń. W wielu urządzeniach embedded firmware jest przechowywany w układach EEPROM i wykonywany przez procesory wykorzystujące pamięć ulotną. Dlatego firmware pozostaje tylko do odczytu, ponieważ oryginalny firmware z etapu produkcji znajduje się w samym EEPROM, a wszelkie nowe pliki zostałyby utracone z powodu wykorzystania pamięci ulotnej. W związku z tym dumping firmware jest wartościowym działaniem podczas pracy z embedded firmware.

Istnieje wiele sposobów wykonania tej czynności, a sekcja SPI obejmuje metody bezpośredniego pozyskiwania firmware z EEPROM przy użyciu różnych urządzeń. Zaleca się jednak najpierw spróbować wykonać dumping firmware za pomocą UART, ponieważ pozyskiwanie firmware przy użyciu fizycznych urządzeń i zewnętrznych interakcji może być ryzykowne.

Dumping firmware z UART Console wymaga najpierw uzyskania dostępu do bootloaderów. Wielu popularnych vendorów korzysta z uboot (Universal Bootloader) jako bootloadera do ładowania systemu Linux. Dlatego konieczne jest uzyskanie dostępu do uboot.

Aby uzyskać dostęp do bootloadera, podłącz port UART do komputera i użyj dowolnego narzędzia Serial Console, pozostawiając odłączone zasilanie urządzenia. Gdy konfiguracja będzie gotowa, naciśnij i przytrzymaj klawisz Enter. Następnie podłącz zasilanie urządzenia i pozwól mu się uruchomić.

Spowoduje to przerwanie ładowania uboot i wyświetlenie menu. Zaleca się zapoznanie z komendami uboot oraz użycie menu help do ich wyświetlenia. Może to być komenda `help`. Ponieważ różni vendorzy korzystają z różnych konfiguracji, konieczne jest osobne zrozumienie każdej z nich.

Zwykle komenda do wykonania dumpingu firmware wygląda następująco:
```
md
```
co oznacza „memory dump”. Spowoduje to zrzut pamięci (zawartości EEPROM) na ekranie. Zaleca się rejestrowanie danych wyjściowych Serial Console przed rozpoczęciem procedury, aby przechwycić zrzut pamięci.

Na koniec usuń wszystkie niepotrzebne dane z pliku dziennika, zapisz plik jako `filename.rom` i użyj binwalk do wyodrębnienia zawartości:
```
binwalk -e <filename.rom>
```
Spowoduje to wyświetlenie możliwej zawartości EEPROM zgodnie z sygnaturami znalezionymi w pliku hex.

Należy jednak pamiętać, że uboot nie zawsze jest odblokowany, nawet jeśli jest używany. Jeśli klawisz Enter nie powoduje żadnej reakcji, sprawdź inne klawisze, takie jak spacja. Jeśli bootloader jest zablokowany i nie można przerwać jego działania, ta metoda nie zadziała. Aby sprawdzić, czy uboot jest bootloaderem urządzenia, sprawdź dane wyjściowe w UART Console podczas uruchamiania urządzenia. Podczas uruchamiania może pojawić się wzmianka o uboot.

{{#include ../../banners/hacktricks-training.md}}
