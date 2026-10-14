# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Przed podłączeniem Bus Pirate sprawdź napięcie docelowe, pinout, układ rezystorów podciągających i wspólną masę. Nie włączaj zasilania Bus Pirate na aktywnej magistrali zasilanej przez urządzenie docelowe, jeśli chcesz ją tylko sniffować; dwa źródła zasilania mogą ze sobą konkurować i uszkodzić sprzęt. Poniższy zapis sesji to przykład dotyczący konkretnego urządzenia: Bus Pirate v3 z firmware społecznościowym, a nie uniwersalna instrukcja podłączania.<sup>[[1]](#references)[[2]](#references)</sup>

Aby sprawdzić, czy Bus Pirate działa, podłącz +5V do VPU, a 3,3 V do ADC, połącz się z Bus Pirate (na przykład za pomocą Tera Term) i użyj polecenia `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Jak widać w poprzednim wierszu poleceń, znaleziono 0 błędów. To bardzo przydatna informacja, która pozwala sprawdzić, czy urządzenie działa po zakupie lub wgraniu firmware’u.

Aby połączyć się z Bus Pirate, możesz skorzystać z dokumentacji:

![Użyj polecenia - naciśnij spację: Aby połączyć się z Bus Pirate, możesz skorzystać z dokumentacji](<../../images/image (484).png>)

W tym przypadku urządzeniem docelowym jest pamięć EEPROM I²C z rodziny 24C256. Sprawdź dokładne oznaczenie sufiksu i kartę katalogową, ponieważ obsługiwane napięcie zasilania różni się w zależności od wersji układu.<sup>[[3]](#references)</sup>

![Użyj polecenia - naciśnij spację: W tym przypadku podłączę się do pamięci EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Do komunikacji z Bus Pirate użyłem programu Tera Term, połączonego z portem COM urządzenia Bus Pirate, i ustawiłem prędkość 115200 w menu Setup --> Serial Port --> Speed.\
Poniżej znajdziesz opis, jak przygotować Bus Pirate do komunikacji przez I²C oraz jak zapisywać i odczytywać dane z pamięci (komentarze zaczynają się od „#” — nie oczekuj ich w tej komunikacji):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

W tym scenariuszu będziemy przechwytywać komunikację I2C między Arduino a poprzednim układem EPROM. Wystarczy skomunikować oba urządzenia, a następnie podłączyć Bus Pirate do pinów SCL, SDA i GND:

![Read 20B from address 0x69 configured before - Sniffer: In this scenario we are going to sniff the I2C communication between the arduino and the previous EPROM, you just need to...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Rekonstrukcja protokołu I2C metodą Black-box

### Identyfikacja magistrali na podstawie aktywnych pinów

Jeśli urządzenie peryferyjne nie ma pinoutu ani dokumentacji, zacznij od pasywnej obserwacji za pomocą analizatora logicznego o wysokiej impedancji, gdy oryginalny host jest uruchomiony. Po połączeniu wspólnej masy i ustaleniu bezpiecznego poziomu logicznego sklasyfikuj piny o stałym stanie jako prawdopodobne linie zasilania, masy lub sygnały podciągnięte do stanu wysokiego, a następnie porównaj aktywne linie z typowymi magistralami: UART ma asynchroniczne, niezależnie kierowane linie TX/RX; konwencjonalny SPI zwykle udostępnia zegar, chip select oraz osobne linie danych dla obu kierunków; I2C ma regularny zegar i jedną dwukierunkową linię danych. Dekodowanie I2C powinno ujawnić 7-bitowe adresy urządzeń docelowych, kierunek odczytu/zapisu, ACK/NACK oraz powtarzające się dane.<sup>[[2]](#references)[[4]](#references)</sup>

Zarejestruj kilka prawidłowych wymian i zachowaj zarówno zdekodowane bajty, jak i surowe dane czasowe. Powtarzające się ramki przydadzą się jako testy ze znaną odpowiedzią dla późniejszych serializatorów, a różnice między żądaniami mogą ujawnić prawdopodobne pola kodu operacji, indeksu, offsetu, długości, sekwencji lub sumy kontrolnej.<sup>[[4]](#references)</sup>

### Odtworzenie formatu ramki z firmware hosta

Jeśli nie masz dostępu do firmware urządzenia peryferyjnego, wyodrębnij firmware **hosta** i znajdź komponent, który otwiera urządzenie I2C. Wyszukaj ciągi i symbole związane z nazwą urządzenia peryferyjnego, `/dev/i2c-`, konstruktorami poleceń, parserami odpowiedzi, procedurami resetowania/inicjalizacji oraz funkcjami sumy kontrolnej. Dla każdego konstruktora zapisz dokładne offsety pól, stałe, akceptowane rozmiary argumentów, długość danych, zakres sumy kontrolnej, kolejność bajtów sumy oraz długość zwracanej ramki — nie wyciągaj wniosków o formacie na podstawie samych nazw funkcji.<sup>[[4]](#references)</sup>

Sama nazwa funkcji sumy kontrolnej `crc16_ccitt` nie wystarczy, by wybrać wariant. Ustal kierunek przesuwania, bajt indeksu tablicy, wielomian reprezentowany przez tablicę, rejestr początkowy, odbicie wejścia/wyjścia, końcowe XOR/negację oraz kolejność bajtów serializatora na łączu. Na przykład tablica niskich bajtów przesuwająca w prawo, oparta na odwróconym wielomianie `0x8408`, zainicjowana wartością `0xFFFF` i zanegowana na końcu, wskazuje na **CRC-16/X-25 (IBM-SDLC)**. Poprawna suma kontrolna jest często niezbędna, by testowane przypadki przeszły walidację integralności i trafiły do parsera poleceń.<sup>[[4]](#references)</sup>

Po odtworzeniu formatu wyszukaj charakterystyczne nazwy symboli i stałe w publicznie dostępnym kodzie. W przypadku MJA1 niezależnie znaleziony wrapper SDK potwierdził identyfikatory poleceń, walidację argumentów, definicje odpowiedzi i lustrzaną implementację CRC; używaj takiego kodu jako potwierdzenia, a nie zamiast sprawdzenia dokładnego binarium celu i kolejności bajtów przesyłanych przez magistralę.<sup>[[4]](#references)[[5]](#references)</sup>

### Wysyłanie ramek z hosta Linux z uprawnieniami root

Skompromitowany host Linux wbudowany może komunikować się z urządzeniem peryferyjnym bez dodawania kolejnego kontrolera magistrali. Otwórz odpowiedni adapter, wybierz 7-bitowy adres za pomocą `I2C_SLAVE` i wyślij ramkę utworzoną przez dedykowany serializator; zachowaj tryb surowych ramek do mutacji i fuzzingu.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Kompiluj skrośnie przy użyciu toolchaina zgodnego z docelowym CPU i libc, a następnie porównaj ślady analizatora wygenerowane przez klienta testowego z prawidłowym ruchem. Granice transakcji, kolejność zapisów i odczytów, opóźnienia oraz stan urządzenia peryferyjnego mogą mieć znaczenie, nawet jeśli widoczne bajty są identyczne.<sup>[[4]](#references)</sup>

### Enumeracja opcode’ów kierowana odpowiedziami

Gdy znana jest już najkrótsza prawidłowa ramka i suma kontrolna, wylicz pełny zakres opcode’ów i użyj jawnej odpowiedzi **unsupported-command** protokołu jako punktu odniesienia dla negatywnego wyniku. Inny wynik — taki jak nieprawidłowe argumenty, nieprawidłowy stan lub nieudokumentowany status — sugeruje, że dekodowanie dotarło do zaimplementowanego lub częściowo zaimplementowanego handlera. **Nie** potwierdza to podatności na exploit; nadaj temu kandydatowi priorytet podczas fuzzingu ustrukturyzowanych długości, argumentów, stanów i sekwencji komend.<sup>[[4]](#references)</sup>

Jeśli test zawiesi urządzenie peryferyjne, automatyzuj jeden odizolowany przypadek na każdy rozruch, używając zewnętrznego kontrolera: połącz się przez SSH, wykonaj test, zapisz surowe żądanie i odpowiedź oraz czasy, uruchom ponownie urządzenie lub odłącz i przywróć zasilanie, zaczekaj na przywrócenie poprawnego działania testów kontrolnych, a następnie kontynuuj. Późniejsze umieszczenie komponentu w układzie testowym sterowanym przez mikrokontroler może zapewnić deterministyczne resetowanie, bezpośrednie sterowanie zasilaniem i szybszy fuzzing.<sup>[[4]](#references)</sup>

## References

- [1] [Dokumentacja Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Specyfikacja magistrali I²C i podręcznik użytkownika](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Dokumentacja układu AT24C256C, szeregowej pamięci EEPROM I²C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Analiza bezpieczeństwa układu zabezpieczającego MJA1 firmy Xiaomi metodą black-box probing](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper kryptograficzny MJA1 z Mijia BLE SDK](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
