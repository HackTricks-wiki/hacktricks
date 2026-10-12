# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Przed podłączeniem Bus Pirate sprawdź napięcie docelowe, rozkład pinów, sposób podłączenia rezystorów podciągających oraz wspólną masę. Nie włączaj zasilaczy Bus Pirate na aktywnej magistrali zasilanej przez urządzenie docelowe wyłącznie po to, by ją podsłuchiwać — dwa zasilacze mogą ze sobą konkurować i uszkodzić sprzęt. Poniższy zapis jest przykładem dotyczącym konkretnego urządzenia — Bus Pirate v3 z firmware społeczności — a nie uniwersalną instrukcją podłączenia.<sup>[[1]](#references)[[2]](#references)</sup>

Aby sprawdzić, czy Bus Pirate działa, podłącz +5V do VPU, a 3.3V do ADC, połącz się z Bus Pirate (na przykład za pomocą Tera Term) i użyj polecenia `~`:

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

Jak widać w poprzednim wierszu poleceń, wykryto 0 błędów. To bardzo przydatna informacja, dzięki której można sprawdzić, czy urządzenie działa po zakupie lub wgraniu firmware’u.

Aby połączyć się z Bus Pirate, możesz skorzystać z dokumentacji:

![Użyj polecenia — naciśnij spację: Aby połączyć się z Bus Pirate, możesz skorzystać z dokumentacji](<../../images/image (484).png>)

W tym przypadku celem jest pamięć EEPROM I²C z rodziny 24C256. Sprawdź dokładne oznaczenie wariantu i jego kartę katalogową, ponieważ obsługiwane napięcie zasilania różni się w zależności od części.<sup>[[3]](#references)</sup>

![Użyj polecenia — naciśnij spację: W tym przypadku podłączę pamięć EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Do komunikacji z Bus Pirate użyłem Tera Term, połączonego z portem COM Bus Pirate. W menu Setup --> Serial Port ustawiłem prędkość 115200.\
Poniższa komunikacja pokazuje, jak przygotować Bus Pirate do komunikacji przez I2C oraz jak zapisywać i odczytywać dane z pamięci (komentarze są oznaczane znakiem „#” — nie oczekuj, że będą widoczne w komunikacji):

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

W tym scenariuszu będziemy nasłuchiwać komunikacji I2C między Arduino a poprzednim układem EPROM. Wystarczy nawiązać komunikację między oboma urządzeniami, a następnie podłączyć Bus Pirate do pinów SCL, SDA i GND:

![Odczyt 20B z wcześniej skonfigurowanego adresu 0x69 - Sniffer: W tym scenariuszu będziemy nasłuchiwać komunikacji I2C między Arduino a poprzednim układem EPROM. Wystarczy...](<../../images/image (166).png>)

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

## Rekonstrukcja protokołu I2C metodą black-box

### Identyfikacja magistrali na podstawie aktywnych pinów

Jeśli urządzenie peryferyjne nie ma opisu pinów ani dokumentacji, zacznij od pasywnego monitorowania za pomocą analizatora logicznego o wysokiej impedancji, gdy oryginalny host jest uruchomiony. Po połączeniu wspólnej masy i upewnieniu się, że poziom logiczny jest bezpieczny, sklasyfikuj stałe sygnały jako prawdopodobne linie zasilania, masy lub sygnały z podciąganiem, a następnie porównaj aktywne linie z typowymi magistralami: UART używa asynchronicznych linii TX/RX o niezależnych kierunkach; konwencjonalne SPI zwykle udostępnia zegar, wybór układu i osobne linie danych dla obu kierunków; I2C ma regularny sygnał zegarowy oraz jedną dwukierunkową linię danych. Dekoder I2C powinien ujawnić 7-bitowe adresy urządzeń docelowych, kierunek odczytu/zapisu, sygnały ACK/NACK i powtarzające się payloady.<sup>[[2]](#references)[[4]](#references)</sup>

Zarejestruj kilka prawidłowych wymian i zachowaj zarówno zdekodowane bajty, jak i surowe dane o taktowaniu. Powtarzające się ramki przydadzą się jako testy z oczekiwanym wynikiem dla późniejszych serializatorów, a różnice między żądaniami mogą ujawnić prawdopodobne pola opcode, indeksu, offsetu, długości, numeru sekwencji lub sumy kontrolnej.<sup>[[4]](#references)</sup>

### Odtworzenie ramkowania na podstawie firmware hosta

Jeśli firmware urządzenia peryferyjnego jest niedostępny, wyodrębnij firmware **hosta** i znajdź komponent, który otwiera urządzenie I2C. Wyszukaj nazwy urządzenia peryferyjnego, `/dev/i2c-`, funkcje tworzące polecenia, parsery odpowiedzi, procedury resetowania/inicjalizacji oraz funkcje sum kontrolnych. Dla każdej funkcji tworzącej ramkę zapisz dokładne offsety pól, stałe, akceptowane rozmiary argumentów, długość payloadu, zakres danych objętych sumą kontrolną, kolejność bajtów sumy kontrolnej oraz długość zwracanej ramki, zamiast wnioskować o formacie na podstawie nazw funkcji.<sup>[[4]](#references)</sup>

Sama nazwa funkcji sumy kontrolnej `crc16_ccitt` nie wystarcza, by wybrać wariant. Ustal kierunek przesunięcia, bajt indeksu tablicy, wielomian reprezentowany przez tablicę, rejestr początkowy, odbicie bitów na wejściu/wyjściu, końcowe XOR/negację oraz kolejność bajtów serializatora na łączu. Na przykład tablica dla młodszego bajtu z przesunięciem w prawo, oparta na odwróconym wielomianie `0x8408`, inicjalizacja wartością `0xFFFF` i negacja na końcu wskazują na **CRC-16/X-25 (IBM-SDLC)**. Poprawna suma kontrolna jest często niezbędna, aby przypadki testowe przeszły walidację integralności i dotarły do parsera poleceń.<sup>[[4]](#references)</sup>

Po odtworzeniu formatu wyszukaj charakterystyczne nazwy symboli i stałe w publicznie dostępnym kodzie. W przypadku MJA1 niezależnie odnaleziony wrapper SDK potwierdził identyfikatory poleceń, walidację argumentów, definicje odpowiedzi i lustrzaną implementację CRC; traktuj taki kod źródłowy jako potwierdzenie, a nie zamiennik weryfikacji dokładnego pliku binarnego i kolejności bajtów przesyłanych przez łącze.<sup>[[4]](#references)[[5]](#references)</sup>

### Wysyłanie ramek z hosta Linux z uprawnieniami root

Zhakowany host z wbudowanym systemem Linux może komunikować się z urządzeniem peryferyjnym bez dodawania kolejnego kontrolera magistrali. Otwórz odpowiedni adapter, wybierz 7-bitowy adres za pomocą `I2C_SLAVE` i wyślij ramkę utworzoną przez dedykowany serializator; zachowaj tryb surowych ramek do mutacji i fuzzingu.<sup>[[4]](#references)</sup>

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

Kompiluj skrośnie przy użyciu toolchaina zgodnego z docelowym CPU i libc, a następnie porównaj ślady analizatora z klienta testowego z legalnym ruchem. Granice transakcji, kolejność zapisów i odczytów, opóźnienia oraz stan urządzenia peryferyjnego mogą mieć znaczenie, nawet gdy widoczne bajty są identyczne.<sup>[[4]](#references)</sup>

### Enumeracja opcode’ów na podstawie odpowiedzi

Gdy znana jest najkrótsza prawidłowa ramka i suma kontrolna, enumeruj pełną szerokość opcode’u, używając jawnej odpowiedzi protokołu **unsupported-command** jako negatywnego punktu odniesienia. Inny wynik — taki jak nieprawidłowe argumenty, nieprawidłowy stan lub nieudokumentowany status — sugeruje, że dekodowanie dotarło do zaimplementowanego lub częściowo zaimplementowanego handlera. **Nie** dowodzi to podatności na exploit; nadaj temu przypadkowi wyższy priorytet podczas fuzzingu ustrukturyzowanych długości, argumentów, stanów i sekwencji poleceń.<sup>[[4]](#references)</sup>

Jeśli test zawiesi urządzenie peryferyjne, zautomatyzuj wykonywanie jednego odizolowanego przypadku na każdy rozruch, korzystając z zewnętrznego kontrolera: połącz się przez SSH, wykonaj przypadek, zapisz surowe żądanie i odpowiedź oraz czasy, uruchom ponownie urządzenie lub odłącz i ponownie podłącz zasilanie, poczekaj na przywrócenie prawidłowego działania testów stanu, a następnie kontynuuj. Późniejsze przeniesienie komponentu do stanowiska testowego sterowanego przez mikrokontroler może zapewnić deterministyczne resetowanie, bezpośrednie sterowanie zasilaniem i szybszy fuzzing.<sup>[[4]](#references)</sup>

## References

- [1] [Dokumentacja Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — specyfikacja magistrali I²C i instrukcja obsługi](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — karta katalogowa szeregowej pamięci EEPROM AT24C256C z interfejsem I²C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — sondowanie czarnej skrzynki: analiza bezpieczeństwa bezpiecznego układu MJA1 firmy Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper kryptograficzny MJA1 w Mijia BLE SDK](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
