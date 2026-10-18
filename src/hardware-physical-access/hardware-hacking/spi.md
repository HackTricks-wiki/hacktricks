# SPI

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczna magistrala szeregowa, powszechnie używana do komunikacji na krótkie odległości między układami scalonymi. Kontroler dostarcza sygnał zegara i wybiera urządzenie peryferyjne, takie jak EEPROM, czujnik lub urządzenie sterujące, za pomocą sygnału chip-select.<sup>[[1]](#references)</sup>

Wiele urządzeń peryferyjnych może współdzielić linie zegara i danych; zazwyczaj każde z nich ma osobną linię chip-select. Kontroler koordynuje transmisje; urządzenia peryferyjne zwykle nie komunikują się ze sobą bezpośrednio przez magistralę SPI. Polaryzacja i taktowanie chip-select zależą od urządzenia; wybór aktywny stanem niskim jest powszechny, ale nie uniwersalny. SPI nie definiuje wykrywania urządzeń, adresowania, poleceń ani jednej maksymalnej długości transmisji, dlatego zawsze sprawdzaj dokumentację układu docelowego.<sup>[[1]](#references)</sup>

MOSI/COPI przesyła dane od kontrolera do urządzenia peryferyjnego, a MISO/CIPO — od urządzenia peryferyjnego do kontrolera. W obu kierunkach można przesyłać dane jednocześnie. Relacja między poleceniem, adresem, cyklami pustymi i zwracanymi danymi jest określana przez urządzenie peryferyjne, a nie przez SPI, i zależy od polaryzacji oraz fazy zegara (tryby 0–3). Nie zakładaj, że dane wyjściowe zaczynają się dokładnie jeden cykl zegara po zakończeniu danych wejściowych.<sup>[[1]](#references)</sup>

## Zrzucanie firmware'u z układów EEPROM

Zrzucenie firmware'u może być przydatne do jego analizy i wyszukiwania podatności. Właściwy obraz może być niedostępny online albo różnić się w zależności od modelu, rewizji sprzętu lub wersji, dlatego bezpośrednie wyodrębnienie go z fizycznego urządzenia zapewnia dokładny obraz do analizy.

Konsola szeregowa może być pomocna, ale jej system plików może być tylko do odczytu, a w urządzeniu docelowym mogą brakować narzędzi do analizy, w tym narzędzi potrzebnych do wysyłania/odbierania ruchu testowego lub wygodnego wyodrębniania plików binarnych. Obraz offline zachowuje pełny układ pamięci flash i umożliwia wyodrębnienie systemu plików oraz inżynierię wsteczną bez modyfikowania działającego urządzenia.

Podczas autoryzowanej oceny fizycznej zweryfikowany zrzut może również posłużyć do kontrolowanych testów modyfikacji i ponownego flashowania. Obejmuje to zmianę plików lub wstrzyknięcie testowego payloadu/backdoora, aby zademonstrować trwałość na poziomie firmware'u. Zachowaj kilka zgodnych odczytów oraz oryginalny obraz przed jakimkolwiek zapisem: nieprawidłowe napięcie, wybór układu, układ danych lub obraz mogą unieruchomić urządzenie.

### Programator i czytnik EEPROM CH341A

To niedrogie narzędzie USB może zrzucać i ponownie flashować zgodne szeregowe układy EEPROM oraz pamięci SPI flash. Jest powszechnie używane z układami pamięci SPI NOR, w których przechowywany jest firmware BIOS/UEFI komputerów PC, i jest wygodne przy ograniczonym czasowo dostępie fizycznym.

![rysunek](../../images/board_image_ch341a.jpg)

Podłącz pamięć flash do CH341A, a następnie podłącz programator do komputera. Jeśli sam programator nie jest wykrywany, przed diagnozowaniem układu docelowego sprawdź kabel USB, uprawnienia systemu operacyjnego i odpowiedni sterownik CH341A. Sprawdź napięcie układu, pin 1, okablowanie adaptera i napięcie wyjściowe programatora, korzystając z dokumentacji lub miernika — **nie** polegaj na zasadzie takiej jak umieszczanie VCC po przeciwnej stronie niż złącze USB. Nieprawidłowa orientacja lub podanie 5 V na układ 3,3/1,8 V może go zniszczyć. Odczyt w układzie może się również nie powieść, jeśli reszta płytki obciąża magistralę lub zasila ją.<sup>[[2]](#references)</sup>

![rysunek](../../images/connect_wires_ch341a.jpg) ![rysunek](../../images/eeprom_plugged_ch341a.jpg)

Do odczytu układu użyj oprogramowania takiego jak `flashrom` lub G-Flash. G-Flash to proste GUI, które może automatycznie wykrywać zgodne urządzenia; bywa to wygodne podczas szybkiego pozyskiwania danych, ale samodzielnie potwierdź wykryty model i napięcie. Podaj dokładny programator, a w razie potrzeby także dokładny model układu; wykonaj co najmniej dwa odczyty i porównaj ich skróty, zanim uznasz zrzut za wiarygodny.<sup>[[2]](#references)</sup>

![rysunek](../../images/connected_status_ch341a.jpg)

Po zrzuceniu firmware'u można analizować pliki binarne. Narzędzia takie jak strings, hexdump, xxd, binwalk itd. pozwalają wyodrębnić wiele informacji o firmware'ie, a także o całym systemie plików.

Do wstępnej analizy Binwalk może skanować pliki w poszukiwaniu znanych sygnatur i wyodrębniać obsługiwaną zawartość osadzoną:

```
binwalk -e <filename>
```

Plik wyjściowy może mieć rozszerzenie `.bin`, `.rom` lub inne; samo rozszerzenie nie określa formatu.

> [!CAUTION]
> Pamiętaj, że odczytywanie firmware'u to delikatny proces wymagający dużej cierpliwości. Nieostrożne działanie może uszkodzić firmware, a nawet całkowicie go wymazać i sprawić, że urządzenie stanie się bezużyteczne. Przed próbą odczytania firmware'u zaleca się zapoznanie z konkretnym urządzeniem.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

W niektórych datasheetach piny docelowe są oznaczone jako `DI` i `DO`: w standardowym połączeniu flash z pojedynczą linią danych kontroler **MOSI/COPI łączy się z DI**, a kontroler **MISO/CIPO łączy się z DO**. Sprawdź datasheet układu docelowego, ponieważ w innych trybach układy obsługujące dual/quad I/O wykorzystują te piny ponownie.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

W systemie Windows lub Linux możesz użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom), aby zrzucić zawartość pamięci flash, uruchamiając polecenie podobne do:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nowsza dokumentacja Bus Pirate opisuje również opcjonalne parametry `serialspeed` i `spispeed`. Zacznij od niskiej prędkości, jeśli długie przewody lub obciążenie w układzie powodują niestabilne odczyty.<sup>[[3]](#references)</sup>

### Odczyt w układzie, gdy kontroler współdzieli magistralę flash

Klips SOIC może doprowadzać zasilanie flash do pozostałej części PCB. Jeśli MCU jest wtedy zasilany i uzyskuje dostęp do tego samego układu, jego transfery SPI mogą kolidować z transferami zewnętrznego programatora. Wynik `No EEPROM/flash device found` nie dowodzi więc, że układu flash brakuje lub nie jest obsługiwany. Najpierw sprawdź wyprowadzenia, napięcie i styk, a następnie ustal, czy kontroler na płytce jest również aktywny.<sup>[[4]](#references)</sup>

Jeśli dostępny jest test pad resetu, przed jego aktywacją sprawdź miernikiem polaryzację i napięcie. Utrzymanie MCU w stanie resetu może umożliwić dostęp do flash, jednocześnie zatrzymując konkurujący host SPI. Alternatywą jest wylutowanie układu lub pasywne rejestrowanie odczytów MCU; ta druga metoda nie daje dostępu do nieodczytanych obszarów ani możliwości zapisu układu, a dodatkowe przewody sondy mogą zakłócić działanie szybkiej magistrali. Ingerencja w oscylator lub tryb rozruchu zależy od konkretnego urządzenia i nie zastępuje sprawdzenia schematu oraz sygnałów.<sup>[[4]](#references)</sup>

Gdy MCU jest nieaktywny, Raspberry Pi z włączonym interfejsem `spidev` może odczytać układ za pomocą programatora `linux_spi` w flashrom. Zmień `-p`, aby użyć innego adaptera. Powtórz odczyt i porównaj sumy kontrolne przed uznaniem wyniku za wiarygodny; automatyczne wykrywanie SFDP i udany odczyt **nie** potwierdzają, że operacje kasowania, zapisu lub ochrony przed zapisem działają w przypadku nieobsługiwanego układu.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Odtwarzanie odczytów pamięci flash SPI za pomocą analizatora logicznego

Gdy aktywny odczyt jest niemożliwy, przechwytuj sygnały chip select, zegar, dane z kontrolera do pamięci flash oraz dane z pamięci flash do kontrolera podczas uruchamiania systemu lub wybranej czynności w UI. W PulseView najpierw zidentyfikuj aktywny przedział chip select i zegar, a następnie skonfiguruj kanały danych dekodera SPI, korzystając z rozkładu wyprowadzeń pamięci flash, i sprawdź, czy występuje wiarygodna komenda/adres, po których następują zwrócone bajty. Wyeksportuj bajty **MISO/wyjścia pamięci flash** za pomocą Binary Decoder Output View i zachowaj zdekodowane adresy odczytu, aby każdą odpowiedź można było umieścić pod odpowiadającym jej offsetem w pamięci flash. Przechwycenie wyłącznie odczytów wywołanych przez menu obejmuje tylko żądane obszary, a nie kompletny obraz pamięci flash; nie łącz odpowiedzi tak, jakby były ciągłe, bez sprawdzenia adresów.<sup>[[4]](#references)</sup>

Jeśli zrzut zawiera raczej grafikę niż kod wykonywalny, przejdź do [wstępnej analizy surowych zasobów wyświetlacza](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy i mieszane przechwycenia SPI/QSPI

W przypadku nieopisanych sond odróżnij MOSI od MISO, sprawdzając, która linia przenosi opcode przed danymi odpowiedzi, a następnie zweryfikuj komendę z dokumentacją pamięci flash. Impulsy krótsze niż okres zegara mogą być szumem sondy, a dodatkowe przewody klipsa mogą sprawić, że przechwycenia z dużą szybkością będą niewiarygodne.<sup>[[5]](#references)</sup>

Eksport CSV SPI z Saleae używa `enable` i `disable` do oznaczenia granic przedziału chip select, a bajty MOSI/MISO umieszcza w wierszach `result`. Grupuj bajty według przedziałów przed dekodowaniem; połączenie wszystkich danych MISO powoduje utratę adresów transakcji.<sup>[[5]](#references)</sup> Obiekt Scapy `Packet` może modelować nagłówek MOSI przy użyciu opcode `ByteEnumField` oraz warunkowych pól adresu i dummy. W przypadku 24-bitowych odczytów NOR komenda `0x03` zawiera opcode i trzy bajty adresu, a `0x0B` dodaje bajt dummy. `len(req.self_build())` zwraca długość modelowanego nagłówka: przy odczycie jednoliniowym `miso[header_length:]` zawiera odpowiedź pamięci flash, natomiast dane MOSI po nagłówku to dane don't-care po stronie kontrolera.<sup>[[5]](#references)</sup> Umieszczaj odpowiedzi pod zdekodowanymi adresami w obrazie wypełnionym bajtami `0xFF` i osobno śledź pokryte offsety. Brak zaobserwowanego bajtu nie jest dowodem, że pamięć flash zawierała w tym miejscu `0xFF`.<sup>[[5]](#references)[[6]](#references)</sup>

Odczyt `0x6B` (1-1-4) w pamięci typu W25Q używa jednej linii dla opcode i adresu, ale linii IO0–IO3 dla danych odpowiedzi. Aktywność na dawnych pinach `/WP` i `/HOLD` jest mocniejszym dowodem przełączenia w tryb quad niż sam szybszy zegar; analizator jednoliniowy może błędnie zdekodować odpowiedź quad.<sup>[[5]](#references)</sup> Wyeksportuj tę fazę za pomocą analizatora QSPI skonfigurowanego z szerokościami linii i cyklami dummy właściwymi dla komendy, a następnie połącz odczyty jedno- i czteroliniowe według adresów pamięci flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` automatycznie wykrywa oba formaty eksportu, odrzuca odczyty zdekodowane przy nieprawidłowej szerokości linii i raportuje pokrycie odczytu.<sup>[[6]](#references)</sup> Po zainstalowaniu zależności, w repozytorium połącz przechwycenia poleceniem:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Wynik pozostaje ograniczoną obserwacją, a nie kompletnym zrzutem chipa.<sup>[[5]](#references)[[6]](#references)</sup> Aby osobno przeanalizować operacje zapisu, skoreluj `0x06` (włączenie zapisu), `0x05` (odpytywanie o status), kody operacji kasowania oraz polecenia programowania stron `0x02`. Dane programowania strony następują po adresie na MOSI i nie są uwzględniane w rekonstrukcji wyłącznie do odczytu.<sup>[[5]](#references)</sup> Przeanalizuj uzyskany obraz za pomocą [analizy firmware](../firmware-analysis/), zachowując informacje o pokryciu odczytem.

## References

- [1] [Analog Devices — Wprowadzenie do interfejsu SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Podręcznik flashrom — programator SPI CH341A i opcje odczytu/zapisu](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacja Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Odświeżenie wiedzy o hackingu sprzętowym, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Rozszerzanie Scapy na potrzeby inżynierii odwrotnej sprzętu](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — przechwytywanie i rekonstrukcja śladów SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Analizator QSPI dla Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
