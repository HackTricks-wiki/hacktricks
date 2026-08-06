# SPI

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczny protokół komunikacji szeregowej używany w systemach embedded do komunikacji na krótkie odległości między układami scalonymi (IC, Integrated Circuits). Protokół komunikacji SPI wykorzystuje architekturę master-slave, która jest zarządzana przez sygnały Clock i Chip Select. Architektura master-slave składa się z mastera (zwykle mikroprocesora), który zarządza zewnętrznymi urządzeniami peryferyjnymi, takimi jak EEPROM, sensory, urządzenia sterujące itp., uznawanymi za slave'y.

Do jednego mastera można podłączyć wiele slave'ów, ale slave'y nie mogą komunikować się ze sobą. Slave'y są zarządzane za pomocą dwóch pinów: clock i chip select. Ponieważ SPI jest synchronicznym protokołem komunikacji, piny wejściowe i wyjściowe podążają za sygnałami zegara. Chip select jest używany przez mastera do wyboru slave'a i komunikowania się z nim. Gdy chip select ma stan wysoki, urządzenie slave nie jest wybrane, natomiast gdy ma stan niski, układ jest wybrany i master komunikuje się ze slave'em.

Piny MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) odpowiadają za wysyłanie i odbieranie danych. Dane są wysyłane do urządzenia slave przez pin MOSI, gdy chip select jest utrzymywany w stanie niskim. Dane wejściowe zawierają instrukcje, adresy pamięci lub dane zgodnie z datasheetem dostawcy urządzenia slave. Po otrzymaniu prawidłowych danych wejściowych pin MISO odpowiada za przesyłanie danych do mastera. Dane wyjściowe są wysyłane dokładnie w następnym cyklu zegara po zakończeniu przesyłania danych wejściowych. Pin MISO przesyła dane do momentu ich całkowitego wysłania albo ustawienia przez mastera pinu chip select w stan wysoki (w takim przypadku slave przestaje transmitować, a master nie odbiera danych po tym cyklu zegara).

## Zrzucanie firmware'u z EEPROM-ów

Zrzucanie firmware'u może być przydatne podczas jego analizy i wyszukiwania w nim podatności. Często firmware nie jest dostępny w internecie lub jest nieistotny ze względu na różnice wynikające z takich czynników jak numer modelu, wersja itp. Dlatego bezpośrednie wyodrębnienie firmware'u z fizycznego urządzenia może być pomocne podczas polowania na zagrożenia, ponieważ pozwala zachować odpowiedni poziom szczegółowości.

Uzyskanie Serial Console może być pomocne, ale często zdarza się, że pliki są tylko do odczytu. Ogranicza to analizę z różnych powodów. Przykładowo, w firmware'ze może nie być narzędzi wymaganych do wysyłania i odbierania pakietów. Z tego powodu wyodrębnienie plików binarnych w celu ich reverse engineeringu nie jest możliwe. Dlatego posiadanie całego firmware'u zrzuconego do systemu i wyodrębnienie plików binarnych do analizy może być bardzo pomocne.

Ponadto podczas red teaming i uzyskiwania fizycznego dostępu do urządzeń zrzucenie firmware'u może pomóc w modyfikowaniu plików lub wstrzykiwaniu złośliwych plików, a następnie ponownym flashowaniu ich do pamięci. Może to pomóc w zainstalowaniu backdoora w urządzeniu. Zrzucanie firmware'u otwiera więc wiele możliwości.

### CH341A EEPROM Programmer and Reader

To niedrogie urządzenie służące do zrzucania firmware'ów z EEPROM-ów oraz ponownego flashowania ich plikami firmware'u. Jest często używane do pracy z układami BIOS komputerów (które są po prostu EEPROM-ami). Urządzenie łączy się przez USB i do rozpoczęcia pracy wymaga minimalnej liczby narzędzi. Zwykle szybko wykonuje swoje zadanie, dzięki czemu może być pomocne również podczas uzyskiwania fizycznego dostępu do urządzeń.

![drawing](../../images/board_image_ch341a.jpg)

Podłącz pamięć EEPROM do programatora CH341A i podłącz urządzenie do komputera. Jeśli urządzenie nie zostanie wykryte, spróbuj zainstalować sterowniki na komputerze. Upewnij się również, że EEPROM jest podłączony we właściwej orientacji (zwykle należy umieścić pin VCC w orientacji odwrotnej względem złącza USB); w przeciwnym razie software nie będzie w stanie wykryć układu. W razie potrzeby skorzystaj ze schematu:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Na koniec użyj software'u takiego jak flashrom, G-Flash (GUI) itp. do zrzucenia firmware'u. G-Flash to minimalistyczne narzędzie GUI, które działa szybko i automatycznie wykrywa EEPROM. Może być pomocne, gdy firmware musi zostać szybko wyodrębniony bez konieczności szczegółowego zapoznawania się z dokumentacją.

![drawing](../../images/connected_status_ch341a.jpg)

Po zrzuceniu firmware'u można przeprowadzić analizę plików binarnych. Narzędzia takie jak strings, hexdump, xxd, binwalk itp. mogą zostać użyte do wyodrębnienia wielu informacji o firmware'ze, a także o całym systemie plików.

Do wyodrębnienia zawartości firmware'u można użyć binwalk. Binwalk analizuje sygnatury hex, identyfikuje pliki w pliku binarnym i potrafi je wyodrębniać.
```
binwalk -e <filename>
```
Może to być plik `.bin` lub `.rom`, zależnie od użytych narzędzi i konfiguracji.

> [!CAUTION]
> Należy pamiętać, że ekstrakcja firmware'u to delikatny proces wymagający dużej cierpliwości. Nieprawidłowe obchodzenie się z urządzeniem może potencjalnie uszkodzić firmware, a nawet całkowicie go wymazać i sprawić, że urządzenie stanie się bezużyteczne. Przed próbą ekstrakcji firmware'u zaleca się zapoznanie ze specyfiką danego urządzenia.

### Bus Pirate + flashrom

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Należy pamiętać, że nawet jeśli PINOUT Bus Pirate wskazuje piny **MOSI** i **MISO** do połączenia ze SPI, niektóre układy SPI mogą oznaczać piny jako DI i DO. **MOSI -> DI, MISO -> DO**

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Należy pamiętać, że nawet jeśli PINOUT Bus Pirate wskazuje piny MOSI i MISO do połączenia ze SPI, niektóre układy SPI mogą...](<../../images/image (360).png>)

W systemie Windows lub Linux można użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom) do zrzucenia zawartości pamięci flash, uruchamiając polecenie podobne do:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
