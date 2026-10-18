# SPI

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczna magistrala szeregowa, powszechnie używana do komunikacji na krótkie odległości między układami scalonymi. Kontroler dostarcza sygnał zegarowy i wybiera urządzenie peryferyjne, takie jak EEPROM, czujnik lub urządzenie sterujące, za pomocą sygnału chip-select.<sup>[[1]](#references)</sup>

Wiele urządzeń peryferyjnych może współdzielić linie zegarowe i danych, zwykle z osobnym sygnałem chip-select dla każdego urządzenia. Kontroler koordynuje transfery; urządzenia peryferyjne zazwyczaj nie komunikują się bezpośrednio między sobą za pośrednictwem magistrali SPI. Polaryzacja i taktowanie sygnału chip-select zależą od urządzenia; wybór aktywny stanem niskim jest powszechny, ale nie uniwersalny. SPI nie definiuje wykrywania urządzeń, adresowania, komend ani jednego maksymalnego rozmiaru transferu, dlatego zawsze należy sprawdzić dokumentację układu docelowego.<sup>[[1]](#references)</sup>

MOSI/COPI przenosi dane z kontrolera do urządzenia peryferyjnego, a MISO/CIPO — z urządzenia peryferyjnego do kontrolera. Oba kierunki mogą przesyłać dane jednocześnie. Sposób powiązania komendy, adresu, cykli pustych i zwracanych danych określa urządzenie peryferyjne, a nie SPI; zależy on też od polaryzacji i fazy zegara (tryby 0–3). Nie należy zakładać, że wysyłanie danych wyjściowych zaczyna się dokładnie jeden cykl zegara po zakończeniu odbierania danych wejściowych.<sup>[[1]](#references)</sup>

## Zrzucanie firmware'u z pamięci EEPROM

Zrzucenie firmware'u może być przydatne podczas jego analizy i wyszukiwania podatności. Właściwy obraz może być niedostępny online albo różnić się w zależności od modelu, rewizji sprzętowej lub wersji, dlatego bezpośrednie wyodrębnienie go z fizycznego urządzenia pozwala uzyskać dokładny cel analizy.

Konsola szeregowa może być pomocna, ale jej system plików może być tylko do odczytu, a w urządzeniu docelowym może brakować narzędzi analitycznych, w tym programów potrzebnych do wysyłania i odbierania ruchu testowego lub wygodnego wyodrębniania plików binarnych. Obraz offline zachowuje pełny układ pamięci flash i umożliwia wyodrębnianie systemu plików oraz inżynierię wsteczną bez modyfikowania działającego urządzenia.

Podczas autoryzowanej oceny fizycznej zweryfikowany zrzut może również posłużyć do kontrolowanych testów modyfikacji i ponownego wgrywania firmware'u. Obejmuje to zmianę plików lub wstrzyknięcie testowego payloadu/backdoora w celu zademonstrowania trwałości na poziomie firmware'u. Przed jakimkolwiek zapisem zachowaj wiele zgodnych odczytów i oryginalny obraz: niewłaściwe napięcie, wybór układu, układ pamięci lub obraz mogą unieruchomić urządzenie.

### Programator i czytnik EEPROM CH341A

To niedrogie narzędzie USB może zrzucać i ponownie wgrywać dane do zgodnych szeregowych pamięci EEPROM i SPI flash. Jest powszechnie używane z układami pamięci SPI NOR przechowującymi firmware PC BIOS/UEFI i przydaje się podczas ograniczonego czasowo dostępu fizycznego.

![drawing](../../images/board_image_ch341a.jpg)

Podłącz pamięć flash do CH341A, a następnie podłącz programator do komputera. Jeśli sam programator nie jest wykrywany, przed rozpoczęciem diagnostyki układu docelowego sprawdź kabel USB, uprawnienia systemu operacyjnego i odpowiedni sterownik CH341A. Sprawdź napięcie układu, pin 1, okablowanie adaptera i napięcie wyjściowe programatora na podstawie dokumentacji układu lub za pomocą miernika — **nie** polegaj na zasadzie takiej jak umieszczanie VCC po przeciwnej stronie niż złącze USB. Nieprawidłowa orientacja lub podanie 5 V na układ 3,3/1,8 V może go zniszczyć. Odczyt w układzie może się nie powieść również dlatego, że pozostała część płytki obciąża magistralę lub zasila ją.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Do odczytu układu użyj oprogramowania takiego jak `flashrom` lub G-Flash. G-Flash to minimalistyczny interfejs graficzny, który może automatycznie wykrywać zgodne urządzenia, co bywa wygodne podczas szybkiego pozyskiwania danych, ale samodzielnie potwierdź wykryty model i napięcie. Podaj dokładny model programatora oraz, jeśli to konieczne, dokładny model układu; wykonaj co najmniej dwa odczyty i porównaj ich sumy kontrolne, zanim uznasz zrzut za wiarygodny.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Po zrzuceniu firmware'u można analizować pliki binarne. Narzędzia takie jak strings, hexdump, xxd, binwalk itp. mogą posłużyć do wyodrębnienia wielu informacji o firmware'ze, a także o całym systemie plików.

Do wstępnej analizy Binwalk może przeskanować obraz w poszukiwaniu znanych sygnatur i wyodrębnić obsługiwaną osadzoną zawartość:

```
binwalk -e <filename>
```

Plik wyjściowy może mieć rozszerzenie `.bin`, `.rom` lub inne; rozszerzenie nie określa formatu.

> [!CAUTION]
> Pamiętaj, że ekstrakcja firmware'u to delikatny proces, który wymaga dużo cierpliwości. Nieostrożne postępowanie może uszkodzić firmware, a nawet całkowicie go wymazać i uniemożliwić korzystanie z urządzenia. Przed próbą ekstrakcji firmware'u zaleca się zapoznanie z konkretnym urządzeniem.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

W niektórych kartach katalogowych piny docelowe są oznaczone jako `DI` i `DO`: w standardowym połączeniu flash z jedną linią danych kontroler **MOSI/COPI łączy się z DI**, a kontroler **MISO/CIPO łączy się z DO**. Sprawdź kartę katalogową układu docelowego, ponieważ w innych trybach układy z obsługą dual/quad I/O wykorzystują te piny ponownie.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

W systemie Windows lub Linux możesz użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom), aby zrzucić zawartość pamięci flash, uruchamiając coś w rodzaju:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nowsza dokumentacja Bus Pirate pokazuje również opcjonalne parametry `serialspeed` i `spispeed`. Jeśli długie przewody lub obciążenie układu powodują niestabilne odczyty, zacznij od niższej prędkości.<sup>[[3]](#references)</sup>

### Odczyt w układzie, gdy kontroler współdzieli magistralę flash

Klips SOIC może doprowadzać zasilanie flash do pozostałej części płytki PCB. Jeśli mikrokontroler jest wtedy zasilany i komunikuje się z tym samym układem, jego transmisje SPI mogą kolidować z transmisjami zewnętrznego programatora. Wynik `No EEPROM/flash device found` nie dowodzi więc, że pamięć flash nie jest obecna lub nie jest obsługiwana. Najpierw sprawdź wyprowadzenia, napięcie i styki, a następnie ustal, czy kontroler na płytce jest również aktywny.<sup>[[4]](#references)</sup>

Jeśli dostępny jest testowy punkt resetu, przed jego aktywowaniem sprawdź miernikiem polaryzację i napięcie. Przytrzymanie mikrokontrolera w resecie może umożliwić dostęp do pamięci flash, zatrzymując jednocześnie konkurencyjny host SPI. Alternatywami są wylutowanie układu lub pasywne rejestrowanie odczytów mikrokontrolera; ta druga metoda nie zapewnia dostępu do nieodczytanych obszarów ani możliwości zapisu układu, a dodatkowe przewody sondy mogą zakłócić działanie szybkiej magistrali. Ingerencja w oscylator lub tryb uruchamiania zależy od konkretnego celu i nie zastępuje sprawdzenia schematu oraz sygnałów.<sup>[[4]](#references)</sup>

Gdy mikrokontroler jest nieaktywny, Raspberry Pi z włączonym interfejsem `spidev` może odczytać pamięć za pomocą programatora `linux_spi` w flashrom. Zmień parametr `-p`, aby użyć innego adaptera. Powtórz odczyt i porównaj sumy kontrolne, zanim mu zaufasz; automatyczne wykrywanie SFDP i pomyślny odczyt **nie** dowodzą, że operacje kasowania, zapisu lub ochrony przed zapisem działają z nieobsługiwanym układem.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Odtwarzanie odczytów pamięci SPI flash za pomocą analizatora stanów logicznych

Gdy odczyt aktywny jest niemożliwy, przechwyć sygnały chip select, zegara, dane kontroler-do-flash i flash-do-kontrolera podczas uruchamiania lub wybranej czynności w UI. W PulseView najpierw zidentyfikuj aktywny przedział chip select i zegar, a następnie skonfiguruj kanały danych dekodera SPI zgodnie z pinoutem pamięci flash i sprawdź, czy pojawia się wiarygodna komenda/adres, po których następują zwrócone bajty. Wyeksportuj bajty **MISO/wyjścia flash** za pomocą Binary Decoder Output View i zachowaj zdekodowane adresy odczytu, aby można było umieścić każdą odpowiedź pod odpowiadającym jej offsetem w pamięci flash. Przechwycenie tylko odczytów wywołanych przez menu obejmuje wyłącznie żądane obszary, a nie kompletny obraz pamięci flash; nie łącz odpowiedzi tak, jakby były ciągłe, bez sprawdzenia adresów.<sup>[[4]](#references)</sup>

Jeśli zrzut wygląda na zawierający grafikę, a nie kod wykonywalny, przejdź do [wstępnej analizy surowych zasobów wyświetlacza](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Wprowadzenie do interfejsu SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Podręcznik flashrom — programator SPI CH341A i opcje odczytu/zapisu](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacja Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Odświeżenie wiedzy o hardware hacking, część 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
