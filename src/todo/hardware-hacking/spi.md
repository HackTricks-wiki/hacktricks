# SPI

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczna magistrala szeregowa powszechnie używana do komunikacji na krótkie odległości między układami scalonymi. Kontroler dostarcza sygnał zegarowy i wybiera urządzenie peryferyjne, takie jak EEPROM, sensor lub urządzenie sterujące, za pomocą sygnału chip-select.<sup>[[1]](#references)</sup>

Wiele urządzeń peryferyjnych może współdzielić linie zegara i danych, zwykle z osobnym chip-select dla każdego urządzenia. Kontroler koordynuje transfery; urządzenia peryferyjne zwykle nie komunikują się bezpośrednio między sobą za pośrednictwem magistrali SPI. Polaryzacja i taktowanie chip-select zależą od urządzenia; wybór aktywny stanem niskim jest powszechny, ale nie uniwersalny. SPI nie definiuje wykrywania urządzeń, adresowania, komend ani jednej maksymalnej długości transferu, dlatego zawsze należy zapoznać się z datasheetem urządzenia docelowego.<sup>[[1]](#references)</sup>

MOSI/COPI przenosi dane z kontrolera do urządzenia peryferyjnego, a MISO/CIPO dane z urządzenia peryferyjnego do kontrolera. Oba kierunki mogą przesyłać dane jednocześnie. Zależność między komendą, adresem, cyklami pustymi (dummy cycles) i zwracanymi danymi jest definiowana przez urządzenie peryferyjne, a nie przez SPI, i zależy od polaryzacji oraz fazy zegara (tryby 0–3). Nie należy zakładać, że dane wyjściowe zaczynają się dokładnie jeden cykl zegara po zakończeniu danych wejściowych.<sup>[[1]](#references)</sup>

## Zrzucanie firmware z EEPROM-ów

Zrzucenie firmware może być przydatne do jego analizy i wyszukiwania podatności. Właściwy obraz może być niedostępny online albo różnić się w zależności od modelu, rewizji sprzętowej lub wersji, dlatego wyodrębnienie go bezpośrednio z fizycznego urządzenia zapewnia dokładny cel analizy.

Konsola szeregowa może być pomocna, ale jej system plików może być tylko do odczytu, a urządzeniu docelowemu może brakować narzędzi analitycznych, w tym programów potrzebnych do wygodnego wysyłania/odbierania testowego ruchu lub wyodrębniania plików binarnych. Obraz offline zachowuje kompletny układ pamięci flash i umożliwia wyodrębnienie systemu plików oraz reverse engineering bez modyfikowania działającego urządzenia.

Podczas autoryzowanej oceny fizycznej zweryfikowany dump może również wspierać kontrolowane modyfikacje i testy ponownego flashowania. Obejmuje to zmianę plików lub wstrzyknięcie testowego payloadu/backdoor w celu zademonstrowania persistence na poziomie firmware. Przed jakimkolwiek zapisem należy zachować wiele zgodnych odczytów oraz oryginalny obraz: nieprawidłowe napięcie, wybór układu, rozmieszczenie lub obraz mogą zbrickować urządzenie.

### CH341A EEPROM Programmer and Reader

To niedrogie urządzenie USB może zrzucać i ponownie flashować kompatybilne szeregowe układy EEPROM i SPI flash. Jest powszechnie używane z układami SPI NOR flash, które przechowują firmware PC BIOS/UEFI, i jest wygodne podczas ograniczonego czasowo dostępu fizycznego.

![drawing](../../images/board_image_ch341a.jpg)

Podłącz pamięć flash do CH341A, a następnie podłącz programator do komputera. Jeśli sam programator nie jest wykrywany, przed rozpoczęciem diagnostyki układu docelowego sprawdź kabel USB, uprawnienia systemu operacyjnego oraz odpowiedni sterownik CH341A. Potwierdź napięcie układu, pin 1, okablowanie adaptera i napięcie wyjściowe programatora na podstawie datasheetów lub za pomocą miernika — **nie** polegaj na zasadzie takiej jak umieszczanie VCC naprzeciwko złącza USB. Nieprawidłowa orientacja lub podanie 5 V na układ 3,3/1,8 V może go zniszczyć. Odczyty in-circuit mogą również się nie powieść, ponieważ pozostała część płytki obciąża magistralę lub zasila ją.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Do odczytu układu użyj oprogramowania takiego jak `flashrom` lub G-Flash. G-Flash to minimalistyczny GUI i może automatycznie wykrywać kompatybilne urządzenia, co bywa wygodne podczas szybkiego pozyskiwania danych, ale samodzielnie potwierdź wykryty model i napięcie. Określ dokładny programator oraz, gdy jest to konieczne, dokładny model układu; wykonaj co najmniej dwa odczyty i porównaj ich hashe, zanim uznasz dump za wiarygodny.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Po zrzuceniu firmware analiza może być przeprowadzona na plikach binarnych. Narzędzia takie jak strings, hexdump, xxd, binwalk itd. mogą służyć do wyodrębnienia wielu informacji o firmware, a także o całym systemie plików.

Podczas wstępnego triage Binwalk może skanować znane sygnatury i wyodrębniać obsługiwane osadzone treści:
```
binwalk -e <filename>
```
Plik wyjściowy może używać rozszerzenia `.bin`, `.rom` lub innego; rozszerzenie nie określa formatu.

> [!CAUTION]
> Należy pamiętać, że ekstrakcja firmware'u jest delikatnym procesem i wymaga dużej cierpliwości. Nieprawidłowe wykonanie czynności może potencjalnie uszkodzić firmware, a nawet całkowicie go wymazać, unieruchamiając urządzenie. Przed próbą ekstrakcji firmware'u zaleca się zapoznanie z konkretnym urządzeniem.

### Bus Pirate + flashrom

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

W niektórych datasheetach piny docelowe są oznaczone jako `DI` i `DO`: w przypadku konwencjonalnego połączenia flash z pojedynczą linią danych kontroler **MOSI/COPI łączy się z DI**, a kontroler **MISO/CIPO łączy się z DO**. Należy zweryfikować datasheet urządzenia docelowego, ponieważ układy z dual/quad I/O wykorzystują te piny w innych trybach.

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Należy pamiętać, że nawet jeśli PINOUT urządzenia Pirate Bus wskazuje piny MOSI i MISO do połączenia z SPI, niektóre układy SPI mogą...](<../../images/image (360).png>)

W systemie Windows lub Linux można użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom) do zrzucenia zawartości pamięci flash, uruchamiając coś takiego:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Nowsza dokumentacja Bus Pirate pokazuje również opcjonalne parametry `serialspeed` i `spispeed`. Zacznij zachowawczo, jeśli długie przewody lub obciążenie układu w obwodzie powodują niestabilność odczytów.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Wprowadzenie do interfejsu SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Podręcznik flashrom — programator CH341A SPI oraz opcje odczytu/zapisu](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacja Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
