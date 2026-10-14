# SPI

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

SPI (Serial Peripheral Interface) to synchroniczna magistrala szeregowa powszechnie używana do komunikacji na krótkie odległości między układami scalonymi. Kontroler dostarcza sygnał zegarowy i wybiera urządzenie peryferyjne, takie jak EEPROM, czujnik lub urządzenie sterujące, za pomocą sygnału chip-select.<sup>[[1]](#references)</sup>

Wiele urządzeń peryferyjnych może współdzielić linie zegara i danych, zwykle z osobnym sygnałem chip-select dla każdego urządzenia. Kontroler koordynuje transfery; urządzenia peryferyjne zazwyczaj nie komunikują się bezpośrednio między sobą przez magistralę SPI. Polaryzacja i synchronizacja sygnału chip-select zależą od urządzenia; wybór aktywny stanem niskim jest powszechny, ale nie uniwersalny. SPI nie definiuje wykrywania urządzeń, adresowania, komend ani jednej maksymalnej długości transferu, dlatego zawsze sprawdzaj dokumentację układu docelowego.<sup>[[1]](#references)</sup>

MOSI/COPI przenosi dane od kontrolera do urządzenia peryferyjnego, a MISO/CIPO — od urządzenia peryferyjnego do kontrolera. Dane mogą być przesyłane jednocześnie w obu kierunkach. Zależność między komendą, adresem, cyklami pozorowanymi i zwracanymi danymi określa urządzenie peryferyjne, a nie SPI; zależy ona od polaryzacji i fazy zegara (tryby 0–3). Nie zakładaj, że dane wyjściowe zaczynają się dokładnie jeden cykl zegara po zakończeniu danych wejściowych.<sup>[[1]](#references)</sup>

## Zrzucanie firmware’u z układów EEPROM

Zrzucenie firmware’u może pomóc w jego analizie i wykrywaniu podatności. Odpowiedni obraz może być niedostępny online lub różnić się w zależności od modelu, rewizji sprzętowej albo wersji, dlatego wyodrębnienie go bezpośrednio z fizycznego urządzenia pozwala uzyskać dokładny obraz do analizy.

Konsola szeregowa może być przydatna, ale jej system plików może być tylko do odczytu, a urządzeniu docelowemu mogą brakować narzędzi analitycznych, w tym programów potrzebnych do wysyłania i odbierania ruchu testowego lub wygodnego wyodrębniania plików binarnych. Obraz offline zachowuje pełny układ pamięci flash i umożliwia wyodrębnienie systemu plików oraz inżynierię wsteczną bez modyfikowania działającego urządzenia.

Podczas autoryzowanej oceny fizycznej zweryfikowany zrzut może również posłużyć do kontrolowanych testów modyfikacji i ponownego flashowania. Obejmuje to zmianę plików lub wstrzyknięcie testowego payloadu/backdoora, aby zademonstrować trwałość na poziomie firmware’u. Przed jakimkolwiek zapisem zachowaj kilka zgodnych odczytów i oryginalny obraz: niewłaściwe napięcie, wybór układu, układ danych lub obraz mogą unieruchomić urządzenie.

### Programator i czytnik EEPROM CH341A

To niedrogie narzędzie USB może zrzucać i ponownie flashować zgodne szeregowe układy EEPROM i pamięci flash SPI. Jest powszechnie używane z układami pamięci flash SPI NOR przechowującymi firmware BIOS/UEFI komputerów PC i przydaje się podczas krótkiego dostępu fizycznego.

![drawing](../../images/board_image_ch341a.jpg)

Podłącz pamięć flash do CH341A, a następnie podłącz programator do komputera. Jeśli sam programator nie zostanie wykryty, przed diagnozowaniem układu docelowego sprawdź kabel USB, uprawnienia systemu operacyjnego i odpowiedni sterownik CH341A. Za pomocą dokumentacji lub miernika sprawdź napięcie układu, pin 1, okablowanie adaptera i napięcie wyjściowe programatora — **nie** polegaj na zasadzie takiej jak umieszczanie VCC po przeciwnej stronie niż złącze USB. Nieprawidłowe ustawienie układu lub podanie 5 V na element 3,3/1,8 V może go zniszczyć. Odczyt w układzie może również się nie powieść, jeśli pozostała część płytki obciąża magistralę lub ją zasila.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Do odczytu układu użyj oprogramowania, takiego jak `flashrom` lub G-Flash. G-Flash to minimalistyczny interfejs graficzny, który może automatycznie wykrywać zgodne urządzenia, co bywa wygodne podczas szybkiego pozyskiwania danych, ale samodzielnie potwierdź wykryty model i napięcie. Podaj dokładny model programatora, a w razie potrzeby również dokładny model układu; wykonaj co najmniej dwa odczyty i porównaj ich sumy kontrolne przed uznaniem zrzutu za wiarygodny.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Po zrzuceniu firmware’u można analizować pliki binarne. Narzędzia takie jak strings, hexdump, xxd, binwalk itp. pozwalają wyodrębnić wiele informacji o firmware’ze, a także o całym systemie plików.

Do wstępnej analizy Binwalk może wyszukiwać znane sygnatury i wyodrębniać obsługiwaną zawartość osadzoną:

```
binwalk -e <filename>
```

Plik wyjściowy może mieć rozszerzenie `.bin`, `.rom` lub inne; samo rozszerzenie nie określa formatu.

> [!CAUTION]
> Należy pamiętać, że ekstrakcja firmware’u to delikatny proces, który wymaga dużo cierpliwości. Nieostrożne postępowanie może uszkodzić firmware, a nawet całkowicie go wymazać i sprawić, że urządzenie stanie się bezużyteczne. Przed próbą ekstrakcji firmware’u zaleca się zapoznanie z konkretnym urządzeniem.

### Bus Pirate + flashrom

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

W niektórych kartach katalogowych piny docelowe są oznaczone jako `DI` i `DO`: w typowym połączeniu flash z pojedynczą linią danych kontroler **MOSI/COPI łączy się z DI**, a kontroler **MISO/CIPO łączy się z DO**. Sprawdź kartę katalogową układu docelowego, ponieważ elementy obsługujące dual/quad I/O wykorzystują te piny ponownie w innych trybach.

![Programator i czytnik EEPROM CH341A - Bus Pirate + flashrom: Zwróć uwagę, że nawet jeśli PINOUT Bus Pirate wskazuje piny MOSI i MISO do połączenia z SPI, niektóre układy SPI mogą...](<../../images/image (360).png>)

W systemie Windows lub Linux możesz użyć programu [**`flashrom`**](https://www.flashrom.org/Flashrom), aby zrzucić zawartość pamięci flash, uruchamiając coś w rodzaju:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nowsza dokumentacja Bus Pirate opisuje również opcjonalne parametry `serialspeed` i `spispeed`. Jeśli długie przewody lub obciążenie układu podczas odczytu powodują niestabilność, zacznij od niskich wartości.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Wprowadzenie do interfejsu SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Podręcznik flashrom — programator CH341A SPI oraz opcje odczytu/zapisu](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacja Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
