# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

W przypadku urządzenia, do którego masz fizyczny dostęp, zacznij od interfejsów udostępnionych przez jego płytkę lub sygnały: [konsol szeregowych UART](uart.md), [dostępu debugowania JTAG/SWD](jtag.md), magistral [I²C](i2c.md) i [SPI flash](spi.md). [Analiza side-channel](side_channel_analysis.md) i [fault injection](fault_injection_attacks.md) dotyczą innych zadań pomiarowych i wprowadzania zakłóceń; [analiza sygnałów radiowych](radio.md) obejmuje punkt wejścia przez transmisję bezprzewodową. Procedury dotyczące RFID/NFC, sub-GHz, podczerwieni, BLE, LoRaWAN i iButton dla konkretnych celów znajdziesz w sekcji [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Przed podłączeniem narzędzi sprawdź poziomy napięć celu oraz ograniczenia opisane w odpowiednim rozdziale.

## JTAG

JTAG (IEEE 1149.1) umożliwia testowanie skanowaniem granicznym za pomocą komórek umieszczonych wokół pinów I/O urządzenia. Wiele procesorów udostępnia także za pośrednictwem tego samego Test Access Port (TAP) funkcje debugowania specyficzne dla danego producenta; skanowanie graniczne i debugowanie CPU to powiązane zastosowania JTAG, ale nie synonimy.<sup>[[1]](#references)</sup>

Standard JTAG definiuje **konkretne polecenia do przeprowadzania skanowania granicznego**, w tym:

- **BYPASS** wybiera jednobitowy rejestr obejściowy, dzięki czemu można uzyskać dostęp do innych urządzeń w łańcuchu skanowania przy minimalnym narzucie.
- **SAMPLE/PRELOAD** przechwytuje wartości pinów podczas normalnego działania i może wstępnie załadować rejestr skanowania granicznego przed użyciem innej instrukcji.
- **EXTEST** ustawia i odczytuje stany pinów.

Może obsługiwać również inne polecenia, takie jak:

- **IDCODE** do identyfikowania urządzenia
- **INTEST** do testowania wewnętrznego urządzenia

Możesz natknąć się na te instrukcje podczas korzystania z narzędzia takiego jak JTAGulator.

### Test Access Port

**Test Access Port (TAP)** zapewnia dostęp do logiki testowej JTAG komponentu. Wymagane są cztery sygnały, a `TRST` jest opcjonalny:<sup>[[1]](#references)</sup>

- Wejście zegara testowego (**TCK**) TCK to **zegar**, który określa, jak często kontroler TAP wykonuje pojedynczą czynność (innymi słowy, przechodzi do następnego stanu maszyny stanów).
- Wejście wyboru trybu testowego (**TMS**) TMS steruje **maszyną stanów skończonych**. Przy każdym takcie zegara kontroler JTAG TAP urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest niższe od określonego progu, sygnał uznaje się za niski i interpretuje jako 0; jeśli jest wyższe od określonego progu, sygnał uznaje się za wysoki i interpretuje jako 1.
- Wejście danych testowych (**TDI**) przesuwa instrukcję szeregową lub dane testowe do wybranego rejestru TAP. IEEE 1149.1 definiuje sposób przesyłania danych przez TAP, natomiast producenci definiują opcjonalne instrukcje i rejestry debugowania.
- Wyjście danych testowych (**TDO**) TDO to pin, który przesyła **dane z układu**.
- Wejście resetowania testowego (**TRST**) Opcjonalny TRST resetuje maszynę stanów **do znanego, poprawnego stanu**. Zamiast tego można utrzymać TMS w stanie 1 przez pięć kolejnych cykli zegara, aby wywołać reset — tak samo jak w przypadku pinu TRST, dlatego TRST jest opcjonalny.

Czasami piny te są oznaczone na PCB. W innych przypadkach trzeba je **znaleźć**.

### Identyfikowanie pinów JTAG

Szybką, specjalnie zaprojektowaną, ale stosunkowo drogą opcją do wykrywania portów JTAG jest **JTAGulator**, który potrafi także identyfikować pinouty UART.<sup>[[2]](#references)</sup>

Ma **24 kanały**, które można podłączyć do punktów testowych płytki. Wylicza możliwe kombinacje pinów za pomocą skanów **IDCODE** i **BYPASS**, a następnie wskazuje kanały odpowiadające wykrytym sygnałom JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikowania pinoutów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontroler zgodny z Arduino.

W przypadku **JTAGenum** najpierw określ piny mikrokontrolera używane do wyliczania. Sprawdź jego pinout, a następnie podłącz te piny do wybranych punktów testowych na płytce celu.<sup>[[3]](#references)</sup>

**Trzecim sposobem** identyfikowania pinów JTAG jest **sprawdzenie PCB** pod kątem znanego footprintu. Niektóre płytki udostępniają footprint **Tag-Connect**, ale Tag-Connect to system złączy, który może obsługiwać JTAG, SWD, UART lub inny interfejs — sam w sobie nie dowodzi, że piny służą do JTAG. Rzeczywiste sygnały można następnie ustalić na podstawie dokumentacji komponentów i pomiarów ciągłości obwodu.<sup>[[5]](#references)</sup>

## SDW

SWD to dwupinowy interfejs debugowania Arm oparty na pakietach.<sup>[[4]](#references)</sup>

Interfejs wykorzystuje dwukierunkowy sygnał **SWDIO** do przesyłania danych oraz **SWCLK** jako zegar. Wiele urządzeń implementuje **Serial Wire/JTAG Debug Port (SWJ-DP)**, który umożliwia wybór między SWD a JTAG na współdzielonych pinach.<sup>[[4]](#references)</sup>

## References

- [1] [Grupa robocza IEEE 1149.1 — JTAG i skanowanie graniczne](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacja JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — wyliczanie pinów JTAG za pomocą Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — interfejsy debugowania o małej liczbie pinów dla systemów wielourządzeniowych](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprinty kabli debugowania i programowania](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
