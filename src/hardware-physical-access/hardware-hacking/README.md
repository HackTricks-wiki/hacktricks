# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

W przypadku urządzenia, do którego masz fizyczny dostęp, zacznij od interfejsu udostępnionego przez jego płytkę lub sygnały: [konsol szeregowych UART](uart.md), [dostępu debugowania JTAG/SWD](jtag.md), magistral [I²C](i2c.md) i [pamięci flash SPI](spi.md). [Analiza side-channel](side_channel_analysis.md) i [wstrzykiwanie błędów](fault_injection_attacks.md) dotyczą innych zadań związanych z pomiarami i glitchingiem; [analiza sygnałów radiowych](radio.md) obejmuje punkt wejścia przez transmisję bezprzewodową. Przed podłączeniem narzędzi sprawdź poziomy napięć urządzenia i ograniczenia opisane w odpowiednim rozdziale.

## JTAG

JTAG (IEEE 1149.1) umożliwia testowanie boundary-scan za pomocą komórek umieszczonych wokół pinów I/O urządzenia. Wiele procesorów udostępnia także funkcje debugowania specyficzne dla danego producenta przez ten sam Test Access Port (TAP); boundary scan i debugowanie CPU to powiązane zastosowania JTAG, a nie synonimy.<sup>[[1]](#references)</sup>

Standard JTAG definiuje **konkretne polecenia do przeprowadzania boundary scan**, w tym:

- **BYPASS** wybiera jednobitowy rejestr bypass, aby można było uzyskać dostęp do innych urządzeń w łańcuchu skanowania przy minimalnym narzucie.
- **SAMPLE/PRELOAD** przechwytuje wartości pinów podczas normalnej pracy i może wstępnie załadować rejestr boundary-scan przed użyciem innej instrukcji.
- **EXTEST** ustawia i odczytuje stany pinów.

Może także obsługiwać inne polecenia, takie jak:

- **IDCODE** do identyfikowania urządzenia
- **INTEST** do testowania urządzenia od wewnątrz

Możesz natknąć się na te instrukcje podczas korzystania z narzędzia takiego jak JTAGulator.

### Test Access Port

**Test Access Port (TAP)** zapewnia dostęp do logiki testowej JTAG komponentu. Wymagane są cztery sygnały, a `TRST` jest opcjonalny:<sup>[[1]](#references)</sup>

- Wejście zegara testowego (**TCK**) TCK jest **zegarem**, który określa, jak często kontroler TAP wykonuje pojedyncze działanie (innymi słowy, przechodzi do kolejnego stanu maszyny stanów).
- Wejście wyboru trybu testowego (**TMS**) TMS steruje **maszyną stanów skończonych**. Przy każdym takcie zegara kontroler JTAG TAP urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest niższe od określonego progu, sygnał uznaje się za niski i interpretuje jako 0; jeśli jest wyższe od określonego progu, sygnał uznaje się za wysoki i interpretuje jako 1.
- Wejście danych testowych (**TDI**) przesuwa instrukcje szeregowe lub dane testowe do wybranego rejestru TAP. IEEE 1149.1 definiuje sposób transferu TAP, natomiast producenci określają opcjonalne instrukcje i rejestry debugowania.
- Wyjście danych testowych (**TDO**) TDO to pin, który przesyła **dane poza układ**.
- Wejście resetu testowego (**TRST**) Opcjonalny TRST resetuje maszynę stanów skończonych **do znanego, prawidłowego stanu**. Alternatywnie przytrzymanie TMS w stanie 1 przez pięć kolejnych cykli zegara powoduje reset, tak jak pin TRST, dlatego TRST jest opcjonalny.

Czasami piny te są oznaczone na PCB. W innych przypadkach trzeba je **znaleźć**.

### Identyfikowanie pinów JTAG

Szybkim, specjalnie zaprojektowanym, lecz stosunkowo drogim narzędziem do wykrywania portów JTAG jest **JTAGulator**, który może także identyfikować wyprowadzenia UART.<sup>[[2]](#references)</sup>

Ma **24 kanały**, które można podłączyć do punktów testowych na płytce. Wylicza możliwe kombinacje pinów za pomocą skanowania **IDCODE** i **BYPASS**, a następnie wskazuje kanały odpowiadające wykrytym sygnałom JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikowania wyprowadzeń JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) wgranego na mikrokontroler zgodny z Arduino.

W przypadku **JTAGenum** najpierw określ piny mikrokontrolera używane do wyliczania połączeń. Sprawdź jego pinout, a następnie podłącz te piny do potencjalnych punktów testowych na docelowej płytce.<sup>[[3]](#references)</sup>

**Trzecim sposobem** na identyfikację pinów JTAG jest **sprawdzenie PCB** pod kątem znanego footprintu. Niektóre płytki udostępniają footprint **Tag-Connect**, ale Tag-Connect to system złączy, który może obsługiwać JTAG, SWD, UART lub inny interfejs — sam w sobie nie potwierdza, że piny są pinami JTAG. Rzeczywiste sygnały można następnie zidentyfikować na podstawie kart katalogowych komponentów i pomiarów ciągłości.<sup>[[5]](#references)</sup>

## SDW

SWD to dwupinowy, pakietowy interfejs debugowania firmy Arm.<sup>[[4]](#references)</sup>

Interfejs wykorzystuje dwukierunkowy sygnał **SWDIO** do przesyłania danych oraz **SWCLK** jako zegar. Wiele urządzeń implementuje **Serial Wire/JTAG Debug Port (SWJ-DP)**, który umożliwia wybór między SWD i JTAG na współdzielonych pinach.<sup>[[4]](#references)</sup>

## References

- [1] [Grupa robocza IEEE 1149.1 — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacja JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — wyliczanie pinów JTAG Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — interfejsy debugowania o małej liczbie pinów dla systemów wielourządzeniowych](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprinty kabli debugowania i programowania](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
