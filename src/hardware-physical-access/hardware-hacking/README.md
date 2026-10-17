# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

W przypadku urządzenia, do którego masz fizyczny dostęp, zacznij od interfejsów udostępnianych przez jego płytkę lub sygnały: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [CoreSight instruction tracing](arm-coresight-instruction-tracing.md), magistrale [I²C](i2c.md) i [SPI flash](spi.md). [Side-channel analysis](side_channel_analysis.md) i [fault injection](fault_injection_attacks.md) służą do innych zadań związanych z pomiarami i zakłóceniami; [radio signal analysis](radio.md) obejmuje punkt wejścia przez interfejs bezprzewodowy. Procedury dotyczące RFID/NFC, pasma sub-GHz, podczerwieni, BLE, LoRaWAN i iButton dla konkretnych celów znajdziesz w sekcji [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Przed podłączeniem narzędzi sprawdź poziomy napięć urządzenia i ograniczenia opisane w odpowiednim rozdziale.

## JTAG

JTAG (IEEE 1149.1) obsługuje testowanie metodą boundary scan za pomocą komórek umieszczonych wokół pinów I/O urządzenia. Wiele procesorów udostępnia też za pośrednictwem tego samego Test Access Port (TAP) funkcje debugowania specyficzne dla danego producenta; boundary scan i debugowanie CPU to powiązane zastosowania JTAG, ale nie są synonimami.<sup>[[1]](#references)</sup>

Standard JTAG definiuje **konkretne polecenia służące do przeprowadzania boundary scan**, w tym:

- **BYPASS** wybiera jednobitowy rejestr bypass, dzięki czemu można uzyskać dostęp do innych urządzeń w łańcuchu skanowania przy minimalnym narzucie.
- **SAMPLE/PRELOAD** przechwytuje wartości pinów podczas normalnej pracy i może wstępnie załadować rejestr boundary-scan przed wykonaniem innej instrukcji.
- **EXTEST** ustawia i odczytuje stany pinów.

Może też obsługiwać inne polecenia, takie jak:

- **IDCODE** do identyfikowania urządzenia
- **INTEST** do testowania urządzenia od wewnątrz

Możesz się zetknąć z tymi instrukcjami podczas korzystania z narzędzia takiego jak JTAGulator.

### Test Access Port

**Test Access Port (TAP)** zapewnia dostęp do logiki testowej JTAG komponentu. Wymagane są cztery sygnały, a `TRST` jest opcjonalny:<sup>[[1]](#references)</sup>

- Wejście zegara testowego (**TCK**) TCK to **zegar**, który określa, jak często kontroler TAP wykonuje pojedyncze działanie (innymi słowy, przechodzi do następnego stanu automatu stanów).
- Wejście wyboru trybu testowego (**TMS**) TMS steruje **automatem stanów skończonych**. Przy każdym takcie zegara kontroler JTAG TAP urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest poniżej określonego progu, sygnał uznaje się za niski i interpretuje jako 0; jeśli jest powyżej tego progu, uznaje się go za wysoki i interpretuje jako 1.
- Wejście danych testowych (**TDI**) przesuwa instrukcje szeregowe lub dane testowe do wybranego rejestru TAP. IEEE 1149.1 definiuje sposób transferu w TAP, natomiast producenci określają opcjonalne instrukcje i rejestry debugowania.
- Wyjście danych testowych (**TDO**) TDO to pin, który przesyła **dane poza układ**.
- Wejście resetu testowego (**TRST**) Opcjonalny TRST resetuje automat stanów skończonych **do znanego, prawidłowego stanu**. Alternatywnie, utrzymanie TMS w stanie 1 przez pięć kolejnych cykli zegara wywołuje reset w taki sam sposób jak pin TRST, dlatego TRST jest opcjonalny.

Czasami piny te są oznaczone na PCB. W innych przypadkach trzeba je **odnaleźć**.

### Identyfikowanie pinów JTAG

Szybkim i specjalnie zaprojektowanym, ale stosunkowo drogim narzędziem do wykrywania portów JTAG jest **JTAGulator**, który może też identyfikować układy pinów UART.<sup>[[2]](#references)</sup>

Ma **24 kanały**, które można podłączyć do punktów testowych na płytce. Wypróbowuje możliwe kombinacje pinów za pomocą skanów **IDCODE** i **BYPASS**, a następnie wskazuje kanały odpowiadające wykrytym sygnałom JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikowania układów pinów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) uruchomionego na mikrokontrolerze zgodnym z Arduino.

W przypadku **JTAGenum** najpierw określ piny mikrokontrolera używane do enumeracji. Sprawdź jego pinout, a następnie podłącz te piny do potencjalnych punktów testowych na płytce urządzenia.<sup>[[3]](#references)</sup>

**Trzecim sposobem** identyfikowania pinów JTAG jest **sprawdzenie PCB** pod kątem znanego footprintu. Niektóre płytki udostępniają footprint **Tag-Connect**, ale Tag-Connect to system złączy, który może przenosić JTAG, SWD, UART lub inny interfejs — jego obecność sama w sobie nie dowodzi, że piny obsługują JTAG. Rzeczywiste sygnały można następnie zidentyfikować na podstawie dokumentacji komponentów i pomiarów ciągłości.<sup>[[5]](#references)</sup>

## SDW

SWD to dwupinowy, pakietowy interfejs debugowania firmy Arm.<sup>[[4]](#references)</sup>

Interfejs wykorzystuje dwukierunkowy sygnał **SWDIO** do przesyłania danych oraz **SWCLK** jako zegar. Wiele urządzeń implementuje **Serial Wire/JTAG Debug Port (SWJ-DP)**, który pozwala wybrać SWD lub JTAG na współdzielonych pinach.<sup>[[4]](#references)</sup>

## References

- [1] [Grupa robocza IEEE 1149.1 — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacja JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeracja pinów JTAG za pomocą Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — interfejsy debugowania z niewielką liczbą pinów dla systemów wielourządzeniowych](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprinty przewodów debugujących i programujących](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
