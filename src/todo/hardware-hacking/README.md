# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) obsługuje testowanie boundary-scan za pomocą komórek umieszczonych wokół pinów wejścia/wyjścia urządzenia. Wiele procesorów udostępnia również funkcje debugowania specyficzne dla danego producenta za pośrednictwem tego samego Test Access Port (TAP); boundary scan i debugowanie CPU to powiązane zastosowania JTAG, ale nie są synonimami.<sup>[[1]](#references)</sup>

Standard JTAG definiuje **konkretne polecenia do przeprowadzania skanowania boundary-scan**, w tym:

- **BYPASS** wybiera jednobitowy rejestr bypass, aby można było dotrzeć do innych urządzeń w łańcuchu skanowania przy minimalnym narzucie.
- **SAMPLE/PRELOAD** przechwytuje wartości pinów podczas normalnego działania i może wstępnie załadować rejestr boundary-scan przed wykonaniem innej instrukcji.
- **EXTEST** ustawia i odczytuje stany pinów.

Może również obsługiwać inne polecenia, takie jak:

- **IDCODE** do identyfikowania urządzenia
- **INTEST** do wewnętrznego testowania urządzenia

Możesz natknąć się na te instrukcje podczas korzystania z narzędzia takiego jak JTAGulator.

### The Test Access Port

**Test Access Port (TAP)** zapewnia dostęp do logiki testowej JTAG komponentu. Wymagane są cztery sygnały, a `TRST` jest opcjonalny:<sup>[[1]](#references)</sup>

- Wejście zegara testowego (**TCK**) TCK to **zegar**, który określa, jak często kontroler TAP wykona pojedynczą akcję (innymi słowy, przejdzie do następnego stanu w automacie stanów).
- Wejście wyboru trybu testowego (**TMS**) TMS steruje **automatem stanów skończonych**. Przy każdym takcie zegara kontroler JTAG TAP urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest niższe od określonego progu, sygnał jest uznawany za niski i interpretowany jako 0, natomiast jeśli napięcie jest wyższe od określonego progu, sygnał jest uznawany za wysoki i interpretowany jako 1.
- Wejście danych testowych (**TDI**) przesuwa szeregową instrukcję lub dane testowe do wybranego rejestru TAP. IEEE 1149.1 definiuje sposób transferu TAP, natomiast producenci definiują opcjonalne instrukcje i rejestry debugowania.
- Wyjście danych testowych (**TDO**) TDO to pin, który wysyła **dane z układu**.
- Wejście resetu testowego (**TRST**) Opcjonalny TRST resetuje automat stanów skończonych **do znanego, prawidłowego stanu**. Alternatywnie, jeśli TMS pozostaje ustawiony na 1 przez pięć kolejnych cykli zegara, wywołuje reset w taki sam sposób, jak pin TRST, dlatego TRST jest opcjonalny.

Czasami te piny są oznaczone na PCB. W innych przypadkach trzeba będzie je **znaleźć**.

### Identyfikowanie pinów JTAG

Szybką, przeznaczoną do tego celu, lecz stosunkowo drogą opcją wykrywania portów JTAG jest **JTAGulator**, który może również identyfikować wyprowadzenia UART.<sup>[[2]](#references)</sup>

Ma **24 kanały**, które można podłączyć do punktów testowych płytki. Wylicza kombinacje potencjalnych pinów za pomocą skanów **IDCODE** i **BYPASS** oraz zgłasza kanały odpowiadające wykrytym sygnałom JTAG.

Tańszym, lecz znacznie wolniejszym sposobem identyfikowania wyprowadzeń JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontrolerze kompatybilnym z Arduino.

W przypadku **JTAGenum** najpierw zdefiniuj piny mikrokontrolera używane do sondowania podczas wyliczania. Sprawdź jego pinout, a następnie podłącz te piny do potencjalnych punktów testowych na docelowej płytce.<sup>[[3]](#references)</sup>

**Trzecim sposobem** identyfikowania pinów JTAG jest **sprawdzenie PCB** pod kątem znanego footprintu. Niektóre płytki udostępniają footprint **Tag-Connect**, jednak Tag-Connect to system złączy, który może przenosić JTAG, SWD, UART lub inny interfejs — sam w sobie nie stanowi dowodu, że piny są pinami JTAG. Rzeczywiste sygnały można następnie zidentyfikować na podstawie dokumentacji komponentów i pomiarów ciągłości.<sup>[[5]](#references)</sup>

## SDW

SWD to dwupinowy, pakietowy interfejs debugowania firmy Arm.<sup>[[4]](#references)</sup>

Interfejs używa dwukierunkowego **SWDIO** do przesyłania danych oraz **SWCLK** jako zegara. Wiele urządzeń implementuje **Serial Wire/JTAG Debug Port (SWJ-DP)**, który umożliwia wybór między SWD i JTAG na współdzielonych pinach.<sup>[[4]](#references)</sup>

## References

- [1] [Grupa robocza IEEE 1149.1 — JTAG i boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Dokumentacja JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — wyliczanie pinów JTAG za pomocą Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — interfejsy debugowania z małą liczbą pinów dla systemów wielourządzeniowych](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprinty kabli debugowania i programowania](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
