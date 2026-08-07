# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG umożliwia wykonanie boundary scan. Boundary scan analizuje określone obwody, w tym wbudowane komórki boundary-scan oraz rejestry dla każdego pinu.

Standard JTAG definiuje **specific commands for conducting boundary scans**, w tym:

- **BYPASS** umożliwia testowanie określonego chipa bez narzutu związanego z przechodzeniem przez inne chipy.
- **SAMPLE/PRELOAD** pobiera próbkę danych wchodzących do urządzenia i wychodzących z niego, gdy działa ono w normalnym trybie.
- **EXTEST** ustawia i odczytuje stany pinów.

Może również obsługiwać inne komendy, takie jak:

- **IDCODE** do identyfikowania urządzenia
- **INTEST** do wewnętrznego testowania urządzenia

Możesz natknąć się na te instrukcje podczas korzystania z narzędzia takiego jak JTAGulator.

### Test Access Port

Boundary scans obejmują testy czteroprzewodowego **Test Access Port (TAP)**, uniwersalnego portu zapewniającego **access to the JTAG test support** functions wbudowane w komponent. TAP wykorzystuje pięć następujących sygnałów:

- Wejście zegara testowego (**TCK**) TCK to **clock**, który określa, jak często kontroler TAP wykona pojedynczą akcję (innymi słowy, przejdzie do następnego stanu w automacie stanów).
- Wejście wyboru trybu testowego (**TMS**) TMS steruje **finite state machine**. Przy każdym takcie zegara kontroler JTAG TAP urządzenia sprawdza napięcie na pinie TMS. Jeśli napięcie jest niższe od określonego progu, sygnał uznaje się za niski i interpretuje jako 0, natomiast jeśli napięcie jest wyższe od określonego progu, sygnał uznaje się za wysoki i interpretuje jako 1.
- Wejście danych testowych (**TDI**) TDI to pin, który przesyła **data into the chip through the scan cells**. Każdy vendor odpowiada za zdefiniowanie protokołu komunikacji na tym pinie, ponieważ JTAG go nie definiuje.
- Wyjście danych testowych (**TDO**) TDO to pin, który przesyła **data out of the chip**.
- Wejście resetu testowego (**TRST**) Opcjonalny TRST resetuje finite state machine **to a known good state**. Alternatywnie, jeśli TMS pozostanie na poziomie 1 przez pięć kolejnych cykli zegara, wywołuje reset w taki sam sposób jak pin TRST, dlatego TRST jest opcjonalny.

Czasami będzie można znaleźć te piny oznaczone na PCB. W innych przypadkach trzeba będzie je **find**.

### Identyfikowanie pinów JTAG

Najszybszym, ale najdroższym sposobem wykrywania portów JTAG jest użycie **JTAGulator**, urządzenia stworzonego specjalnie w tym celu (chociaż może ono **also detect UART pinouts**).

Ma ono **24 channels**, które można podłączyć do pinów płyty. Następnie wykonuje **BF attack** na wszystkich możliwych kombinacjach, wysyłając komendy boundary scan **IDCODE** i **BYPASS**. Jeśli otrzyma odpowiedź, wyświetla kanał odpowiadający każdemu sygnałowi JTAG.

Tańszym, ale znacznie wolniejszym sposobem identyfikowania pinoutów JTAG jest użycie [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) załadowanego na mikrokontrolerze kompatybilnym z Arduino.

Korzystając z **JTAGenum**, najpierw **define the pins of the probing** urządzenia, którego użyjesz do enumeracji. Należy odwołać się do diagramu pinoutu urządzenia, a następnie połączyć te piny z punktami testowymi na urządzeniu docelowym.

**Third way** identyfikacji pinów JTAG polega na **inspecting the PCB** pod kątem jednego z pinoutów. W niektórych przypadkach PCB mogą wygodnie udostępniać **Tag-Connect interface**, co wyraźnie wskazuje, że płyta ma również złącze JTAG. Wygląd tego interfejsu można zobaczyć na stronie [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Ponadto analiza **datasheets of the chipsets on the PCB** może ujawnić diagramy pinoutów wskazujące interfejsy JTAG.

## SDW

SWD to specyficzny dla ARM protokół przeznaczony do debugowania.

Interfejs SWD wymaga **two pins**: dwukierunkowego sygnału **SWDIO**, który jest odpowiednikiem **TDI and TDO pins and a clock** JTAG, oraz **SWCLK**, który jest odpowiednikiem **TCK** w JTAG. Wiele urządzeń obsługuje **Serial Wire or JTAG Debug Port (SWJ-DP)**, połączony interfejs JTAG i SWD umożliwiający podłączenie do urządzenia docelowego sondy SWD lub JTAG.

{{#include ../../banners/hacktricks-training.md}}
