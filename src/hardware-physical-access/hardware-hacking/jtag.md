# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Bezpieczniejsze wyszukiwanie pinów i konfiguracja sprzętu

- Najpierw zidentyfikuj Vtref i GND za pomocą multimetru. Wiele adapterów wymaga Vtref do ustawienia napięcia I/O.
- Translacja poziomów: preferuj dwukierunkowe translatory poziomów przeznaczone do sygnałów push-pull (linie JTAG nie są typu open-drain). Unikaj automatycznych translatorów kierunku I2C w przypadku JTAG.
- Przydatne adaptery: płytki FT2232H/FT232H (np. Tigard), CMSIS-DAP, J-Link, ST-LINK (zależne od producenta), ESP-USB-JTAG (w ESP32-Sx). Podłącz co najmniej TCK, TMS, TDI, TDO, GND i Vtref; opcjonalnie także TRST i SRST.

W przypadku nieopisanego złącza zidentyfikuj GND, sprawdzając ciągłość połączenia ze znaną płaszczyzną masy **przy wyłączonym zasilaniu urządzenia**. Po przełączeniu multimetru w tryb pomiaru napięcia i włączeniu zasilania nie uznawaj każdego pinu o wysokim napięciu za Vtref: wejścia cyfrowe w stanie wysokim mogą wyglądać podobnie na mierniku. Prześledź potencjalne linie zasilania do pobliskich kondensatorów odsprzęgających i porównaj przebiegi ich napięcia podczas włączania i wyłączania zasilania za pomocą oscyloskopu. Wolniejszy wzrost lub spadek napięcia o kształcie charakterystycznym dla kondensatora wskazuje na linię zasilania lub odniesienia, ale przed podłączeniem sondy z translacją poziomów sprawdź napięcie i połączenia. W PiFex można wybrać zewnętrzne napięcie odniesienia o niższej wartości dla urządzenia docelowego za pomocą `VCCA_IN`, zamiast korzystać z domyślnego ustawienia 3,3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** to narzędzie, które można uruchomić na mikrokontrolerze zgodnym z Arduino lub, eksperymentalnie, na Raspberry Pi, aby metodą brute-force sprawdzić nieznany układ pinów JTAG i wyliczyć rejestry instrukcji.<sup>[[3]](#references)</sup>

- Arduino: podłącz piny cyfrowe D2–D11 do maksymalnie 10 podejrzanych padów/punktów testowych JTAG, a GND Arduino do GND urządzenia docelowego. Zasilaj urządzenie docelowe osobno, chyba że masz pewność, że dana linia zasilania jest bezpieczna. Preferuj logikę 3,3 V (np. Arduino Due) albo użyj translatora poziomów/rezystorów szeregowych podczas testowania urządzeń docelowych z napięciem 1,8–3,3 V.
- Raspberry Pi: kompilacja dla Pi udostępnia mniej użytecznych GPIO (więc skanowanie trwa dłużej); sprawdź repozytorium, aby poznać aktualną mapę pinów i ograniczenia.

Po wgraniu programu otwórz monitor portu szeregowego z szybkością 115200 baud i wyślij `h`, aby wyświetlić pomoc. Typowy przebieg:

- `l` znajdź pętle zwrotne, aby uniknąć fałszywych trafień
- `r` przełącz wewnętrzne rezystory pull-up, jeśli to konieczne
- `s` skanuj w poszukiwaniu TCK/TMS/TDI/TDO (a czasem TRST/SRST)
- `y` użyj brute-force na IR, aby odkryć nieudokumentowane kody operacji
- `x` wykonaj migawkę stanów pinów przez boundary-scan

![JTAG - JTAGenum: x migawka stanów pinów przez boundary-scan](<../../images/image (939).png>)

![JTAG - JTAGenum: x migawka stanów pinów przez boundary-scan](<../../images/image (578).png>)

![JTAG - JTAGenum: x migawka stanów pinów przez boundary-scan](<../../images/image (774).png>)



Jeśli zostanie znaleziony prawidłowy TAP, pojawią się wiersze zaczynające się od `FOUND!`, wskazujące wykryte piny.

### Wskazówki dotyczące bezpieczeństwa JTAGenum

- Zawsze łącz masy i nigdy nie podawaj na nieznane piny napięcia wyższego niż Vtref urządzenia docelowego. W razie wątpliwości dodaj rezystory szeregowe 100–470 Ω na podejrzanych pinach.
- Jeśli urządzenie używa SWD/SWJ zamiast 4-przewodowego JTAG, JTAGenum może go nie wykryć; wypróbuj narzędzia SWD albo adapter obsługujący SWJ-DP.

## Wykrywanie pinów GPIO za pomocą go-jtagenum

Na zasilanym urządzeniu docelowym, ze sprawdzonym wspólnym uziemieniem i zgodnym napięciem I/O, `go-jtagenum` może wyliczyć potencjalne sygnały JTAG z pinów GPIO Raspberry Pi. JSON `-pins` mapuje etykiety na **numery GPIO**, a nie pozycje fizyczne na złączu.<sup>[[5]](#references)</sup> W przykładzie z dyskiem SSD pierwszy skan IDCODE zgłosił również nieprawdopodobnie długi łańcuch zmieniających się wartości: sama zmieniająca się linia TDO nie jest dowodem na prawidłowy TAP. Zweryfikuj ponownie wiarygodny wynik za pomocą skanu BYPASS, który przesuwa znany wzorzec bitowy z TDI przez jednobitowy rejestr bypass do TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

W przypadku tej płytki BYPASS potwierdził `TCK=10`, `TMS=14`, `TDI=9` i `TDO=15`; pozostałe piny były jedynie **możliwymi** kandydatami na nTRST. Jeśli kandydat zwraca same zera lub niespójny wzorzec, przed przypisaniem mu sygnału sprawdź styk, zasilanie układu docelowego, rezystory podciągające oraz opóźnienia zegara/resetu.<sup>[[4]](#references)[[5]](#references)</sup> Narzędzie obsługuje też opcję `-known-pins` z `test_bypass`, aby ponownie przetestować odzyskane mapowanie.<sup>[[5]](#references)</sup>

## Charakteryzowanie nieudokumentowanego TAP za pomocą UrJTAG

Odkryty pinout nie określa kodów opcode rejestru instrukcji (IR) ani szerokości rejestrów danych (DR) potrzebnych do debugowania. W kompilacji UrJTAG obsługującej kabel Raspberry Pi GPIO ustaw odzyskane mapowanie i uruchom kolejno `idcode`, `detect`, a następnie `discover`. Przykład z SSD wykrył jeden TAP, czterobitowy IR oraz różne szerokości DR dla różnych wartości IR. Długość DR równa `-1` lub komunikat „TDO stuck at 0” nie stanowią użytecznej definicji rejestru; zamiast przypisywać mu szerokość, sprawdź taktowanie, okablowanie i wybraną instrukcję.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

To rekonesans TAP, a nie automatyczna identyfikacja CPU: porównaj uzyskany IDCODE z dokumentacją urządzenia i obsługiwanymi targetami OpenOCD. Lokalna baza producentów UrJTAG może oznaczyć prawidłowy skądinąd ID jako nieznany.<sup>[[4]](#references)</sup>

## Pierwszy kontakt z OpenOCD (skanowanie i IDCODE)

OpenOCD to de facto OSS dla JTAG/SWD. Przy użyciu obsługiwanego adaptera możesz przeskanować łańcuch i odczytać IDCODE:<sup>[[1]](#references)</sup>

- Ogólny przykład z J-Linkiem:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Wbudowany USB-JTAG w ESP32‑S3 (nie wymaga zewnętrznego programatora):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Uwagi

- Jeśli otrzymujesz IDCODE składający się z samych jedynek/zer, sprawdź okablowanie, zasilanie, Vtref i to, czy port nie jest zablokowany przez fuse’y/option bytes.
- Podczas uruchamiania nieznanych łańcuchów zobacz niskopoziomowe polecenia OpenOCD `irscan`/`drscan` do ręcznej interakcji z TAP.<sup>[[1]](#references)</sup>

## Dodawanie nieudokumentowanego celu do OpenOCD

Gdy znane są już ID TAP i długość IR, sprawdź skrypty OpenOCD w katalogach `cpu/`, `target/` i `board/`, aby znaleźć **zgodną architekturę CPU**, a następnie utwórz osobne konfiguracje adaptera i celu.<sup>[[4]](#references)[[6]](#references)</sup> Poniższe mapowanie GPIO Pi i konfiguracja celu ARCv2 to przetestowany przykład SSD, a nie uniwersalna konfiguracja JTAG. Wybór celu ARC i ustawienia debugowania były założeniami, które sprawdziły się w przypadku tego urządzenia; używając innej płytki, zastąp je zmierzonym ID, długością IR, architekturą i numerami GPIO celu.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Uruchom `openocd -f raspberrypi-io.cfg -f target.cfg` i przed odczytem pamięci upewnij się, że badanie TAP zakończyło się powodzeniem. W przykładzie uruchomiono Telnet na porcie `4444` oraz serwer GDB na porcie `3333`; samo rozpoznanie IDCODE nie dowodzi, że wybrany target CPU można zbadać ani debugować.<sup>[[4]](#references)</sup> GPIO Raspberry Pi nie muszą być pinami oznaczonymi jako JTAG na płytce breakout, jeśli adapter pozwala na remapowanie `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Zatrzymywanie CPU i zrzucanie pamięci/flash

Po rozpoznaniu TAP i wybraniu skryptu targetu możesz zatrzymać rdzeń i zrzucić regiony pamięci lub wewnętrzny flash. Przykłady (dostosuj target, adresy bazowe i rozmiary):<sup>[[1]](#references)</sup>

- Ogólny target po init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC-V (preferuj SBA, jeśli jest dostępne):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programowanie lub odczyt za pomocą narzędzia pomocniczego OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Wskazówki dotyczące zrzucania pamięci

- Użyj `mdw/mdh/mdb`, aby szybko sprawdzić pamięć przed wykonaniem długich zrzutów.
- W łańcuchach z wieloma urządzeniami ustaw BYPASS dla urządzeń innych niż docelowe albo użyj pliku board definiującego wszystkie TAP-y.

W przypadku nieudokumentowanej mapy pamięci, podczas analizy SSD sprawdzono zrzut o rozmiarze 1 MiB pod kątem rozpoznawalnych ciągów znaków kontrolera, a następnie użyto GDB obsługującego daną architekturę przez OpenOCD do sprawdzenia `$pc`, deasemblacji i rejestrów. Te adresy odczytane na żywo pomogły wskazać drugi obszar do zrzutu, który następnie porównano z pasującymi instrukcjami w kompilacji Ghidry obsługującej ARC. Same ciągi znaków są jedynie wstępnym sprawdzeniem wiarygodności, a nie dowodem, że obraz jest kompletny lub poprawnie zmapowany.<sup>[[4]](#references)</sup> Zobacz [analizę firmware](../firmware-analysis/), aby poznać szersze omówienie etapów analizy statycznej.

## Sztuczki z boundary-scan (EXTEST/SAMPLE)

Nawet gdy dostęp do debugowania CPU jest zablokowany, boundary-scan może być nadal dostępny. Za pomocą UrJTAG/OpenOCD możesz:<sup>[[1]](#references)</sup>
- Użyć SAMPLE do zarejestrowania stanów pinów podczas działania systemu (wykrywania aktywności magistrali i potwierdzania mapowania pinów).
- Użyć EXTEST do sterowania pinami (np. bit-bangować linie zewnętrznej pamięci flash SPI za pośrednictwem MCU, aby odczytać ją offline, jeśli pozwala na to okablowanie płytki).

Minimalny przebieg UrJTAG z adapterem FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Potrzebujesz pliku BSDL, aby poznać kolejność bitów w rejestrze boundary. Pamiętaj, że niektórzy producenci blokują komórki boundary-scan na etapie produkcji.

## Nowoczesne układy i uwagi

- ESP32‑S3/C3 mają wbudowany mostek USB‑JTAG; OpenOCD może komunikować się bezpośrednio przez USB, bez zewnętrznego programatora. Bardzo przydatne podczas wstępnej analizy i zrzutów danych.<sup>[[2]](#references)</sup>
- Debugowanie RISC‑V (v0.13+) jest szeroko obsługiwane przez OpenOCD; w przypadku dostępu do pamięci preferuj SBA, gdy nie można bezpiecznie zatrzymać rdzenia.
- Wiele mikrokontrolerów implementuje uwierzytelnianie debugowania i stany cyklu życia. Jeśli JTAG nie działa, mimo że zasilanie jest prawidłowe, układ może być zaprogramowany bezpiecznikami w stan zamknięty albo wymagać uwierzytelnionego programatora.

## Zabezpieczenia i wzmacnianie ochrony (czego można się spodziewać w rzeczywistych urządzeniach)

- Trwale wyłącz lub zablokuj JTAG/SWD w produkcji (np. STM32 RDP poziom 2, bezpieczniki eFuse ESP wyłączające PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Wymagaj uwierzytelnionego debugowania (ARMv8.2‑A ADIv6 Debug Authentication, uwierzytelnianie challenge-response zarządzane przez producenta), zachowując jednocześnie dostęp produkcyjny.
- Nie wyprowadzaj łatwo dostępnych padów testowych; ukrywaj przelotki testowe, usuwaj lub montuj rezystory, aby odizolować TAP, oraz używaj złączy z kluczowaniem lub przyrządów testowych z pinami pogo.
- Blokada debugowania przy włączaniu zasilania: zabezpiecz TAP, tak aby dostęp do niego kontrolował wczesny ROM wymuszający bezpieczne uruchamianie.

## References

- [1] [Przewodnik użytkownika OpenOCD – polecenia JTAG i konfiguracja](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debugowanie JTAG w Espressif ESP32‑S3 (USB‑JTAG, korzystanie z OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – skaner pinoutu JTAG oparty na Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — hakowanie JTAG za pomocą Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — enumeracja GPIO JTAG](https://github.com/gremwell/go-jtagenum)
- [6] [Przewodnik użytkownika OpenOCD — konfiguracja adaptera debugowania](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
