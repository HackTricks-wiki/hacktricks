# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** to narzędzie, które można uruchomić na mikrokontrolerze zgodnym z Arduino lub eksperymentalnie na Raspberry Pi, aby metodą brute force ustalić nieznany układ pinów JTAG i wyliczyć rejestry instrukcji.<sup>[[3]](#references)</sup>

- Arduino: podłącz piny cyfrowe D2–D11 do maksymalnie 10 podejrzewanych padów/testpointów JTAG, a pin GND Arduino do GND urządzenia docelowego. Zasilaj urządzenie docelowe osobno, chyba że masz pewność, że dana linia zasilania jest bezpieczna. Preferuj logikę 3,3 V (np. Arduino Due) lub użyj konwertera poziomów/rezystorów szeregowych podczas testowania urządzeń z napięciem 1,8–3,3 V.
- Raspberry Pi: wersja dla Pi udostępnia mniej użytecznych GPIO (dlatego skanowanie trwa dłużej); sprawdź repozytorium, aby poznać aktualną mapę pinów i ograniczenia.

Po wgraniu programu otwórz monitor portu szeregowego z szybkością 115200 baud i wyślij `h`, aby wyświetlić pomoc. Typowy przebieg:

- `l` wyszukuje pętle zwrotne, aby uniknąć wyników fałszywie dodatnich
- `r` w razie potrzeby przełącza wewnętrzne rezystory podciągające
- `s` skanuje w poszukiwaniu TCK/TMS/TDI/TDO (a czasami TRST/SRST)
- `y` metodą brute force sprawdza IR, aby odkryć nieudokumentowane kody operacji
- `x` wykonuje zrzut stanu pinów przez boundary scan

![JTAG - JTAGenum: x zrzut stanu pinów przez boundary scan](<../../images/image (939).png>)

![JTAG - JTAGenum: x zrzut stanu pinów przez boundary scan](<../../images/image (578).png>)

![JTAG - JTAGenum: x zrzut stanu pinów przez boundary scan](<../../images/image (774).png>)



Jeśli zostanie znaleziony prawidłowy TAP, pojawią się wiersze zaczynające się od `FOUND!`, wskazujące wykryte piny.

### Wskazówki dotyczące bezpieczeństwa podczas korzystania z JTAGenum

- Zawsze łącz masy i nigdy nie podawaj na nieznane piny napięcia wyższego niż Vtref urządzenia docelowego. W razie wątpliwości dodaj rezystory szeregowe 100–470 Ω do testowanych pinów.
- Jeśli urządzenie korzysta z SWD/SWJ zamiast 4-przewodowego JTAG, JTAGenum może go nie wykryć; wypróbuj narzędzia SWD lub adapter obsługujący SWJ-DP.

## Bezpieczniejsze wyszukiwanie pinów i konfiguracja sprzętu

- Najpierw ustal za pomocą multimetru, które piny to Vtref i GND. Wiele adapterów wymaga Vtref do ustawienia napięcia I/O.
- Konwersja poziomów: preferuj dwukierunkowe konwertery poziomów przeznaczone do sygnałów push-pull (linie JTAG nie są typu open-drain). Unikaj konwerterów I2C z automatycznym określaniem kierunku sygnału.
- Przydatne adaptery: płytki FT2232H/FT232H (np. Tigard), CMSIS-DAP, J-Link, ST-LINK (zależny od producenta), ESP-USB-JTAG (w ESP32-Sx). Podłącz co najmniej TCK, TMS, TDI, TDO, GND i Vtref; opcjonalnie także TRST i SRST.

## Pierwszy kontakt z OpenOCD (skanowanie i IDCODE)

OpenOCD to de facto standardowe oprogramowanie open source do JTAG/SWD. Za pomocą obsługiwanego adaptera można przeskanować łańcuch i odczytać kody IDCODE:<sup>[[1]](#references)</sup>

- Ogólny przykład z J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Wbudowany USB-JTAG w ESP32‑S3 (nie wymaga zewnętrznej sondy):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Uwagi

- Jeśli otrzymasz IDCODE składający się z samych jedynek/zer, sprawdź okablowanie, zasilanie, Vtref oraz czy port nie jest zablokowany przez fuse’y/bajty opcji.
- Zobacz niskopoziomowe polecenia OpenOCD `irscan`/`drscan`, umożliwiające ręczną interakcję z TAP podczas uruchamiania nieznanych łańcuchów.<sup>[[1]](#references)</sup>

## Zatrzymywanie CPU i zrzucanie pamięci/flash

Po rozpoznaniu TAP i wybraniu skryptu targetu możesz zatrzymać rdzeń i zrzucić obszary pamięci lub wewnętrzny flash. Przykłady (dostosuj target, adresy bazowe i rozmiary):<sup>[[1]](#references)</sup>

- Ogólny target po inicjalizacji:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (preferuj SBA, jeśli jest dostępne):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programowanie lub odczyt za pomocą pomocnika OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Wskazówki dotyczące zrzucania pamięci

- Użyj `mdw/mdh/mdb`, aby wstępnie sprawdzić pamięć przed wykonaniem długiego zrzutu.
- W łańcuchach z wieloma urządzeniami ustaw BYPASS dla urządzeń innych niż docelowe albo użyj pliku board definiującego wszystkie TAP-y.

## Sztuczki boundary-scan (EXTEST/SAMPLE)

Nawet gdy dostęp debugowania CPU jest zablokowany, boundary-scan może być nadal dostępny. Za pomocą UrJTAG/OpenOCD możesz:<sup>[[1]](#references)</sup>
- Użyć SAMPLE, aby zarejestrować stany pinów podczas działania systemu (wykryć aktywność magistrali, potwierdzić mapowanie pinów).
- Użyć EXTEST do sterowania pinami (np. bit-bangować linie zewnętrznej pamięci flash SPI przez MCU, aby odczytać ją offline, jeśli pozwala na to okablowanie płytki).

Minimalny przepływ pracy UrJTAG z adapterem FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Do poznania kolejności bitów w rejestrze boundary potrzebny jest plik BSDL urządzenia. Uważaj: niektórzy producenci blokują komórki boundary-scan w urządzeniach przeznaczonych do produkcji.

## Nowoczesne cele i uwagi

- ESP32‑S3/C3 mają natywny mostek USB‑JTAG; OpenOCD może komunikować się bezpośrednio przez USB, bez zewnętrznego debuggera. Bardzo wygodne podczas wstępnej analizy i zrzutów danych.<sup>[[2]](#references)</sup>
- Debugowanie RISC‑V (v0.13+) jest szeroko obsługiwane przez OpenOCD; jeśli nie można bezpiecznie zatrzymać rdzenia, do dostępu do pamięci preferuj SBA.
- Wiele MCU implementuje uwierzytelnianie debugowania i stany cyklu życia. Jeśli JTAG nie działa, mimo że zasilanie jest prawidłowe, urządzenie może być trwale skonfigurowane w stanie zamkniętym lub wymagać uwierzytelnionego debuggera.

## Zabezpieczenia i hardening (czego można się spodziewać w rzeczywistych urządzeniach)

- Trwale wyłącz lub zablokuj JTAG/SWD w produkcji (np. STM32 RDP level 2, bezpieczniki eFuse w ESP wyłączające PAD JTAG, APPROTECT/DPAP w NXP/Nordic).
- Wymagaj uwierzytelnionego debugowania (ARMv8.2‑A ADIv6 Debug Authentication, zarządzane przez producenta OEM uwierzytelnianie challenge-response), zachowując jednocześnie dostęp na potrzeby produkcji.
- Nie wyprowadzaj łatwo dostępnych pól testowych; ukrywaj przelotki testowe, usuwaj lub montuj rezystory, aby odizolować TAP, oraz używaj złączy z kluczowaniem lub przyrządów z pinami pogo.
- Blokada debugowania przy włączaniu zasilania: odetnij dostęp do TAP za pomocą wczesnego kodu ROM wymuszającego secure boot.

## References

- [1] [Podręcznik użytkownika OpenOCD – polecenia i konfiguracja JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debugowanie JTAG w Espressif ESP32‑S3 (USB‑JTAG, obsługa OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – skaner pinów JTAG oparty na Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
