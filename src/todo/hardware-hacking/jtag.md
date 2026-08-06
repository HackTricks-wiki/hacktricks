# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) to narzędzie, które można wgrać do MCU kompatybilnego z Arduino lub (eksperymentalnie) do Raspberry Pi, aby metodą brute-force wykrywać nieznane układy pinów JTAG, a nawet wyliczać rejestry instrukcji.

- Arduino: podłącz piny cyfrowe D2–D11 do maksymalnie 10 podejrzanych padów/punktów testowych JTAG, a Arduino GND do GND urządzenia docelowego. Zasilaj urządzenie docelowe osobno, chyba że masz pewność, że dana szyna jest bezpieczna. Preferuj logikę 3,3 V (np. Arduino Due) albo użyj level shiftera/rezystorów szeregowych podczas testowania urządzeń docelowych 1,8–3,3 V.
- Raspberry Pi: wersja dla Pi udostępnia mniej użytecznych GPIO (więc skany są wolniejsze); sprawdź repozytorium pod kątem aktualnej mapy pinów i ograniczeń.

Po wgraniu firmware'u otwórz monitor portu szeregowego z prędkością 115200 baudów i wyślij `h`, aby wyświetlić pomoc. Typowy przebieg:

- `l` znajdź loopbacki, aby uniknąć false positives
- `r` przełącz wewnętrzne pull-upy, jeśli jest to wymagane
- `s` skanuj w poszukiwaniu TCK/TMS/TDI/TDO (a czasami TRST/SRST)
- `y` wykonaj brute-force IR, aby odkryć nieudokumentowane opcode'y
- `x` wykonaj snapshot boundary-scan stanu pinów

![JTAG - JTAGenum: x snapshot boundary-scan stanu pinów](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot boundary-scan stanu pinów](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot boundary-scan stanu pinów](<../../images/image (774).png>)



Jeśli zostanie znaleziony prawidłowy TAP, zobaczysz wiersze zaczynające się od `FOUND!`, wskazujące wykryte piny.

Wskazówki
- Zawsze zapewniaj wspólną masę i nigdy nie steruj nieznanymi pinami napięciem wyższym niż Vtref urządzenia docelowego. W razie wątpliwości dodaj rezystory szeregowe 100–470 Ω na pinach kandydujących.
- Jeśli urządzenie używa SWD/SWJ zamiast 4-przewodowego JTAG, JTAGenum może go nie wykryć; wypróbuj narzędzia SWD lub adapter obsługujący SWJ-DP.

## Bezpieczniejsze wyszukiwanie pinów i konfiguracja sprzętowa

- Najpierw zidentyfikuj Vtref i GND za pomocą multimetru. Wiele adapterów potrzebuje Vtref do ustawienia napięcia I/O.
- Level shifting: preferuj dwukierunkowe level shiftery przeznaczone do sygnałów push-pull (linie JTAG nie są open-drain). Unikaj automatycznych level shifterów I2C w przypadku JTAG.
- Przydatne adaptery: płytki FT2232H/FT232H (np. Tigard), CMSIS-DAP, J-Link, ST-LINK (zależny od producenta), ESP-USB-JTAG (w ESP32-Sx). Podłącz co najmniej TCK, TMS, TDI, TDO, GND i Vtref; opcjonalnie także TRST i SRST.

## Pierwszy kontakt z OpenOCD (skanowanie i IDCODE)

OpenOCD to de facto OSS dla JTAG/SWD. Za pomocą obsługiwanego adaptera możesz przeskanować chain i odczytać IDCODE:<sup>[[1]](#references)</sup>

- Ogólny przykład z J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Wbudowany USB-JTAG w ESP32-S3 (nie jest wymagany zewnętrzny probe):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notatki
- Jeśli otrzymasz IDCODE składający się z samych jedynek/zer, sprawdź okablowanie, zasilanie, Vtref oraz to, czy port nie jest zablokowany przez fuse/option bytes.
- Zobacz niskopoziomowe `irscan`/`drscan` w OpenOCD, aby ręcznie obsługiwać TAP podczas uruchamiania nieznanych łańcuchów.<sup>[[1]](#references)</sup>

## Zatrzymywanie CPU i zrzucanie pamięci/flash

Po rozpoznaniu TAP i wybraniu target script możesz zatrzymać rdzeń oraz zrzucić regiony pamięci lub wewnętrzny flash. Przykłady (dostosuj target, adresy bazowe i rozmiary):<sup>[[1]](#references)</sup>

- Generic target po init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferuj SBA, jeśli dostępne):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programowanie lub odczyt za pomocą OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Wskazówki
- Użyj `mdw/mdh/mdb`, aby sprawdzić poprawność pamięci przed długimi zrzutami.
- W przypadku łańcuchów z wieloma urządzeniami ustaw BYPASS dla urządzeń niebędących celami albo użyj pliku board definiującego wszystkie TAP-y.

## Sztuczki boundary-scan (EXTEST/SAMPLE)

Nawet gdy dostęp debugowania CPU jest zablokowany, boundary-scan może być nadal dostępny. Za pomocą UrJTAG/OpenOCD możesz:<sup>[[1]](#references)</sup>
- Użyć SAMPLE do zarejestrowania stanów pinów podczas działania systemu (znaleźć aktywność magistrali, potwierdzić mapowanie pinów).
- Użyć EXTEST do sterowania pinami (np. wykonać bit-bang na liniach zewnętrznej pamięci SPI za pośrednictwem MCU, aby odczytać ją offline, jeśli pozwala na to okablowanie board).

Minimalny przepływ UrJTAG z adapterem FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Aby poznać kolejność bitów rejestru boundary, potrzebujesz BSDL urządzenia. Uważaj, ponieważ niektórzy vendorzy blokują komórki boundary-scan w produkcji.

## Nowoczesne cele i uwagi

- ESP32-S3/C3 zawierają natywny mostek USB-JTAG; OpenOCD może komunikować się bezpośrednio przez USB bez zewnętrznego probe'a. Jest to bardzo wygodne podczas triage i wykonywania dumpów.<sup>[[2]](#references)</sup>
- Debugowanie RISC-V (v0.13+) jest szeroko obsługiwane przez OpenOCD; preferuj SBA do dostępu do pamięci, gdy rdzenia nie można bezpiecznie zatrzymać.
- Wiele MCU implementuje uwierzytelnianie debugowania i stany lifecycle. Jeśli JTAG wydaje się nieaktywny, ale zasilanie jest prawidłowe, urządzenie mogło zostać zaprogramowane do stanu zamkniętego albo wymaga uwierzytelnionego probe'a.

## Zabezpieczenia i hardening (czego oczekiwać na rzeczywistych urządzeniach)

- Trwale wyłącz lub zablokuj JTAG/SWD w produkcji (np. STM32 RDP level 2, eFuses ESP wyłączające PAD JTAG, APPROTECT/DPAP w NXP/Nordic).
- Wymagaj uwierzytelnionego debugowania (ARMv8.2-A ADIv6 Debug Authentication, zarządzane przez OEM challenge-response), zachowując jednocześnie dostęp produkcyjny.
- Nie wyprowadzaj łatwo dostępnych test padów; ukrywaj test vias, usuwaj lub montuj rezystory w celu odizolowania TAP, używaj złączy z kluczowaniem albo fixture'ów z pogo pinami.
- Blokada debugowania przy włączaniu zasilania: umieść TAP za wczesnym ROM-em wymuszającym secure boot.

## Referencje

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
