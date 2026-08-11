# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** to narzędzie, które można załadować na MCU kompatybilny z Arduino lub, eksperymentalnie, na Raspberry Pi, aby metodą brute-force wykrywać nieznane rozkłady pinów JTAG i wyliczać rejestry instrukcji.<sup>[[3]](#references)</sup>

- Arduino: połącz piny cyfrowe D2–D11 z maksymalnie 10 podejrzanymi padami/punktami testowymi JTAG, a Arduino GND z GND urządzenia docelowego. Zasilaj urządzenie docelowe osobno, chyba że masz pewność, że dana szyna zasilająca jest bezpieczna. Preferuj logikę 3,3 V (np. Arduino Due) lub użyj konwertera poziomów/rezystorów szeregowych podczas testowania urządzeń docelowych 1,8–3,3 V.
- Raspberry Pi: wersja dla Pi udostępnia mniej użytecznych GPIO (więc skanowanie jest wolniejsze); sprawdź repozytorium, aby poznać aktualne mapowanie pinów i ograniczenia.

Po wgraniu firmware'u otwórz monitor portu szeregowego z prędkością 115200 baudów i wyślij `h`, aby uzyskać pomoc. Typowy przebieg:

- `l` wyszukuje loopbacki, aby uniknąć false positives
- `r` przełącza wewnętrzne pull-upy, jeśli jest to potrzebne
- `s` skanuje w poszukiwaniu TCK/TMS/TDI/TDO (a czasami TRST/SRST)
- `y` wykonuje brute-force IR w celu wykrycia nieudokumentowanych opcode'ów
- `x` wykonuje snapshot boundary-scan stanów pinów

![JTAG - JTAGenum: x snapshot boundary-scan stanów pinów](<../../images/image (939).png>)

![JTAG - JTAGenum: x snapshot boundary-scan stanów pinów](<../../images/image (578).png>)

![JTAG - JTAGenum: x snapshot boundary-scan stanów pinów](<../../images/image (774).png>)



Jeśli zostanie znaleziony prawidłowy TAP, zobaczysz wiersze rozpoczynające się od `FOUND!`, wskazujące wykryte piny.

### Wskazówki dotyczące bezpieczeństwa JTAGenum

- Zawsze współdziel masę i nigdy nie steruj nieznanymi pinami napięciem wyższym niż Vtref urządzenia docelowego. W razie wątpliwości dodaj rezystory szeregowe 100–470 Ω na pinach kandydujących.
- Jeśli urządzenie używa SWD/SWJ zamiast 4-przewodowego JTAG, JTAGenum może go nie wykryć; wypróbuj narzędzia SWD lub adapter obsługujący SWJ-DP.

## Bezpieczniejsze wyszukiwanie pinów i konfiguracja sprzętowa

- Najpierw zidentyfikuj Vtref i GND za pomocą multimetru. Wiele adapterów wymaga Vtref do ustawienia napięcia I/O.
- Konwersja poziomów: preferuj dwukierunkowe konwertery poziomów przeznaczone dla sygnałów push-pull (linie JTAG nie są open-drain). Unikaj konwerterów I2C z automatycznym kierunkiem dla JTAG.
- Przydatne adaptery: płytki FT2232H/FT232H (np. Tigard), CMSIS-DAP, J-Link, ST-LINK (zależne od vendora), ESP-USB-JTAG (w ESP32-Sx). Podłącz co najmniej TCK, TMS, TDI, TDO, GND i Vtref; opcjonalnie TRST i SRST.

## Pierwszy kontakt z OpenOCD (skanowanie i IDCODE)

OpenOCD to de facto OSS dla JTAG/SWD. Za pomocą obsługiwanego adaptera możesz przeskanować łańcuch i odczytać IDCODE:<sup>[[1]](#references)</sup>

- Ogólny przykład z J-Linkiem:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Wbudowany USB-JTAG w ESP32-S3 (nie wymaga zewnętrznego probe’a):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Uwagi

- Jeśli otrzymasz IDCODE składający się z samych jedynek lub zer, sprawdź okablowanie, zasilanie, Vtref oraz to, czy port nie jest zablokowany przez fuse lub option bytes.
- Zobacz niskopoziomowe `irscan`/`drscan` w OpenOCD, aby ręcznie obsługiwać TAP podczas uruchamiania nieznanych łańcuchów.<sup>[[1]](#references)</sup>

## Zatrzymywanie CPU i zrzucanie pamięci/flash

Po rozpoznaniu TAP i wybraniu target scriptu możesz zatrzymać rdzeń oraz zrzucić zawartość regionów pamięci lub wewnętrznego flash. Przykłady (dostosuj target, adresy bazowe i rozmiary):<sup>[[1]](#references)</sup>

- Generic target po init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferuj SBA, jeśli jest dostępne):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programować lub odczytywać za pomocą pomocnika OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Wskazówki dotyczące zrzutu pamięci

- Użyj `mdw/mdh/mdb`, aby zweryfikować stan pamięci przed wykonaniem długich zrzutów.
- W przypadku łańcuchów z wieloma urządzeniami ustaw BYPASS na urządzeniach niebędących celami albo użyj pliku board, który definiuje wszystkie TAP-y.

## Sztuczki boundary-scan (EXTEST/SAMPLE)

Nawet gdy dostęp debugowania CPU jest zablokowany, boundary-scan może być nadal dostępny. Za pomocą UrJTAG/OpenOCD możesz:<sup>[[1]](#references)</sup>
- Użyć SAMPLE do zarejestrowania stanów pinów podczas działania systemu (wyszukać aktywność magistrali, potwierdzić mapowanie pinów).
- Użyć EXTEST do sterowania pinami (np. bit-bangować linie zewnętrznej pamięci flash SPI za pośrednictwem MCU, aby odczytać ją offline, jeśli okablowanie płytki na to pozwala).

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
Do zrozumienia kolejności bitów rejestru boundary potrzebny jest BSDL urządzenia. Należy pamiętać, że niektórzy producenci blokują komórki boundary-scan w produkcji.

## Nowoczesne cele i uwagi

- ESP32-S3/C3 zawierają natywny most USB-JTAG; OpenOCD może komunikować się bezpośrednio przez USB, bez zewnętrznego probe'a. Jest to bardzo wygodne podczas triage i wykonywania dumpów.<sup>[[2]](#references)</sup>
- Debugowanie RISC-V (v0.13+) jest szeroko obsługiwane przez OpenOCD; preferuj SBA do dostępu do pamięci, gdy rdzenia nie można bezpiecznie zatrzymać.
- Wiele MCU implementuje uwierzytelnianie debugowania i stany cyklu życia. Jeśli JTAG wydaje się nie działać, mimo że zasilanie jest prawidłowe, urządzenie mogło zostać zaprogramowane do stanu zamkniętego albo wymaga uwierzytelnionego probe'a.

## Zabezpieczenia i hardening (czego oczekiwać na rzeczywistych urządzeniach)

- Trwale wyłącz lub zablokuj JTAG/SWD w produkcji (np. STM32 RDP level 2, ESP eFuses wyłączające PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Wymagaj uwierzytelnionego debugowania (ARMv8.2-A ADIv6 Debug Authentication, zarządzane przez OEM challenge-response), zachowując dostęp produkcyjny.
- Nie wyprowadzaj łatwo dostępnych padów testowych; zakop vias testowe, usuwaj lub montuj rezystory w celu odizolowania TAP, używaj złączy z kluczem lub fixture'ów z pogo-pinami.
- Blokada debugowania przy włączaniu zasilania: umieść TAP za wczesnym ROM-em wymuszającym secure boot.

## References

- [1] [Przewodnik użytkownika OpenOCD – polecenia JTAG i konfiguracja](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debugowanie JTAG Espressif ESP32-S3 (USB-JTAG, użycie OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – skaner pinoutu JTAG oparty na Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
