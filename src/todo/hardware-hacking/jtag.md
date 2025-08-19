# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) to narzędzie, które możesz załadować na kompatybilny z Arduino MCU lub (eksperymentalnie) Raspberry Pi, aby przeprowadzić brute-force nieznanych pinoutów JTAG i nawet enumerować rejestry instrukcji.

- Arduino: podłącz cyfrowe piny D2–D11 do maksymalnie 10 podejrzewanych padów/testpointów JTAG, a GND Arduino do GND celu. Zasilaj cel osobno, chyba że wiesz, że szyna jest bezpieczna. Preferuj logikę 3.3 V (np. Arduino Due) lub użyj konwertera poziomów/oporników szeregowych przy badaniu celów 1.8–3.3 V.
- Raspberry Pi: budowa Pi udostępnia mniej użytecznych GPIO (więc skany są wolniejsze); sprawdź repozytorium, aby uzyskać aktualną mapę pinów i ograniczenia.

Po wgraniu, otwórz monitor szeregowy na 115200 baud i wyślij `h` po pomoc. Typowy przepływ:

- `l` znajdź pętle, aby uniknąć fałszywych pozytywów
- `r` przełącz wewnętrzne pull-upy, jeśli to konieczne
- `s` skanowanie TCK/TMS/TDI/TDO (a czasami TRST/SRST)
- `y` brute-force IR, aby odkryć nieudokumentowane opkody
- `x` zrzut stanu pinów w boundary-scan

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)

Jeśli znajdziesz ważny TAP, zobaczysz linie zaczynające się od `FOUND!`, wskazujące odkryte piny.

Wskazówki
- Zawsze dziel wspólną masę i nigdy nie podnoś nieznanych pinów powyżej Vtref celu. W razie wątpliwości, dodaj oporniki szeregowe 100–470 Ω na pinach kandydujących.
- Jeśli urządzenie używa SWD/SWJ zamiast 4-przewodowego JTAG, JTAGenum może go nie wykryć; spróbuj narzędzi SWD lub adaptera, który obsługuje SWJ-DP.

## Bezpieczniejsze poszukiwanie pinów i konfiguracja sprzętowa

- Najpierw zidentyfikuj Vtref i GND za pomocą multimetru. Wiele adapterów potrzebuje Vtref do ustawienia napięcia I/O.
- Zmiana poziomów: preferuj dwukierunkowe konwertery poziomów zaprojektowane do sygnałów push-pull (linie JTAG nie są otwartym drenem). Unikaj konwerterów I2C z automatycznym kierunkiem dla JTAG.
- Przydatne adaptery: płytki FT2232H/FT232H (np. Tigard), CMSIS-DAP, J-Link, ST-LINK (specyficzne dla dostawcy), ESP-USB-JTAG (na ESP32-Sx). Podłącz przynajmniej TCK, TMS, TDI, TDO, GND i Vtref; opcjonalnie TRST i SRST.

## Pierwszy kontakt z OpenOCD (skanowanie i IDCODE)

OpenOCD to de facto OSS dla JTAG/SWD. Z obsługiwanym adapterem możesz skanować łańcuch i odczytywać IDCODE:

- Przykład ogólny z J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Wbudowany USB‑JTAG w ESP32‑S3 (nie wymaga zewnętrznego sondy):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notatki
- Jeśli otrzymasz "wszystkie jedynki/zera" IDCODE, sprawdź okablowanie, zasilanie, Vtref oraz to, czy port nie jest zablokowany przez bezpieczniki/bajty opcji.
- Zobacz OpenOCD niskopoziomowe `irscan`/`drscan` dla ręcznej interakcji TAP podczas uruchamiania nieznanych łańcuchów.

## Zatrzymywanie CPU i zrzut pamięci/flash

Gdy TAP zostanie rozpoznany i wybrany skrypt docelowy, możesz zatrzymać rdzeń i zrzucić obszary pamięci lub wewnętrzny flash. Przykłady (dostosuj cel, adresy bazowe i rozmiary):
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferuj SBA, gdy dostępne):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programuj lub odczytuj za pomocą pomocnika OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Użyj `mdw/mdh/mdb`, aby sprawdzić pamięć przed długimi zrzutami.
- W przypadku łańcuchów z wieloma urządzeniami, ustaw BYPASS na niecelach lub użyj pliku płyty, który definiuje wszystkie TAPy.

## Sztuczki z boundary-scan (EXTEST/SAMPLE)

Nawet gdy dostęp debugowania CPU jest zablokowany, boundary-scan może być nadal dostępny. Z UrJTAG/OpenOCD możesz:
- SAMPLE, aby uchwycić stany pinów podczas działania systemu (znaleźć aktywność magistrali, potwierdzić mapowanie pinów).
- EXTEST, aby sterować pinami (np. bit-bang zewnętrzne linie SPI flash za pośrednictwem MCU, aby odczytać je offline, jeśli okablowanie płyty na to pozwala).

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
Musisz mieć urządzenie BSDL, aby poznać kolejność bitów rejestru granicznego. Uważaj, że niektórzy dostawcy blokują komórki skanowania granicznego w produkcji.

## Nowoczesne cele i uwagi

- ESP32‑S3/C3 zawiera natywny mostek USB‑JTAG; OpenOCD może komunikować się bezpośrednio przez USB bez zewnętrznego sondy. Bardzo wygodne do triage i zrzutów.
- Debugowanie RISC‑V (v0.13+) jest szeroko wspierane przez OpenOCD; preferuj SBA do dostępu do pamięci, gdy rdzeń nie może być bezpiecznie zatrzymany.
- Wiele MCU implementuje uwierzytelnianie debugowania i stany cyklu życia. Jeśli JTAG wydaje się martwy, ale zasilanie jest poprawne, urządzenie może być zablokowane w zamkniętym stanie lub wymaga uwierzytelnionej sondy.

## Ochrona i wzmocnienie (czego się spodziewać w rzeczywistych urządzeniach)

- Na stałe wyłącz lub zablokuj JTAG/SWD w produkcji (np. STM32 RDP poziom 2, ESP eFuses, które wyłączają PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Wymagaj uwierzytelnionego debugowania (ARMv8.2‑A ADIv6 Debug Authentication, zarządzane przez OEM wyzwanie-odpowiedź) przy zachowaniu dostępu do produkcji.
- Nie prowadź łatwych padów testowych; ukryj otwory testowe, usuń/zamień rezystory, aby izolować TAP, użyj złączy z kluczem lub elementów pogo-pin.
- Blokada debugowania przy włączaniu: zablokuj TAP za wczesnym ROM, wymuszającym bezpieczne uruchamianie.

## Odniesienia

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
