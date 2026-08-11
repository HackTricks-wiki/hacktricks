# Naciśnięcia klawiszy USB

{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz plik pcap zawierający komunikację przez USB klawiatury, takiej jak poniżej:

![Naciśnięcia klawiszy USB: Jeśli masz plik pcap zawierający komunikację przez USB klawiatury, takiej jak poniżej](<../../../images/image (962).png>)

W przypadku klawiatury używającej **boot protocol** HID każdy raport Interrupt IN ma stały układ 8 bajtów: jeden bajt modyfikatorów, jeden zarezerwowany bajt i sześć bajtów keycode. Host porównuje kolejne raporty i mapuje keycode na HID usages, aby odtworzyć zdarzenia klawiszy.<sup>[[8]](#references)</sup>

## Podstawy raportów USB HID

Standardowy raport wejściowy klawiatury boot jest zorganizowany w następujący sposób.<sup>[[8]](#references)[[9]](#references)</sup>

| Bajt | Znaczenie |
| --- | --- |
| 0 | Bitmapa modyfikatorów (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt itd.). Jednocześnie może być ustawionych wiele bitów. |
| 1 | Zarezerwowany bajt; nieużywane raporty powinny zwykle ustawiać go na zero. Zastosowanie przez OEM lub system specyficzne dla danego systemu nie jest przenośne. |
| 2-7 | Maksymalnie sześć jednocześnie używanych keycode w formacie USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` oznacza „brak klawisza”. |

W układzie boot usage ID `0x01` (`Keyboard ErrorRollOver`) jest raportowany we wszystkich slotach klawiszy, gdy wciśniętych jest więcej niż sześć klawiszy innych niż modyfikatory; może również sygnalizować nierozpoznawalną kombinację.<sup>[[8]](#references)[[9]](#references)</sup> Zrozumienie tego układu jest pomocne, gdy masz tylko surowe bajty `usb.capdata`.

## Wyodrębnianie danych HID z pliku PCAP

### Najpierw zidentyfikuj interfejs klawiatury

W przypadku obszernych przechwyceń zidentyfikuj klawiaturę HID przed zrzuceniem raportów. Dobrym punktem wyjścia jest odpowiedź deskryptora interfejsu:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Klasa HID definiuje następujące wartości interfejsu:<sup>[[8]](#references)</sup>

- `subclass == 1` to Boot Interface Subclass; wraz z `protocol == 1` identyfikuje boot keyboard
- `protocol == 2` identyfikuje boot mouse
- `protocol == 0` oznacza brak boot protocol; zamiast zakładać układ 8-bajtowy, sprawdź deskryptor raportu HID

Po rozpoznaniu interfejsu przypnij filtry do `usb.bus_id`, `usb.device_address` oraz, jeśli to możliwe, `usb.bInterfaceNumber`, zanim cokolwiek wyeksportujesz.

### Workflow w Wireshark

1. **Odizoluj urządzenie**: filtruj ruch interrupt IN z klawiatury, np. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Dodaj przydatne kolumny**: kliknij prawym przyciskiem myszy pole `Leftover Capture Data` (`usb.capdata`) oraz wybrane pola `usbhid.*` (np. `usbhid.boot_report.keyboard.keycode_1`), aby śledzić naciśnięcia klawiszy bez otwierania każdej ramki.<sup>[[11]](#references)</sup>
3. **Ukryj puste raporty**: zastosuj `!(usb.capdata == 00:00:00:00:00:00:00:00)`, aby pominąć ramki bezczynności.
4. **Wyeksportuj dane do dalszego przetwarzania**: `File -> Export Packet Dissections -> As CSV`, uwzględnij `frame.number`, `usb.src`, `usb.capdata` oraz zdekodowane pola modyfikatorów, takie jak `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`, aby później odtworzyć dane za pomocą skryptu.<sup>[[10]](#references)[[11]](#references)</sup>

### Workflow w wierszu poleceń

Klasyczny schemat ekstrakcji — zrzucenie `usb.capdata`, odrzucenie raportów bezczynności i mapowanie identyfikatorów usage — pojawia się w oryginalnej analizie z 2017 roku oraz w jej walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

Repository `ctf-usb-keyboard-parser` automatyzuje klasyczny pipeline tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
W nowszych przechwyceniach preferuj zdekodowane pole `usbhid.data` w Wiresharku, a w razie jego braku użyj `usb.capdata`; zapisuj jeden payload na raport do osobnego pliku dla każdego urządzenia:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Te pliki dla poszczególnych urządzeń można przekazać do dekodera po znormalizowaniu formatu hex, którego on oczekuje. Jeśli przechwycony ruch pochodził z klawiatur BLE tunelowanych przez GATT, filtruj za pomocą `btatt.value && frame.len == 20` i zrzucaj ładunki hex przed dekodowaniem.<sup>[[7]](#references)</sup>

### Gdy raport nie jest klasycznym 8-bajtowym raportem boot

Interfejs non-boot lub report ID może zmienić układ payloadu, dlatego nie zakładaj, że każdy raport klawiatury odpowiada układowi `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Preferuj `usbhid.data` zamiast `usb.capdata`, gdy Wireshark wcześniej przeanalizował warstwę HID.
- Jeśli każda linia zaczyna się stałym prefiksem lub report ID, usuń go za pomocą dekodera uwzględniającego offset, zamiast zakładać, że bajt 0 zawsze jest modyfikatorem.<sup>[[7]](#references)</sup>
- Niektóre eksporty USBPcap pomijają zarezerwowany bajt, dlatego dekodery obsługujące `--no-reserved` lub niestandardowy offset oszczędzają czas.<sup>[[7]](#references)</sup>
- Jeśli w przechwyconym ruchu znajduje się deskryptor raportu HID lub mapa raportu BLE HOGP, użyj jej do odtworzenia rzeczywistego układu pól przed napisaniem parsera.

## Automatyzacja dekodowania

- **ctf-usb-keyboard-parser** nadal jest przydatny podczas szybkich wyzwań CTF i jest już dołączony do repozytorium.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) natywnie analizuje pliki `pcap` i `pcapng`, obsługuje `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i nie wymaga tshark ani innej zewnętrznej zależności, więc nadaje się do izolowanych sandboxów.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** dodaje wizualizatory klawiatur, myszy i tabletów. Możesz uruchomić pomocniczy skrypt `extract_hid_data.sh` (backend tshark) lub `extract_hid_data.py` (backend scapy), a następnie przekazać wynikowy plik tekstowy do dekodera lub modułów replay, aby obserwować kolejne naciśnięcia klawiszy.<sup>[[7]](#references)</sup>

### Dekodowanie stanowe ma znaczenie

Klawiatury USB boot wysyłają raporty z częstotliwością idle nawet wtedy, gdy nie wystąpiło nowe zdarzenie klawisza, dlatego przechwycony ruch może zawierać powtarzające się raporty przed zdarzeniem zwolnienia klawisza. Praktyczny dekoder powinien:<sup>[[3]](#references)[[8]](#references)</sup>

- emitować tylko nowo naciśnięte keycode'y w porównaniu z poprzednim raportem
- zachowywać stan modyfikatorów (`Shift`, `Ctrl`, `AltGr`) z bajtu 0 lub przeanalizowanych pól, takich jak `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`
- śledzić klawisze przełączające, takie jak `Caps Lock`, ponieważ wielkość liter nie jest kontrolowana wyłącznie przez Shift
- pamiętać, że identyfikatory użycia HID są niezależne od układu: `0x1d` oznacza fizyczną pozycję klawisza `z`/`y` zależnie od układu klawiatury hosta.<sup>[[9]](#references)</sup>

## Szybki dekoder Python
```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
modifier = int(raw[0:2], 16)
keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
current = {k for k in keycodes if k}
newly_pressed = [k for k in keycodes if k and k not in prev]
shift = bool(modifier & 0x22)
for keycode in newly_pressed:
if keycode == 0x39:
caps = not caps
continue
char = SHIFTED.get(keycode) if shift else None
if char is None:
char = NORMAL.get(keycode, '?')
if char.isalpha() and (shift ^ caps):
char = char.upper()
sys.stdout.write(char)
prev = current
```
Nakarm go zwykłymi liniami hex zrzutowanymi wcześniej, aby natychmiast uzyskać przybliżoną rekonstrukcję bez wciągania pełnego parsera do środowiska. W przypadku układów innych niż US nadal rekonstruuje to fizyczną pozycję klawisza, a niekoniecznie końcowy znak wyświetlany na hoście ofiary.

## Troubleshooting tips

- Jeśli Wireshark nie wypełnia pól `usbhid.*`, prawdopodobnie nie przechwycono deskryptora raportu HID. Odłącz i ponownie podłącz klawiaturę podczas przechwytywania albo użyj surowego `usb.capdata`.
- W przechwytywaniu realizowanym przez software na Linuxie standardowym źródłem jest `usbmon`; w Windows Wireshark wymaga extcap **USBPcap**, aby w ogóle widzieć surowe URB USB.<sup>[[4]](#references)</sup>
- Jeśli klawiatura była podłączona przez hub lub dock, najpierw potwierdź deskryptor interfejsu, a następnie dekoduj tylko tę parę urządzenia/interfejsu. Przechwytywanie złożonych HID często miesza raporty klawiatury i myszy.
- Przechwytywanie w Windows wymaga interfejsu extcap **USBPcap**; upewnij się, że przetrwał aktualizacje Wireshark, ponieważ brak extcap skutkuje pustymi listami urządzeń.<sup>[[4]](#references)</sup>
- Zawsze skoreluj krotkę magistrali, urządzenia i interfejsu (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; np. `1.9.1`) przed rozpoczęciem dekodowania — mieszanie wielu klawiatur lub urządzeń pamięci masowej prowadzi do bezsensownych naciśnięć klawiszy.<sup>[[10]](#references)</sup>

## References

- [1] [Raport HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analiza przechwyconych pakietów klawiatury USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 — omówienie pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Konfiguracja przechwytywania USB w Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [parser klawiatury USB dla CTF](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [Parser klawiatury USB dla CTF](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Dekodery USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definicja klasy urządzenia dla Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabele zastosowań HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Informacje o filtrach wyświetlania Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Informacje o filtrach wyświetlania Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
