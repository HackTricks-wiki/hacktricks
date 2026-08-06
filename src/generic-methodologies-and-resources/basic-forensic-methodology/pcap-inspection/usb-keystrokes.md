# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz plik pcap zawierający komunikację przez USB klawiatury, jak na poniższym przykładzie:

![USB Keystrokes: Jeśli masz plik pcap zawierający komunikację przez USB klawiatury, jak na poniższym przykładzie](<../../../images/image (962).png>)

Klawiatury USB zwykle korzystają z **boot protocol** HID, dlatego każdy transfer interrupt do hosta ma długość zaledwie 8 bajtów: jeden bajt bitów modyfikatorów (Ctrl/Shift/Alt/Super), jeden zarezerwowany bajt oraz maksymalnie sześć keycode'ów w każdym raporcie. Zdekodowanie tych bajtów wystarcza do odtworzenia wszystkiego, co zostało wpisane.

## Podstawy raportów USB HID

Typowy raport IN wygląda następująco:

| Byte | Znaczenie |
| --- | --- |
| 0 | Mapa bitowa modyfikatorów (`0x02` = lewy Shift, `0x20` = prawy Alt itd.). Jednocześnie może być ustawionych wiele bitów. |
| 1 | Zarezerwowane/wypełniające, ale często wykorzystywane przez gaming keyboards do przesyłania danych producenta. |
| 2-7 | Maksymalnie sześć jednocześnie używanych keycode'ów w formacie USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` oznacza „brak klawisza”. |

Klawiatury bez NKRO zwykle wysyłają `0x01` w bajcie 2, gdy naciśniętych jest więcej niż sześć klawiszy, aby zasygnalizować „rollover”. Zrozumienie tego układu jest pomocne, gdy masz tylko surowe bajty `usb.capdata`.

## Wyodrębnianie danych HID z PCAP

### Najpierw zidentyfikuj interfejs klawiatury

W przypadku przechwyconych danych zawierających dużo ruchu najpierw zidentyfikuj klawiaturę HID, zanim zrzucisz raporty. Dobrym punktem wyjścia jest odpowiedź deskryptora interfejsu:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Sprawdź `usb.bInterfaceSubClass` i `usb.bInterfaceProtocol`:

- `subclass == 1` i `protocol == 1` zwykle oznaczają boot keyboard
- `protocol == 2` zazwyczaj oznacza mouse
- `protocol == 0` często oznacza zdefiniowany przez dostawcę lub działający w stylu NKRO interfejs HID, który nadal przenosi dane klawiatury, ale nie w prostym 8-bajtowym układzie boot

Po rozpoznaniu interfejsu przypnij filtry do `usb.bus_id`, `usb.device_address` oraz, jeśli to możliwe, `usb.interface_number`, zanim cokolwiek wyeksportujesz.

### Workflow w Wiresharku

1. **Odizoluj urządzenie**: filtruj ruch interrupt IN z klawiatury, np. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodaj przydatne kolumny**: kliknij prawym przyciskiem pole `Leftover Capture Data` (`usb.capdata`) oraz wybrane pola `usbhid.*` (np. `usbhid.boot_report.keyboard.keycode_1`), aby śledzić naciśnięcia klawiszy bez otwierania każdej ramki.
3. **Ukryj puste raporty**: zastosuj `!(usb.capdata == 00:00:00:00:00:00:00:00)`, aby pominąć ramki bezczynności.
4. **Wyeksportuj dane do dalszego przetwarzania**: `File -> Export Packet Dissections -> As CSV`, uwzględniając `frame.number`, `usb.src`, `usb.capdata` i `usbhid.modifiers`, aby później odtworzyć dane za pomocą skryptu.

### Workflow w wierszu poleceń

`ctf-usb-keyboard-parser` automatyzuje już klasyczny pipeline tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
W nowszych przechwyceniach możesz zachować zarówno `usb.capdata`, jak i bogatsze pole `usbhid.data`, grupując dane według urządzenia:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Te pliki dla poszczególnych urządzeń można bezpośrednio przekazać do dowolnego dekodera. Jeśli przechwycenie pochodziło z klawiatur BLE tunelowanych przez GATT, filtruj za pomocą `btatt.value && frame.len == 20` i zrzuć payloady w formacie hex przed dekodowaniem.

### Gdy raport nie jest klasycznym 8-bajtowym raportem boot

Nowsze klawiatury gamingowe, klawiatury dzielone i złożone urządzenia HID często udostępniają nie-bootowy interfejs klawiatury, w którym payload nie odpowiada już układowi `modifier,reserved,key1..key6`.

- Preferuj `usbhid.data` zamiast `usb.capdata`, gdy Wireshark przeanalizował już warstwę HID.
- Jeśli każda linia zaczyna się od stałego prefiksu lub identyfikatora raportu, usuń go za pomocą dekodera uwzględniającego offset, zamiast zakładać, że bajt 0 zawsze zawiera modyfikator.
- Niektóre eksporty USBPcap pomijają zarezerwowany bajt, więc dekodery obsługujące `--no-reserved` lub własny offset pozwalają oszczędzić czas.
- Jeśli w przechwyceniu znajduje się deskryptor raportu HID lub mapa raportu BLE HOGP, użyj jej do odtworzenia rzeczywistego układu pól przed napisaniem parsera.

## Automatyzacja dekodowania

- **ctf-usb-keyboard-parser** nadal jest przydatny w szybkich wyzwaniach CTF i jest już dołączony do repository.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) natywnie parsuje pliki `pcap` i `pcapng`, obsługuje `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i nie wymaga tshark, dzięki czemu dobrze działa w izolowanych sandboxach.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** dodaje wizualizatory klawiatur, myszy i tabletów. Możesz uruchomić helpera `extract_hid_data.sh` (backend tshark) lub `extract_hid_data.py` (backend scapy), a następnie przekazać wynikowy plik tekstowy do dekodera lub modułów replay, aby obserwować kolejne naciśnięcia klawiszy.<sup>[[5]](#references)</sup>

### Dekodowanie stanowe ma znaczenie

Przechwycenia przerwań USB zwykle zawierają zarówno naciśnięcie klawisza, jak i jedną lub więcej powtórzonych kopii tego samego raportu, zanim nadejdzie zdarzenie zwolnienia klawisza. Praktyczny dekoder powinien:<sup>[[2]](#references)</sup>

- emitować tylko nowo naciśnięte kody klawiszy w porównaniu z poprzednim raportem
- zachowywać stan modyfikatorów (`Shift`, `Ctrl`, `AltGr`) z bajtu 0 lub z sparsowanego pola `usbhid.boot_report.keyboard.modifier`
- śledzić klawisze przełączające, takie jak `Caps Lock`, ponieważ wielkość liter nie zależy wyłącznie od klawisza Shift
- pamiętać, że identyfikatory użycia HID są niezależne od układu: `0x1d` oznacza fizyczną pozycję klawisza `z`/`y` zależnie od układu klawiatury hosta

## Szybki dekoder w Pythonie
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
Podaj mu zwykłe wiersze hex zrzucane wcześniej, aby natychmiast uzyskać przybliżoną rekonstrukcję bez dodawania do środowiska pełnego parsera. W przypadku układów innych niż US nadal rekonstruowana jest fizyczna pozycja klawisza, a niekoniecznie końcowy znak wyświetlany na hoście ofiary.

## Wskazówki dotyczące rozwiązywania problemów

- Jeśli Wireshark nie wypełnia pól `usbhid.*`, prawdopodobnie nie przechwycono deskryptora raportu HID. Odłącz i ponownie podłącz klawiaturę podczas przechwytywania albo użyj surowego `usb.capdata`.
- W przypadku przechwytywania programowego w systemie Linux standardowym źródłem jest `usbmon`; w systemie Windows Wireshark wymaga extcap **USBPcap**, aby w ogóle widzieć surowe URB USB.<sup>[[1]](#references)</sup>
- Jeśli klawiatura była podłączona przez hub lub stację dokującą, najpierw potwierdź deskryptor interfejsu, a następnie dekoduj tylko tę parę urządzenie/interfejs. Przechwycenia Composite HID często mieszają raporty klawiatury i myszy.
- Przechwycenia w systemie Windows wymagają interfejsu extcap **USBPcap**; upewnij się, że przetrwał aktualizacje Wireshark, ponieważ brak extcap skutkuje pustymi listami urządzeń.<sup>[[1]](#references)</sup>
- Zawsze skoreluj `usb.bus_id:device:interface` (np. `1.9.1`) przed rozpoczęciem dekodowania — mieszanie wielu klawiatur lub urządzeń pamięci masowej prowadzi do bezsensownych naciśnięć klawiszy.

## Odnośniki

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
