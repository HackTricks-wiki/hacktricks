# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz pcap zawierający komunikację przez USB klawiatury takiej jak poniżej:

![](<../../../images/image (962).png>)

Klawiatury USB zwykle używają protokołu HID **boot protocol**, więc każdy transfer przerwania do hosta ma tylko 8 bajtów: jeden bajt bitów modyfikatorów (Ctrl/Shift/Alt/Super), jeden bajt zarezerwowany oraz do sześciu keycode’ów na raport. Odczytanie tych bajtów wystarcza, aby odtworzyć wszystko, co zostało wpisane.

## USB HID report basics

Typowy raport IN wygląda tak:

| Byte | Meaning |
| --- | --- |
| 0 | Mapa bitowa modyfikatorów (`0x02` = Left Shift, `0x20` = Right Alt, itd.). Można jednocześnie ustawić wiele bitów. |
| 1 | Zarezerwowany/wypełnienie, ale często wykorzystywany ponownie przez gaming keyboards na dane producenta. |
| 2-7 | Do sześciu jednoczesnych keycode’ów w formacie USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` oznacza "no key". |

Klawiatury bez NKRO zwykle wysyłają `0x01` w bajcie 2, gdy wciśnięto więcej niż sześć klawiszy, aby zasygnalizować "rollover". Zrozumienie tego układu pomaga, gdy masz tylko surowe bajty `usb.capdata`.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

W przechwyceniach z dużym ruchem najpierw zidentyfikuj HID keyboard, zanim zaczniesz zrzucać jakiekolwiek raporty. Pewnym punktem startowym jest odpowiedź deskryptora interfejsu:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Spójrz na `usb.bInterfaceSubClass` i `usb.bInterfaceProtocol`:

- `subclass == 1` i `protocol == 1` zwykle oznacza boot keyboard
- `protocol == 2` zazwyczaj oznacza mouse
- `protocol == 0` często oznacza vendor-defined lub interfejs HID w stylu NKRO, który nadal przenosi dane keyboard, ale nie w prostym 8-bajtowym układzie boot

Gdy interfejs jest już znany, zawęź filtry do `usb.bus_id`, `usb.device_address` i, jeśli to możliwe, `usb.interface_number` przed czymkolwiek eksportujesz.

### Wireshark workflow

1. **Izoluj urządzenie**: filtruj ruch interrupt IN z keyboard, np. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodaj przydatne kolumny**: kliknij prawym przyciskiem na pole `Leftover Capture Data` (`usb.capdata`) oraz na wybrane pola `usbhid.*` (np. `usbhid.boot_report.keyboard.keycode_1`), aby śledzić keystrokes bez otwierania każdej ramki.
3. **Ukryj puste raporty**: zastosuj `!(usb.capdata == 00:00:00:00:00:00:00:00)`, aby odfiltrować bezczynne ramki.
4. **Eksport do dalszego przetwarzania**: `File -> Export Packet Dissections -> As CSV`, dołącz `frame.number`, `usb.src`, `usb.capdata` i `usbhid.modifiers`, aby później zautomatyzować rekonstrukcję.

### Command-line workflow

`ctf-usb-keyboard-parser` już automatyzuje klasyczny pipeline tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
W nowszych przechwyceniach możesz zachować zarówno `usb.capdata`, jak i bogatsze pole `usbhid.data`, grupując dane per urządzenie:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Te pliki per-device trafiają bezpośrednio do dowolnego dekodera. Jeśli przechwycenie pochodziło z klawiatur BLE tunelowanych przez GATT, filtruj `btatt.value && frame.len == 20` i zrzucaj hex payloads przed dekodowaniem.

### Gdy raport nie jest klasycznym 8-bajtowym boot report

Nowsze klawiatury gamingowe, klawiatury split oraz złożone urządzenia HID często ujawniają interfejs klawiatury inny niż boot, gdzie payload nie pasuje już do `modifier,reserved,key1..key6`.

- Preferuj `usbhid.data` zamiast `usb.capdata`, gdy Wireshark już sparsował warstwę HID.
- Jeśli każda linia zaczyna się od stałego prefixu lub report ID, usuń go dekoderem uwzględniającym offset zamiast zakładać, że bajt 0 zawsze jest modifier.
- Niektóre eksporty USBPcap pomijają bajt reserved, więc dekodery wspierające `--no-reserved` albo niestandardowy offset oszczędzają czas.
- Jeśli w przechwyceniu obecny jest HID report descriptor albo BLE HOGP report map, użyj go do odtworzenia rzeczywistego układu pól przed napisaniem parsera.

## Automatyzacja dekodowania

- **ctf-usb-keyboard-parser** nadal jest przydatny do szybkich wyzwań CTF i już jest dołączony do repozytorium.
- **CTF-Usb_Keyboard_Parser** (`main.py`) natywnie parsuje pliki `pcap` i `pcapng`, rozumie `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i nie wymaga tshark, więc dobrze działa w odizolowanych sandboxach.
- **USB-HID-decoders** dodaje wizualizatory klawiatury, myszy i tabletu. Możesz uruchomić helper `extract_hid_data.sh` (backend tshark) albo `extract_hid_data.py` (backend scapy), a następnie podać wynikowy plik tekstowy do dekodera lub modułów replay, aby obserwować, jak keystrokes się rozwijają.

### Stanowe dekodowanie ma znaczenie

Przechwycenia USB interrupt zwykle zawierają zarówno naciśnięcie klawisza, jak i jedną lub więcej powtórzonych kopii tego samego report przed nadejściem eventu zwolnienia. Praktyczny dekoder powinien:

- emitować tylko nowo naciśnięte keycodes w porównaniu z poprzednim report
- zachowywać stan modifierów (`Shift`, `Ctrl`, `AltGr`) z bajtu 0 albo z sparsowanego pola `usbhid.boot_report.keyboard.modifier`
- śledzić klawisze przełączające, takie jak `Caps Lock`, ponieważ wielkie litery nie są kontrolowane wyłącznie przez Shift
- pamiętać, że HID usage IDs są niezależne od layoutu: `0x1d` to fizyczna pozycja klawisza `z`/`y` zależnie od layoutu klawiatury hosta

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
Wprowadź do tego surowe linie hex zebrane wcześniej, aby uzyskać natychmiastową, przybliżoną rekonstrukcję bez wciągania pełnego parsera do środowiska. Dla układów spoza USA nadal odtwarza to fizyczne położenie klawisza, a niekoniecznie końcowy glyph wyświetlony na hoście ofiary.

## Troubleshooting tips

- Jeśli Wireshark nie wypełnia pól `usbhid.*`, to prawdopodobnie nie został przechwycony HID report descriptor. Podłącz ponownie klawiaturę podczas capture albo przejdź na surowe `usb.capdata`.
- W przechwytach software na Linuxie normalnym źródłem jest `usbmon`; na Windows Wireshark polega na extcap **USBPcap**, aby w ogóle widzieć surowe USB URBs.
- Jeśli klawiatura była podłączona przez hub lub dock, najpierw potwierdź interface descriptor, a potem dekoduj tylko tę parę device/interface. Złożone przechwyty HID często mieszają raporty klawiatury i myszy.
- Przechwyty na Windows wymagają interfejsu extcap **USBPcap**; upewnij się, że przetrwał aktualizacje Wiresharka, bo brakujące extcapy zostawiają puste listy urządzeń.
- Zawsze najpierw skoreluj `usb.bus_id:device:interface` (np. `1.9.1`) przed dekodowaniem czegokolwiek — mieszanie wielu klawiatur lub urządzeń storage prowadzi do bezsensownych keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
