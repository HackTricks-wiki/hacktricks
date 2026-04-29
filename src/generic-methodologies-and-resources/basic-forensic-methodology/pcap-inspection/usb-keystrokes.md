# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Eğer aşağıdakine benzer bir keyboard’ın USB üzerinden iletişimini içeren bir pcap’iniz varsa:

![](<../../../images/image (962).png>)

USB keyboards genellikle HID **boot protocol** kullanır, bu yüzden host’a giden her interrupt transfer yalnızca 8 bytes uzunluğundadır: bir byte modifier bitleri (Ctrl/Shift/Alt/Super), bir reserved byte ve her report başına en fazla altı keycode. Bu byte’ları decode etmek, yazılan her şeyi yeniden oluşturmak için yeterlidir.

## USB HID report basics

Tipik IN report şöyle görünür:

| Byte | Anlamı |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Birden fazla bit aynı anda set edilebilir. |
| 1 | Reserved/padding, ancak gaming keyboards tarafından vendor data için sıklıkla yeniden kullanılır. |
| 2-7 | USB usage ID formatında aynı anda en fazla altı keycode (`0x04 = a`, `0x1E = 1`). `0x00` "no key" anlamına gelir. |

NKRO olmayan keyboards, altıdan fazla key basıldığında rollover sinyali vermek için genellikle byte 2 içinde `0x01` gönderir. Bu düzeni anlamak, yalnızca ham `usb.capdata` bytes’larına sahip olduğunuzda yardımcı olur.

## PCAP'ten HID data çıkarma

### Önce keyboard interface'ini belirleyin

Yoğun captures içinde, herhangi bir report dump etmeden önce HID keyboard’u identify edin. Güvenilir bir başlangıç noktası interface descriptor response’dur:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` ve `usb.bInterfaceProtocol` değerlerine bakın:

- `subclass == 1` ve `protocol == 1` genellikle bir boot keyboard anlamına gelir
- `protocol == 2` tipik olarak bir mouse’tur
- `protocol == 0` çoğu zaman vendor-defined veya keyboard verisi taşıyan, ancak basit 8-byte boot düzeninde olmayan bir NKRO-style HID interface anlamına gelir

Interface belirlendikten sonra, herhangi bir şey export etmeden önce filtrelerinizi `usb.bus_id`, `usb.device_address` ve mümkünse `usb.interface_number` üzerine sabitleyin.

### Wireshark workflow

1. **Device’i izole edin**: keyboard’dan gelen interrupt IN traffic üzerinde filtre uygulayın, örn. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Faydalı columns ekleyin**: `Leftover Capture Data` alanına (`usb.capdata`) ve tercih ettiğiniz `usbhid.*` field’larına (örn. `usbhid.boot_report.keyboard.keycode_1`) sağ tıklayın; böylece her frame’i açmadan keystrokes takip edebilirsiniz.
3. **Boş reports’u gizleyin**: idle frame’leri kaldırmak için `!(usb.capdata == 00:00:00:00:00:00:00:00)` uygulayın.
4. **Post-processing için export edin**: `File -> Export Packet Dissections -> As CSV`, daha sonra reconstruction’ı script etmek için `frame.number`, `usb.src`, `usb.capdata` ve `usbhid.modifiers` dahil edin.

### Command-line workflow

`ctf-usb-keyboard-parser` zaten klasik tshark + sed pipeline’ını otomatikleştirir:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Daha yeni yakalamalarda cihaz başına gruplandırarak hem `usb.capdata` hem de daha zengin `usbhid.data` alanını koruyabilirsiniz:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Bu cihaz başına dosyalar doğrudan herhangi bir decoder içine alınabilir. Eğer capture, GATT üzerinden tünellenmiş BLE keyboard’lardan geldiyse, `btatt.value && frame.len == 20` ile filtreleyin ve decode etmeden önce hex payload’ları dökün.

### Rapor klasik 8-byte boot report olmadığında

Yeni gaming keyboard’lar, split keyboard’lar ve composite HID device’lar, payload artık `modifier,reserved,key1..key6` ile eşleşmeyen bir non-boot keyboard interface sıkça sunar.

- Wireshark zaten HID katmanını parse ettiğinde `usb.capdata` yerine `usbhid.data` tercih edin.
- Her satır sabit bir prefix veya report ID ile başlıyorsa, byte 0’ın her zaman modifier olduğunu varsaymak yerine offset-aware bir decoder ile bunu temizleyin.
- Bazı USBPcap export’ları reserved byte’ı atlar, bu yüzden `--no-reserved` destekleyen ya da custom offset kullanan decoder’lar zaman kazandırır.
- Capture içinde HID report descriptor veya BLE HOGP report map varsa, parser yazmadan önce gerçek field layout’u kurtarmak için bunları kullanın.

## Decoding’i otomatikleştirme

- **ctf-usb-keyboard-parser** hızlı CTF challenge’ları için hâlâ kullanışlıdır ve zaten repository içinde gelir.
- **CTF-Usb_Keyboard_Parser** (`main.py`) hem `pcap` hem de `pcapng` dosyalarını native olarak parse eder, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` anlar ve tshark gerektirmez; bu yüzden izole sandbox’larda da iyi çalışır.
- **USB-HID-decoders** keyboard, mouse ve tablet visualizer’ları ekler. Ya `extract_hid_data.sh` helper’ını (tshark backend) ya da `extract_hid_data.py` (scapy backend) çalıştırıp oluşan text file’ı decoder’a veya replay module’larına vererek keystroke’ların ortaya çıkışını izleyebilirsiniz.

### Stateful decoding önemlidir

USB interrupt capture’ları genellikle hem key press’i hem de release event gelmeden önce aynı report’un bir veya daha fazla tekrarını içerir. Pratik bir decoder şunları yapmalıdır:

- önceki report ile karşılaştırınca yalnızca yeni basılan keycode’ları üretmek
- modifier durumunu (`Shift`, `Ctrl`, `AltGr`) byte 0’dan veya parse edilmiş `usbhid.boot_report.keyboard.modifier` field’ından korumak
- `Caps Lock` gibi toggle key’leri izlemek, çünkü uppercase output yalnızca Shift ile kontrol edilmez
- HID usage ID’lerinin layout-agnostic olduğunu hatırlamak: `0x1d`, host keyboard layout’una bağlı olarak fiziksel `z`/`y` key konumudur

## Quick Python decoder
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
Daha önce dökülen düz hex satırlarını vererek, ortama tam bir parser eklemeden anında kaba bir yeniden yapılandırma elde edebilirsin. US dışı layout'larda bu hâlâ fiziksel tuş konumunu yeniden oluşturur, kurban host üzerinde görülen son glyph'i değil.

## Troubleshooting tips

- Eğer Wireshark `usbhid.*` alanlarını doldurmuyorsa, HID report descriptor büyük olasılıkla capture edilmemiştir. Capture alırken klavyeyi yeniden tak veya ham `usb.capdata`'ya geri dön.
- Linux software captures için normal kaynak `usbmon`'dur; Windows'ta Wireshark ham USB URB'leri görmek için tamamen **USBPcap** extcap'ine bağlıdır.
- Klavye bir hub veya dock üzerinden bağlıysa, önce interface descriptor'ı doğrula ve ardından sadece o device/interface çiftini decode et. Composite HID captures sık sık keyboard ve mouse raporlarını karıştırır.
- Windows captures, **USBPcap** extcap arayüzünü gerektirir; Wireshark upgrades sırasında ayakta kaldığından emin ol, çünkü eksik extcaps seni boş device listeleriyle bırakır.
- Bir şey decode etmeden önce her zaman `usb.bus_id:device:interface` (ör. `1.9.1`) ile correlate et — birden fazla keyboard veya storage device'ı karıştırmak saçma keystrokes'e yol açar.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
