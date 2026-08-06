# USB Tuş Vuruşları

{{#include ../../../banners/hacktricks-training.md}}

Aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap dosyanız varsa:

![USB Tuş Vuruşları: Aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap dosyanız varsa](<../../../images/image (962).png>)

USB klavyeler genellikle HID **boot protocol** kullanır; bu nedenle host'a yönelik her interrupt transfer yalnızca 8 byte uzunluğundadır: bir byte modifier bitleri (Ctrl/Shift/Alt/Super), bir reserved byte ve her report için en fazla altı keycode. Bu byte'ları decode etmek, yazılan her şeyi yeniden oluşturmak için yeterlidir.

## USB HID report temelleri

Tipik IN report şu şekildedir:

| Byte | Anlamı |
| --- | --- |
| 0 | Modifier bitmap'i (`0x02` = Left Shift, `0x20` = Right Alt vb.). Aynı anda birden fazla bit set edilebilir. |
| 1 | Reserved/padding; ancak gaming klavyeleri tarafından vendor data için sıklıkla yeniden kullanılır. |
| 2-7 | USB usage ID formatında en fazla altı eşzamanlı keycode (`0x04 = a`, `0x1E = 1`). `0x00`, "no key" anlamına gelir. |

NKRO özelliği olmayan klavyeler, altıdan fazla tuşa basıldığında "rollover" sinyali vermek için genellikle byte 2'de `0x01` gönderir. Bu yerleşimi anlamak, yalnızca ham `usb.capdata` byte'larına sahip olduğunuzda yardımcı olur.

## PCAP'ten HID data çıkarma

### Önce klavye interface'ini belirleyin

Yoğun capture'larda report'ları dump etmeden önce HID klavyesini belirleyin. Güvenilir bir başlangıç noktası interface descriptor response'dur:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` ve `usb.bInterfaceProtocol` alanlarına bakın:

- `subclass == 1` ve `protocol == 1` genellikle bir boot keyboard anlamına gelir
- `protocol == 2` genellikle bir mouse'tur
- `protocol == 0` çoğunlukla, hâlâ keyboard verisi taşıyan ancak basit 8-byte boot düzeninde olmayan, vendor-defined veya NKRO-style bir HID interface anlamına gelir

Interface belirlendikten sonra herhangi bir şeyi export etmeden önce filtrelerinizi `usb.bus_id`, `usb.device_address` ve mümkünse `usb.interface_number` üzerinde sabitleyin.

### Wireshark workflow

1. **Cihazı izole edin**: Keyboard'dan gelen interrupt IN trafiğini filtreleyin, örneğin `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Yararlı sütunlar ekleyin**: Her frame'i açmadan keystroke'ları takip etmek için `Leftover Capture Data` alanına (`usb.capdata`) ve tercih ettiğiniz `usbhid.*` alanlarına (ör. `usbhid.boot_report.keyboard.keycode_1`) sağ tıklayın.
3. **Boş report'ları gizleyin**: Idle frame'leri kaldırmak için `!(usb.capdata == 00:00:00:00:00:00:00:00)` uygulayın.
4. **Post-processing için export edin**: `File -> Export Packet Dissections -> As CSV` yolunu kullanın; daha sonra reconstruction işlemini script ile gerçekleştirmek için `frame.number`, `usb.src`, `usb.capdata` ve `usbhid.modifiers` alanlarını ekleyin.

### Command-line workflow

`ctf-usb-keyboard-parser`, klasik tshark + sed pipeline'ını zaten otomatikleştirir:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Daha yeni yakalamalarda, cihaz başına gruplama yaparak hem `usb.capdata` hem de daha zengin `usbhid.data` alanını koruyabilirsiniz:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Bu cihaz başına oluşturulan dosyalar doğrudan herhangi bir decoder'a aktarılabilir. Capture BLE klavyelerden GATT üzerinden tünellenerek geldiyse `btatt.value && frame.len == 20` filtresini uygulayın ve decode işlemi öncesinde hex payload'larını dışa aktarın.

### Rapor klasik 8-byte boot report olmadığında

Yeni gaming klavyeler, split klavyeler ve composite HID cihazları çoğu zaman payload'ı artık `modifier,reserved,key1..key6` biçimiyle eşleşmeyen bir non-boot keyboard interface sunar.

- Wireshark HID katmanını zaten parse ettiyse `usb.capdata` yerine `usbhid.data` kullanın.
- Her satır sabit bir prefix veya report ID ile başlıyorsa, byte 0'ın her zaman modifier olduğunu varsaymak yerine offset-aware bir decoder kullanarak bu kısmı çıkarın.
- Bazı USBPcap export'ları reserved byte'ını içermez; bu nedenle `--no-reserved` destekleyen decoder'lar veya özel bir offset kullanmak zaman kazandırır.
- Capture içinde HID report descriptor veya BLE HOGP report map mevcutsa parser yazmadan önce gerçek field layout'u kurtarmak için bunları kullanın.

## Decode işlemini otomatikleştirme

- **ctf-usb-keyboard-parser**, hızlı CTF challenge'ları için hâlâ kullanışlıdır ve repository içinde hazır olarak gelir.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`), hem `pcap` hem de `pcapng` dosyalarını native olarak parse eder, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` türlerini anlar ve tshark gerektirmez; bu nedenle izole sandbox'larda iyi çalışır.<sup>[[4]](#references)</sup>
- **USB-HID-decoders**, keyboard, mouse ve tablet visualizer'ları ekler. `extract_hid_data.sh` helper'ını (tshark backend'i) veya `extract_hid_data.py`'yi (scapy backend'i) çalıştırabilir, ardından ortaya çıkan text file'ı decoder'a ya da keystroke'ların açığa çıkışını izlemek için replay module'larına aktarabilirsiniz.<sup>[[5]](#references)</sup>

### Stateful decoding önemlidir

USB interrupt capture'ları genellikle key press ile release event'i arasındaki sürede aynı report'un key press ve bir veya daha fazla tekrarlanan kopyasını içerir. Pratik bir decoder şunları yapmalıdır:<sup>[[2]](#references)</sup>

- önceki report'a kıyasla yalnızca yeni basılan keycode'ları output olarak vermek
- byte 0'dan veya parse edilmiş `usbhid.boot_report.keyboard.modifier` field'ından modifier state'ini (`Shift`, `Ctrl`, `AltGr`) korumak
- `Caps Lock` gibi toggle key'lerini takip etmek; çünkü uppercase output yalnızca Shift tarafından kontrol edilmez
- HID usage ID'lerinin layout-agnostic olduğunu hatırlamak: `0x1d`, host keyboard layout'una bağlı olarak fiziksel `z`/`y` key position'ıdır

## Hızlı Python decoder
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
Daha önce dökülen düz hex satırlarını buna vererek, tam bir parser'ı ortama dahil etmeden anında yaklaşık bir yeniden oluşturma elde edebilirsiniz. ABD dışı klavye düzenlerinde bu işlem, kurban hostunda gösterilen nihai karakteri değil, fiziksel tuş konumunu yeniden oluşturur.

## Sorun giderme ipuçları

- Wireshark `usbhid.*` alanlarını doldurmuyorsa HID report descriptor muhtemelen yakalanmamıştır. Yakalama sırasında klavyeyi çıkarıp yeniden takın veya ham `usb.capdata` verisine geri dönün.
- Linux software capture'larında normal kaynak `usbmon`'dur; Windows'ta Wireshark'ın ham USB URB'lerini görebilmesi için **USBPcap** extcap'ine ihtiyaç vardır.<sup>[[1]](#references)</sup>
- Klavye bir hub veya dock üzerinden bağlandıysa önce interface descriptor'ını doğrulayın, ardından yalnızca ilgili device/interface çiftini decode edin. Composite HID capture'ları sıklıkla klavye ve mouse report'larını karıştırır.
- Windows capture'ları **USBPcap** extcap interface'i gerektirir; eksik extcap'ler boş device listeleri bıraktığından, Wireshark yükseltmelerinden sonra bunun korunduğundan emin olun.<sup>[[1]](#references)</sup>
- Herhangi bir decode işleminden önce daima `usb.bus_id:device:interface` değerini (ör. `1.9.1`) ilişkilendirin — birden fazla klavyeyi veya storage device'ını karıştırmak anlamsız keystroke'lara yol açar.

## Referanslar

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
