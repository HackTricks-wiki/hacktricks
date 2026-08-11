# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap dosyanız varsa:

![USB Keystrokes: Aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap dosyanız varsa](<../../../images/image (962).png>)

**boot protocol** kullanan bir klavye için her Interrupt IN report sabit 8 baytlık bir yapıya sahiptir: bir modifier baytı, bir ayrılmış bayt ve altı keycode baytı. Host, ardışık report'ları karşılaştırır ve key event'larını yeniden oluşturmak için keycode'ları HID usage'larına eşler.<sup>[[8]](#references)</sup>

## USB HID report temelleri

Standart boot keyboard input report aşağıdaki şekilde yapılandırılır.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Anlamı |
| --- | --- |
| 0 | Modifier bitmap'i (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt vb.). Aynı anda birden fazla bit ayarlanabilir. |
| 1 | Ayrılmış bayt; kullanılmayan report'lar normalde bunu sıfıra ayarlamalıdır. OEM veya sisteme özel kullanım taşınabilir değildir. |
| 2-7 | USB usage ID formatında en fazla altı eşzamanlı keycode (`0x04 = a`, `0x1E = 1`). `0x00`, "no key" anlamına gelir. |

Boot düzeninde, altıdan fazla modifier olmayan tuşa basıldığında tüm key slot'larında usage ID `0x01` (`Keyboard ErrorRollOver`) raporlanır; bu değer tanınamayan bir kombinasyonu da gösterebilir.<sup>[[8]](#references)[[9]](#references)</sup> Bu düzeni anlamak, yalnızca ham `usb.capdata` baytlarına sahip olduğunuzda yardımcı olur.

## PCAP'ten HID verilerini çıkarma

### Önce klavye interface'ini belirleyin

Yoğun capture'larda herhangi bir report dökümü almadan önce HID klavyesini belirleyin. Güvenilir bir başlangıç noktası interface descriptor yanıtıdır:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class, bu interface değerlerini tanımlar:<sup>[[8]](#references)</sup>

- `subclass == 1`, Boot Interface Subclass'tır; `protocol == 1` ile birlikte bir boot keyboard tanımlar
- `protocol == 2`, bir boot mouse tanımlar
- `protocol == 0`, boot protocol olmadığını belirtir; 8 baytlık bir düzen varsaymak yerine HID report descriptor'ı inceleyin

Interface belirlendikten sonra herhangi bir şeyi dışa aktarmadan önce filtrelerinizi `usb.bus_id`, `usb.device_address` ve mümkünse `usb.bInterfaceNumber` değerlerine sabitleyin.

### Wireshark iş akışı

1. **Cihazı izole edin**: klavyeden gelen interrupt IN trafiğine filtre uygulayın; örneğin `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Kullanışlı sütunlar ekleyin**: her frame'i açmadan keystroke'ları takip etmek için `Leftover Capture Data` alanına (`usb.capdata`) ve tercih ettiğiniz `usbhid.*` alanlarına (örneğin `usbhid.boot_report.keyboard.keycode_1`) sağ tıklayın.<sup>[[11]](#references)</sup>
3. **Boş report'ları gizleyin**: idle frame'leri kaldırmak için `!(usb.capdata == 00:00:00:00:00:00:00:00)` uygulayın.
4. **Post-processing için dışa aktarın**: daha sonra reconstruction işlemini script ile gerçekleştirmek üzere `File -> Export Packet Dissections -> As CSV` seçeneğini kullanın; `frame.number`, `usb.src`, `usb.capdata` ve `usbhid.boot_report.keyboard.modifier.left_shift` ile `usbhid.boot_report.keyboard.modifier.right_alt` gibi decode edilmiş modifier alanlarını dahil edin.<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line iş akışı

`usb.capdata` değerini dump etme, idle report'ları kaldırma ve usage ID'lerini eşleme şeklindeki klasik extraction pattern, orijinal 2017 analizinde ve walkthrough'unda yer alır.<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository'si klasik tshark + sed pipeline'ını otomatikleştirir:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Daha yeni capture’larda Wireshark’ın çözümlenmiş `usbhid.data` alanını tercih edin ve `usb.capdata` alanını yedek olarak kullanın; her report için payload’ı cihaz başına bir dosyaya yazın:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Bu cihaz başına oluşturulan dosyalar, beklediği hex formatı normalize edildikten sonra bir decoder'a aktarılabilir. Capture, GATT üzerinden tünellenen BLE klavyelerden geldiyse, `btatt.value && frame.len == 20` filtresini uygulayın ve decoding işleminden önce hex payload'larını dışa aktarın.<sup>[[7]](#references)</sup>

### Rapor klasik 8 baytlık boot raporu olmadığında

Boot olmayan bir interface veya report ID, payload düzenini değiştirebilir; bu nedenle her klavye raporunun `modifier,reserved,key1..key6` biçiminde olduğunu varsaymayın.<sup>[[8]](#references)[[11]](#references)</sup>

- Wireshark HID katmanını zaten parse etmişse `usb.capdata` yerine `usbhid.data` kullanın.
- Her satır sabit bir prefix veya report ID ile başlıyorsa, byte 0'ın her zaman modifier olduğunu varsaymak yerine offset-aware bir decoder ile bu kısmı kaldırın.<sup>[[7]](#references)</sup>
- Bazı USBPcap export'ları reserved byte'ı atlar; bu nedenle `--no-reserved` veya özel bir offset destekleyen decoder'lar zaman kazandırır.<sup>[[7]](#references)</sup>
- HID report descriptor veya BLE HOGP report map capture içinde mevcutsa, bir parser yazmadan önce gerçek field düzenini belirlemek için bunları kullanın.

## Decoding işlemini otomatikleştirme

- **ctf-usb-keyboard-parser**, hızlı CTF challenge'ları için hâlâ kullanışlıdır ve repository içinde zaten bulunur.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`), `pcap` ve `pcapng` dosyalarını native olarak parse eder, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` destekler ve tshark ya da başka bir external dependency gerektirmez; bu nedenle izole sandbox'lar için uygundur.<sup>[[6]](#references)</sup>
- **USB-HID-decoders**, klavye, mouse ve tablet visualizer'ları ekler. `extract_hid_data.sh` yardımcı script'ini (tshark backend'i) veya `extract_hid_data.py` script'ini (scapy backend'i) çalıştırabilir, ardından oluşan text dosyasını decoder'a ya da replay module'lerine aktararak keystroke'ların nasıl ortaya çıktığını izleyebilirsiniz.<sup>[[7]](#references)</sup>

### Stateful decoding önemlidir

USB boot klavyeleri, yeni bir key event olmadığında bile idle rate'te rapor gönderir; bu nedenle capture'larda release event'inden önce tekrarlanan raporlar bulunabilir. Pratik bir decoder şunları yapmalıdır:<sup>[[3]](#references)[[8]](#references)</sup>

- önceki rapora kıyasla yalnızca yeni basılan keycode'ları emit etmek
- byte 0'dan veya `usbhid.boot_report.keyboard.modifier.left_shift` ve `usbhid.boot_report.keyboard.modifier.right_alt` gibi parse edilmiş field'lar üzerinden modifier state'i (`Shift`, `Ctrl`, `AltGr`) korumak
- `Caps Lock` gibi toggle key'lerini takip etmek; çünkü büyük harf çıktısı yalnızca Shift tarafından kontrol edilmez
- HID usage ID'lerinin layout-agnostic olduğunu unutmamak: `0x1d`, host klavye layout'una bağlı olarak fiziksel `z`/`y` tuş konumudur.<sup>[[9]](#references)</sup>

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
Daha önce dökülen düz hex satırlarını buna besleyerek, ortama tam bir parser çekmeden anında kabaca yeniden oluşturabilirsiniz. ABD dışı klavyelerde bu işlem, kurban hostunda gösterilen son glyph'i değil, fiziksel tuş konumunu yeniden oluşturur.

## Sorun giderme ipuçları

- Wireshark `usbhid.*` alanlarını doldurmuyorsa HID report descriptor muhtemelen yakalanmamıştır. Yakalama sırasında klavyeyi çıkarıp yeniden takın veya ham `usb.capdata` verisine geri dönün.
- Linux yazılım yakalamalarında normal kaynak `usbmon`'dur; Windows'ta Wireshark, ham USB URB'lerini görebilmek için **USBPcap** extcap'e bağlıdır.<sup>[[4]](#references)</sup>
- Klavye bir hub veya dock üzerinden bağlandıysa önce interface descriptor'ı doğrulayın, ardından yalnızca o device/interface çiftini decode edin. Composite HID yakalamaları sıklıkla klavye ve mouse report'larını karıştırır.
- Windows yakalamaları **USBPcap** extcap interface'ini gerektirir; eksik extcap'ler boş device listeleriyle sonuçlanacağından, Wireshark yükseltmelerinden sonra bunun kaldığından emin olun.<sup>[[4]](#references)</sup>
- Herhangi bir decode işleminden önce bus, device ve interface tuple'ını (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ör. `1.9.1`) mutlaka ilişkilendirin — birden fazla klavye veya storage device'ı karıştırmak anlamsız keystroke'lara yol açar.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Keyboard packet capture analysis](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Device Class Definition for Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
