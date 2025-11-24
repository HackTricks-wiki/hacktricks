# USB Tuş Vuruşları

{{#include ../../../banners/hacktricks-training.md}}

Aşağıdaki gibi bir klavyenin USB üzerinden iletişimini içeren bir pcap'iniz varsa:

![](<../../../images/image (962).png>)

USB klavyeler genellikle HID **boot protocol** kullanır, bu yüzden host'a yapılan her interrupt transferi yalnızca 8 byte uzunluğundadır: bir byte modifier bitleri (Ctrl/Shift/Alt/Super), bir ayrılmış byte ve her raporda en fazla altı keycode. Bu byte'ları decode etmek yazılan her şeyi yeniden oluşturmak için yeterlidir.

## USB HID rapor temelleri

Tipik IN raporu şu şekildedir:

| Byte | Anlam |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, vb.). Birden fazla bit aynı anda set edilebilir. |
| 1 | Ayrılmış/padding fakat genellikle gaming klavyeler tarafından vendor verisi için yeniden kullanılır. |
| 2-7 | USB usage ID formatında eşzamanlı en fazla altı keycode (`0x04 = a`, `0x1E = 1`). `0x00` "hiç tuş yok" anlamına gelir. |

NKRO olmayan klavyeler genellikle altıdan fazla tuşa basıldığında "rollover"u belirtmek için byte 2'de `0x01` gönderir. Bu düzeni anlamak, elinizde yalnızca ham `usb.capdata` byte'ları olduğunda yardımcı olur.

## PCAP'ten HID verisi çıkarma

### Wireshark iş akışı

1. **Cihazı izole et**: klavyeden gelen interrupt IN trafiğini filtreleyin, örn. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Faydalı sütunlar ekleyin**: `Leftover Capture Data` alanına (`usb.capdata`) ve tercih ettiğiniz `usbhid.*` alanlarına (örn. `usbhid.boot_report.keyboard.keycode_1`) sağ tıklayarak her frame'i açmadan tuş vuruşlarını takip edin.
3. **Boş raporları gizle**: idle frameleri düşürmek için `!(usb.capdata == 00:00:00:00:00:00:00:00)` uygulayın.
4. **Son işlem için dışa aktar**: `File -> Export Packet Dissections -> As CSV`, yeniden oluşturmayı script'lemek için `frame.number`, `usb.src`, `usb.capdata`, ve `usbhid.modifiers` dahil edin.

### Komut satırı iş akışı

`ctf-usb-keyboard-parser` klasik tshark + sed pipeline'ını zaten otomatikleştirir:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Daha yeni yakalamalarda, cihaz başına batchleme yaparak hem `usb.capdata` hem de daha zengin `usbhid.data` alanını koruyabilirsiniz:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Bu cihaz başına dosyalar herhangi bir decoder'a doğrudan yüklenebilir. Eğer yakalama GATT üzerinden tünellenmiş BLE klavyelerinden geldiyse, `btatt.value && frame.len == 20` ile filtreleyin ve decode etmeden önce hex payload'ları dökün.

## Decode işlemini otomatikleştirme

- **ctf-usb-keyboard-parser** hızlı CTF görevleri için kullanışlıdır ve zaten repository'de bulunur.
- **CTF-Usb_Keyboard_Parser** (`main.py`) hem `pcap` hem `pcapng` dosyalarını yerel olarak parse eder, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`'i anlar ve tshark gerektirmez; bu yüzden izole sandbox'lar içinde iyi çalışır.
- **USB-HID-decoders** klavye, fare ve tablet görselleştiricileri ekler. `extract_hid_data.sh` yardımcı programını (tshark backend) veya `extract_hid_data.py`'yi (scapy backend) çalıştırabilir ve ardından ortaya çıkan metin dosyasını decoder veya replay modüllerine vererek tuş vuruşlarının açılmasını izleyebilirsiniz.

## Hızlı Python decoder
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Daha önce dökülen düz hex satırlarıyla besleyin; ortama tam bir parser yüklemeden anlık kaba bir yeniden yapılandırma elde edersiniz.

## Sorun Giderme İpuçları

- Eğer Wireshark `usbhid.*` alanlarını doldurmuyorsa, muhtemelen HID report descriptor yakalanmamıştır. Yakalama sırasında klavyeyi yeniden takın veya ham `usb.capdata`'ya dönün.
- Windows yakalamaları **USBPcap** extcap arayüzünü gerektirir; Wireshark yükseltmelerinden sonra extcap'lerin sağlam kaldığından emin olun, çünkü eksik extcap'ler sizi boş cihaz listeleriyle bırakır.
- Herhangi bir şeyi dekode etmeden önce her zaman `usb.bus_id:device:interface` (ör. `1.9.1`) ile korelasyon kurun — birden fazla klavye veya depolama cihazını karıştırmak anlamsız tuş vuruşlarına yol açar.

## Kaynaklar

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
