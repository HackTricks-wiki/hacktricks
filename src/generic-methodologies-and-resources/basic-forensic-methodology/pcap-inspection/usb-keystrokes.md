# USB Tuş Vuruşları

{{#include ../../../banners/hacktricks-training.md}}

Aşağıdaki gibi, klavyenin USB üzerinden yaptığı iletişimi içeren bir pcap dosyanız varsa:

![USB Tuş Vuruşları: Aşağıdaki gibi, klavyenin USB üzerinden yaptığı iletişimi içeren bir pcap dosyanız varsa](<../../../images/image (962).png>)

HID **boot protocol** kullanan bir klavyede her Interrupt IN raporu sabit 8 baytlık bir düzene sahiptir: bir modifier baytı, bir ayrılmış bayt ve altı keycode baytı. Ana bilgisayar, tuş olaylarını yeniden oluşturmak için ardışık raporları karşılaştırır ve keycode değerlerini HID kullanım kimlikleriyle eşleştirir.<sup>[[8]](#references)</sup>

Genel yakalama incelemesi için [Pcap Inspection](./) sayfasına bakın.

## USB HID raporlarının temelleri

Standart boot keyboard giriş raporu şu şekilde yapılandırılmıştır.<sup>[[8]](#references)[[9]](#references)</sup>

| Bayt | Anlamı |
| --- | --- |
| 0 | Modifier bitmap'i (`0x02` = Sol Shift, `0x20` = Sağ Shift, `0x40` = Sağ Alt vb.). Aynı anda birden fazla bit ayarlanabilir. |
| 1 | Ayrılmış bayt; normalde kullanılmayan raporlarda sıfır olmalıdır. OEM veya sisteme özgü kullanım taşınabilir değildir. |
| 2-7 | USB kullanım kimliği biçiminde en fazla altı eşzamanlı keycode (`0x04 = a`, `0x1E = 1`). `0x00`, "tuş yok" anlamına gelir. | 

Boot düzeninde, altıdan fazla modifier olmayan tuşa basıldığında tüm tuş yuvalarında kullanım kimliği `0x01` (`Keyboard ErrorRollOver`) raporlanır; bu, tanınamayan bir kombinasyonu da gösterebilir.<sup>[[8]](#references)[[9]](#references)</sup> Yalnızca ham `usb.capdata` baytlarına sahip olduğunuzda bu düzeni anlamak işe yarar.

## PCAP dosyasından HID verilerini çıkarma

### Önce klavye arayüzünü belirleyin

Yoğun yakalamalarda herhangi bir raporu dökmeden önce HID klavyeyi belirleyin. İyi bir başlangıç noktası, arayüz tanımlayıcısı yanıtıdır:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID sınıfı şu arayüz değerlerini tanımlar:<sup>[[8]](#references)</sup>

- `subclass == 1`, Boot Interface Subclass değeridir; `protocol == 1` ile birlikte bir boot klavyesini tanımlar
- `protocol == 2`, bir boot faresini tanımlar
- `protocol == 0`, boot protocol olmadığını belirtir; 8 baytlık bir düzen varsaymak yerine HID report descriptor'ını inceleyin

Boot desteğine sahip bir arayüz, **boot protocol'ün etkin olduğunun kanıtı değildir**. HID cihazları report protocol ile başlatılır. Host, `SET_PROTOCOL` ile boot mode'u seçer (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1`, report protocol'ü seçer. Yakalama sırasında enumeration varsa, 8 baytlık bir boot decoder kullanmadan önce klavye arayüzüne (`wIndex`) yönelik isteği kontrol edin. İstek yakalamada yoksa, arayüz descriptor'ından mode çıkarsamak yerine gözlemlenen report düzenini doğrulayın.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Arayüzü öğrendikten sonra, herhangi bir şeyi dışa aktarmadan önce filtrelerinizi `usb.bus_id`, `usb.device_address` ve mümkünse `usb.bInterfaceNumber` ile sınırlandırın.

### Wireshark iş akışı

1. **Aygıtı yalıtın**: Klavyeden gelen interrupt IN trafiğini filtreleyin. Örneğin: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Yararlı sütunlar ekleyin**: Her çerçeveyi açmadan tuş vuruşlarını izlemek için `Leftover Capture Data` alanına (`usb.capdata) ve tercih ettiğiniz `usbhid.*` alanlarına (ör. `usbhid.boot_report.keyboard.keycode_1`) sağ tıklayın.<sup>[[11]](#references)</sup>
3. **Boş raporları gizleyin**: Boşta kalan çerçeveleri kaldırmak için `!(usb.capdata == 00:00:00:00:00:00:00:00)` uygulayın.
4. **Sonraki işlemler için dışa aktarın**: Yeniden oluşturma işlemini daha sonra betikle gerçekleştirmek için `frame.number`, `usb.src`, `usb.capdata` ve `usbhid.boot_report.keyboard.modifier.left_shift` ile `usbhid.boot_report.keyboard.modifier.right_alt` gibi çözümlenmiş modifier alanlarını dahil ederek `File -> Export Packet Dissections -> As CSV` seçeneğini kullanın.<sup>[[10]](#references)[[11]](#references)</sup>

### Komut satırı iş akışı

`usb.capdata` değerini dökme, boşta kalan raporları kaldırma ve usage ID'lerini eşleme şeklindeki klasik çıkarma yöntemi, 2017'deki özgün analizde ve adım adım anlatımında yer alır.<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` deposu, klasik tshark + sed işlem hattını otomatikleştirir:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Yeni yakalamalarda, Wireshark’ın çözümlenmiş `usbhid.data` alanını tercih edin ve bu alan yoksa `usb.capdata` alanına başvurun; her raporun payload’ını cihaz başına ayrı bir dosyaya yazın:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Bu cihaz başına oluşturulan dosyalar, beklediği hex biçimi normalize edildikten sonra bir decoder'a verilebilir. Yakalama, GATT üzerinden tünellenen BLE klavyelerinden geldiyse, `btatt.value && frame.len == 20` filtresini uygulayın ve decode etmeden önce hex payload'ları dökün.<sup>[[7]](#references)</sup>

### Rapor klasik 8 baytlık boot report olmadığında

Boot olmayan bir arayüz veya report ID, payload düzenini değiştirebilir. Bu nedenle her klavye raporunun `modifier,reserved,key1..key6` biçiminde olduğunu varsaymayın.<sup>[[8]](#references)[[11]](#references)</sup>

- Wireshark HID katmanını zaten ayrıştırdıysa `usb.capdata` yerine `usbhid.data` kullanın.
- Her satır sabit bir önekle veya report ID ile başlıyorsa, 0. baytın her zaman modifier olduğunu varsaymak yerine bunu offset'i dikkate alan bir decoder ile kaldırın.<sup>[[7]](#references)</sup>
- Bazı USBPcap dışa aktarımlarında reserved bayt bulunmaz; `--no-reserved` seçeneğini veya özel bir offset'i destekleyen decoder'lar zaman kazandırır.<sup>[[7]](#references)</sup>
- Yakalamada HID report descriptor veya BLE HOGP report map varsa, parser yazmadan önce gerçek alan düzenini belirlemek için bunları kullanın.

### Report-protocol key bitmap'ini decode etme

Giriş raporu altı boot key slot'u yerine bitmap olan bir klavyenin **HID report descriptor**'ını enumeration trafiğinde bulun. Bu filtre, Wireshark'ın Report Size öğesini decode ettiği çerçeveleri bulur; birini açıp descriptor'ın tamamını inceleyin. Descriptor yoksa klavyeyi takmadan önce yeni bir yakalama başlatın.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Her klavye Input raporu için `Report ID` (varsa), `Usage Page` (klavye tuşları için `0x07`), `Usage Minimum/Maximum`, `Report Size`, `Report Count` ve her `Input` öğesinin **Variable** mı yoksa **Array** mı olduğunu not edin. Tuş alanının bit ofsetini bulmak için önceki tüm Input alanlarını ve sabit dolgu bitlerini sayın; rapor alanlarının bayt hizalı olması gerekmez. Ardışık klavye usage değerlerine sahip tek bitlik bir Variable alanı, tuş durumu bitmap'idir: bu alanın 0. biti, tanımlanan ilk usage değerine; 1. biti ise sonrakine karşılık gelir. Array ise bit başına bir basılı tuş içermez; değerleri descriptor'daki usage aralığına göre çözümlenir. Bir Report ID tanımlanmışsa önce bu öneki taşıyan raporları seçin ve alan ofsetlerini hesaplarken bu baytı atlayın. Yalnızca yeni basışları belirlemek için basılı tutulan usage kümelerini aynı interface ve Report ID'ye ait ardışık raporlar arasında karşılaştırın.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Çözümlemeyi otomatikleştirme

- **ctf-usb-keyboard-parser**, hızlı CTF görevlerinde hâlâ kullanışlıdır ve depoda hazır olarak bulunur.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`), hem `pcap` hem de `pcapng` dosyalarını yerel olarak ayrıştırır, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` türlerini anlar ve tshark ya da başka bir harici bağımlılık gerektirmez; bu nedenle yalıtılmış sandbox ortamları için uygundur.<sup>[[6]](#references)</sup>
- **USB-HID-decoders**, klavye, fare ve tablet görselleştiricileri ekler. `extract_hid_data.sh` yardımcı programını (tshark backend'i) veya `extract_hid_data.py`'yi (scapy backend'i) çalıştırıp elde edilen metin dosyasını çözücüye ya da tuş vuruşlarının ortaya çıkışını izlemek için replay modüllerine aktarabilirsiniz.<sup>[[7]](#references)</sup>

### Durum bilgili çözümleme önemlidir

USB boot klavyeleri, yeni bir tuş olayı olmasa bile boşta kalma hızında rapor gönderir; bu nedenle yakalamalarda tuş bırakma olayından önce yinelenen raporlar bulunabilir. Uygulamada kullanışlı bir çözücü şunları yapmalıdır:<sup>[[3]](#references)[[8]](#references)</sup>

- Önceki rapora kıyasla yalnızca yeni basılan keycode'ları üretmek
- Bayt 0'daki veya `usbhid.boot_report.keyboard.modifier.left_shift` ve `usbhid.boot_report.keyboard.modifier.right_alt` gibi ayrıştırılmış alanlardaki modifier durumunu (`Shift`, `Ctrl`, `AltGr`) tutmak
- `Caps Lock` gibi toggle tuşlarını izlemek; çünkü büyük harf çıktısı yalnızca Shift tarafından kontrol edilmez
- HID usage ID'lerinin klavye düzeninden bağımsız olduğunu unutmamak: `0x1d`, ana bilgisayarın klavye düzenine bağlı olarak fiziksel `z`/`y` tuş konumunu belirtir.<sup>[[9]](#references)</sup>

## Hızlı Python çözücüsü

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

Önceden dökülen düz hex satırlarını buna vererek tam bir parser'ı ortama eklemeden hızlı ve kabaca bir yeniden oluşturma elde edin. ABD dışındaki klavye düzenlerinde bu, kurbanın sisteminde gösterilen son karakteri değil, fiziksel tuş konumunu yeniden oluşturur.

## Sorun giderme ipuçları

- Wireshark `usbhid.*` alanlarını doldurmuyorsa HID report descriptor büyük olasılıkla yakalanmamıştır. Yakalama sürerken klavyeyi çıkarıp yeniden takın veya ham `usb.capdata` verisine başvurun.
- Linux yazılım yakalamalarında normal kaynak `usbmon`'dur; Windows'ta Wireshark'ın ham USB URB'lerini görebilmesi için **USBPcap** extcap gerekir.<sup>[[4]](#references)</sup>
- Klavye bir hub veya dock üzerinden bağlandıysa önce interface descriptor'ı doğrulayın, ardından yalnızca ilgili cihaz/interface çiftini decode edin. Composite HID yakalamalarında klavye ve fare raporları sık sık karışır.
- Windows yakalamaları **USBPcap** extcap interface'ini gerektirir; Wireshark yükseltmelerinden sonra da çalıştığını doğrulayın. Eksik extcap'ler cihaz listesinin boş kalmasına neden olur.<sup>[[4]](#references)</sup>
- Herhangi bir şeyi decode etmeden önce bus, device ve interface üçlüsünü (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ör. `1.9.1`) mutlaka eşleştirin; birden fazla klavye veya depolama cihazını karıştırmak anlamsız tuş vuruşlarına yol açar.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Çözüm Yazısı: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Klavye Paket Yakalama Analizi](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 çözüm yazısı](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB Yakalama Kurulumu](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [İnsan Arayüzü Aygıtları (HID) için Aygıt Sınıfı Tanımı 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Kullanım Tabloları 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Görüntüleme Filtresi Başvurusu: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Görüntüleme Filtresi Başvurusu: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux çekirdeği: HID report descriptor'larına giriş](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboard çözüm yazısı](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
