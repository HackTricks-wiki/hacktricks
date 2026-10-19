# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Daha güvenli pin arama ve donanım kurulumu

- Önce multimetreyle Vtref ve GND'yi belirleyin. Pek çok adaptör, I/O voltajını ayarlamak için Vtref'e ihtiyaç duyar.
- Seviye dönüştürme: push-pull sinyaller için tasarlanmış çift yönlü seviye dönüştürücüleri tercih edin (JTAG hatları open-drain değildir). JTAG için otomatik yön belirleyen I2C dönüştürücülerini kullanmayın.
- Kullanışlı adaptörler: FT2232H/FT232H kartları (ör. Tigard), CMSIS-DAP, J-Link, ST-LINK (üreticiye özgü), ESP-USB-JTAG (ESP32-Sx üzerinde). En azından TCK, TMS, TDI, TDO, GND ve Vtref'i bağlayın; isteğe bağlı olarak TRST ve SRST'yi de bağlayabilirsiniz.

Belgelenmemiş bir başlıkta, hedef cihaza **güç verilmemişken** bilinen bir toprak düzlemine süreklilik testi yaparak GND'yi belirleyin. Voltaj moduna geçip cihaza güç verdikten sonra, yüksek seviyedeki her pini Vtref olarak sınıflandırmayın: yüksek dijital girişler multimetrede benzer görünebilir. Aday hatları yakındaki dekuplaj kapasitörlerine kadar izleyin ve osiloskopta güç açma/kapama dalga biçimlerini karşılaştırın. Daha yavaş, kapasitör biçimli bir yükselme veya düşme, bunun bir besleme/referans hattı olduğuna işaret eder; ancak seviye dönüştürücülü bir prob bağlamadan önce voltajı ve kablolamayı doğrulayın. PiFex'te varsayılan 3.3 V ayarı yerine `VCCA_IN` üzerinden harici, daha düşük voltajlı bir hedef referansı seçilebilir.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum**, bilinmeyen JTAG pin dizilimlerini kaba kuvvetle bulmak ve komut yazmaçlarını numaralandırmak için Arduino uyumlu bir MCU'ya veya deneysel olarak Raspberry Pi'ye yükleyebileceğiniz bir araçtır.<sup>[[3]](#references)</sup>

- Arduino: D2–D11 dijital pinlerini, şüpheli en fazla 10 JTAG pad/test noktasına; Arduino GND'yi ise hedef GND'ye bağlayın. Besleme hattının güvenli olduğundan emin değilseniz hedefe ayrı bir kaynaktan güç verin. 3.3 V lojik (ör. Arduino Due) kullanın veya 1.8–3.3 V hedefleri incelerken seviye dönüştürücü/seri direnç kullanın.
- Raspberry Pi: Pi sürümü daha az kullanılabilir GPIO pini sunar (bu nedenle taramalar daha yavaştır); güncel pin eşlemesini ve kısıtlamaları depoda kontrol edin.

Yazılım yüklendikten sonra seri monitörü 115200 baud'da açıp yardım için `h` gönderin. Tipik akış:

- `l` yanlış pozitifleri önlemek için loopback bağlantılarını bulur
- `r` gerekirse dahili pull-up'ları açıp kapatır
- `s` TCK/TMS/TDI/TDO'yu (ve bazen TRST/SRST'yi) tarar
- `y` belgelenmemiş opcode'ları keşfetmek için IR'yi kaba kuvvetle tarar
- `x` pin durumlarının boundary-scan anlık görüntüsünü alır

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri belirten `FOUND!` ile başlayan satırlar görürsünüz.

### JTAGenum güvenlik ipuçları

- Her zaman ortak toprak bağlantısı kurun ve bilinmeyen pinlere hedef Vtref'in üzerinde voltaj uygulamayın. Emin değilseniz aday pinlere 100–470 Ω seri direnç ekleyin.
- Cihaz 4 telli JTAG yerine SWD/SWJ kullanıyorsa JTAGenum bunu algılamayabilir; SWD araçlarını veya SWJ-DP destekleyen bir adaptörü deneyin.

## go-jtagenum ile GPIO pini keşfi

Doğrulanmış ortak toprak bağlantısı ve uyumlu I/O voltajı olan, güç verilmiş bir hedefte `go-jtagenum`, Raspberry Pi GPIO'larından olası JTAG sinyallerini numaralandırabilir. `-pins` JSON'u, etiketleri fiziksel başlık konumlarına değil **GPIO numaralarına** eşler.<sup>[[5]](#references)</sup> SSD örneğinde, ilk IDCODE taramasında değişen değerlerden oluşan makul görünmeyecek kadar uzun bir zincir de raporlanmıştı: yalnızca aday TDO hattındaki değişiklik, geçerli bir TAP bulunduğunu kanıtlamaz. Makul görünen bir sonucu, TDI'dan bir bitlik bypass yazmacı üzerinden TDO'ya bilinen bir bit desenini kaydıran BYPASS taramasıyla yeniden doğrulayın.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Bu kart için BYPASS, `TCK=10`, `TMS=14`, `TDI=9` ve `TDO=15` değerlerini doğruladı; ek pinler yalnızca olası nTRST adaylarıydı. Bir aday tüm sıfırları veya tutarsız bir deseni döndürürse, ona bir sinyal atamadan önce teması, hedefin gücünü, pull-up’ları ve saat/reset gecikmelerini kontrol edin.<sup>[[4]](#references)[[5]](#references)</sup> Araç, kurtarılan eşlemeyi yeniden test etmek için `test_bypass` ile `-known-pins` seçeneğini de kabul eder.<sup>[[5]](#references)</sup>

## UrJTAG ile belgelenmemiş bir TAP’i tanımlama

Pinout’u keşfetmek, hata ayıklama için gereken instruction-register (IR) opcode’larını veya data-register (DR) genişliklerini belirlemez. Raspberry Pi GPIO kablosunu destekleyen bir UrJTAG derlemesinde, kurtarılan eşlemeyi ayarlayın ve ardından `idcode`, `detect` ve `discover` komutlarını çalıştırın. SSD örneği bir TAP, dört bitlik bir IR ve farklı IR değerleri için farklı DR genişlikleri döndürdü. `-1` DR uzunluğu veya “TDO stuck at 0” sonucu kullanılabilir bir register tanımı değildir; ona bir genişlik atamak yerine zamanlamayı, kablolamayı ve seçilen instruction’ı inceleyin.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Bu, TAP keşfidir; otomatik CPU tanımlama değildir: Elde edilen IDCODE'u cihaz belgeleri ve desteklenen OpenOCD hedefleriyle karşılaştırın. UrJTAG'ın yerel üretici veritabanı, geçerli bir ID'yi bilinmiyor olarak etiketleyebilir.<sup>[[4]](#references)</sup>

## OpenOCD ile ilk temas (tarama ve IDCODE)

OpenOCD, JTAG/SWD için fiilî OSS'dir. Desteklenen bir adaptörle zinciri tarayabilir ve IDCODE'ları okuyabilirsiniz:<sup>[[1]](#references)</sup>

- J-Link ile genel örnek:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 yerleşik USB‑JTAG (harici prob gerektirmez):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notlar

- "all ones/zeros" IDCODE alırsanız kabloları, gücü, Vtref'i ve portun fuse/option byte'larla kilitlenip kilitlenmediğini kontrol edin.
- Bilinmeyen zincirleri ilk kez çalıştırırken TAP ile manuel etkileşim için OpenOCD'nin düşük seviyeli `irscan`/`drscan` komutlarına bakın.<sup>[[1]](#references)</sup>

## Belgelenmemiş bir hedefi OpenOCD'ye ekleme

TAP ID ve IR uzunluğu bilindikten sonra, **eşleşen bir CPU mimarisi** bulmak için OpenOCD'nin `cpu/`, `target/` ve `board/` betiklerini inceleyin; ardından adapter ve target yapılandırmalarını ayrı ayrı oluşturun.<sup>[[4]](#references)[[6]](#references)</sup> Aşağıdaki Pi GPIO eşlemesi ve ARCv2 target'ı, test edilmiş SSD örneğidir; evrensel bir JTAG yapılandırması değildir. ARC target seçimi ve debug ayarları bu cihazda başarılı olan varsayımlardı; başka bir kartta hedefin ölçülen ID'sini, IR uzunluğunu, mimarisini ve GPIO numaralarını kullanın.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

`openocd -f raspberrypi-io.cfg -f target.cfg` komutunu çalıştırın ve belleği okumadan önce TAP incelemesinin başarılı olduğunu doğrulayın. Örnekte 4444 portunda Telnet, 3333 portunda ise GDB server açıldı; tanınan bir IDCODE tek başına seçilen CPU target'ın incelenebileceğini veya debug edilebileceğini kanıtlamaz.<sup>[[4]](#references)</sup> Adapter `adapter gpio` yeniden eşlemesine izin veriyorsa Raspberry Pi GPIO'larının breakout board üzerinde JTAG olarak etiketlenen pinlere bağlanması gerekmez.<sup>[[4]](#references)[[6]](#references)</sup>

## CPU'yu durdurma ve bellek/flash dökümü alma

TAP tanındıktan ve bir target script seçildikten sonra core'u durdurup bellek bölgelerini veya dahili flash'ı dökebilirsiniz. Örnekler (target, temel adresleri ve boyutları ayarlayın):<sup>[[1]](#references)</sup>

- Init sonrasında genel target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (mümkün olduğunda SBA'yı tercih edin):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD yardımcı aracı üzerinden programlayın veya okuyun:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Bellek Dökümü İpuçları

- Uzun dökümler almadan önce belleği hızlıca kontrol etmek için `mdw/mdh/mdb` kullanın.
- Birden fazla cihaz içeren zincirlerde hedef olmayan cihazlarda BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir board file kullanın.

Belgelenmemiş bir bellek haritası için SSD araştırmasında, tanınabilir denetleyici dizgelerini bulmak amacıyla 1 MiB'lık bir döküm incelendi; ardından `$pc`, disassembly ve register'ları incelemek için OpenOCD üzerinden mimariyi destekleyen bir GDB kullanıldı. Bu canlı adresler, ikinci bir bölge dökümüne yön verdi; döküm, ARC destekli bir Ghidra derlemesindeki eşleşen talimatlarla karşılaştırıldı. Dizgeler tek başına yalnızca makul bir eşleşme göstergesidir; imajın eksiksiz olduğunu veya doğru şekilde eşlendiğini kanıtlamaz.<sup>[[4]](#references)</sup> Daha kapsamlı statik analiz adımları için [firmware analysis](../firmware-analysis/) bölümüne bakın.

## Boundary-scan püf noktaları (EXTEST/SAMPLE)

CPU debug erişimi kilitli olsa bile boundary-scan erişimi açık olabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:<sup>[[1]](#references)</sup>
- Sistem çalışırken pin durumlarının anlık görüntüsünü almak için SAMPLE kullanın (bus etkinliğini bulun, pin eşlemesini doğrulayın).
- Pin'leri sürmek için EXTEST kullanın (ör. kart bağlantıları elveriyorsa, MCU üzerinden harici SPI flash hatlarına bit-bang uygulayarak flash'ı çevrimdışı okuyun).

FT2232x adaptörle temel UrJTAG akışı:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Cihazın boundary register bit sıralamasını bilmek için BSDL gerekir. Bazı üreticilerin üretim aşamasında boundary-scan hücrelerini kilitlediğini unutmayın.

## Modern hedefler ve notlar

- ESP32‑S3/C3 yerel bir USB‑JTAG köprüsü içerir; OpenOCD harici bir probe olmadan doğrudan USB üzerinden iletişim kurabilir. Triage ve dump işlemleri için çok kullanışlıdır.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) OpenOCD tarafından yaygın biçimde desteklenir; core güvenli biçimde durdurulamıyorsa bellek erişimi için SBA’yı tercih edin.
- Birçok MCU, debug authentication ve yaşam döngüsü durumları kullanır. Güç doğru olduğu hâlde JTAG çalışmıyor gibi görünüyorsa cihaz kapalı duruma geçecek şekilde fuse’lanmış olabilir veya kimliği doğrulanmış bir probe gerektiriyor olabilir.

## Savunmalar ve güçlendirme (gerçek cihazlarda karşılaşılabilecekler)

- Üretim aşamasında JTAG/SWD’yi kalıcı olarak devre dışı bırakın veya kilitleyin (örn. STM32 RDP level 2, PAD JTAG’i devre dışı bırakan ESP eFuse’ları, NXP/Nordic APPROTECT/DPAP).
- Üretim erişimini korurken kimliği doğrulanmış debug gerektirin (ARMv8.2‑A ADIv6 Debug Authentication, OEM tarafından yönetilen challenge-response).
- Kolay erişilebilir test pad’leri kullanmayın; test via’larını gizleyin, TAP’i yalıtmak için dirençleri çıkarın/takın, anahtarlamalı konektörler veya pogo-pin fikstürleri kullanın.
- Güç açılışında debug kilidi: TAP’i güvenli boot’u uygulayan erken ROM’un arkasına alın.

## References

- [1] [OpenOCD Kullanıcı Kılavuzu – JTAG Komutları ve yapılandırma](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debug (USB‑JTAG, OpenOCD kullanımı)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino tabanlı JTAG pinout tarayıcısı](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Raspberry Pi ile JTAG hacking](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG enumerasyonu](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD Kullanıcı Kılavuzu — Debug Adapter yapılandırması](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
