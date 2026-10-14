# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum**, bilinmeyen JTAG pin dizilimlerini kaba kuvvetle bulmak ve talimat register’larını listelemek için Arduino uyumlu bir MCU’ya veya deneysel olarak Raspberry Pi’ye yükleyebileceğiniz bir araçtır.<sup>[[3]](#references)</sup>

- Arduino: Dijital pinler D2–D11’i şüpheli en fazla 10 JTAG pad/test noktasına, Arduino GND’yi ise hedef GND’ye bağlayın. Hattın güvenli olduğunu bilmiyorsanız hedefe ayrı bir güç kaynağı kullanın. 3.3 V lojik tercih edin (ör. Arduino Due) veya 1.8–3.3 V hedefleri test ederken seviye dönüştürücü/seri direnç kullanın.
- Raspberry Pi: Pi sürümü daha az kullanılabilir GPIO sunar (bu nedenle taramalar daha yavaştır); güncel pin eşlemesini ve kısıtlamaları depodan kontrol edin.

Yükleme tamamlandıktan sonra seri monitörü 115200 baud hızında açın ve yardım için `h` gönderin. Tipik iş akışı:

- `l` yanlış pozitifleri önlemek için loopback’leri bulur
- `r` gerekirse dahili pull-up’ları açıp kapatır
- `s` TCK/TMS/TDI/TDO (bazen TRST/SRST de) pinlerini tarar
- `y` belgelenmemiş opcode’ları keşfetmek için IR üzerinde kaba kuvvet uygular
- `x` pin durumlarının boundary-scan anlık görüntüsünü alır

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri gösteren `FOUND!` ile başlayan satırlar görürsünüz.

### JTAGenum Güvenlik İpuçları

- Her zaman ortak GND kullanın ve bilinmeyen pinlere hedef Vtref değerinin üzerinde gerilim uygulamayın. Emin değilseniz aday pinlere 100–470 Ω seri direnç ekleyin.
- Cihaz 4 telli JTAG yerine SWD/SWJ kullanıyorsa JTAGenum bunu algılamayabilir; SWD araçlarını veya SWJ-DP destekleyen bir adaptörü deneyin.

## Daha güvenli pin tespiti ve donanım kurulumu

- Önce multimetreyle Vtref ve GND’yi belirleyin. Birçok adaptör, G/Ç gerilimini ayarlamak için Vtref’e ihtiyaç duyar.
- Seviye dönüştürme: push-pull sinyaller için tasarlanmış çift yönlü seviye dönüştürücüleri tercih edin (JTAG hatları open-drain değildir). JTAG için otomatik yön algılayan I2C seviye dönüştürücülerinden kaçının.
- Kullanışlı adaptörler: FT2232H/FT232H kartları (ör. Tigard), CMSIS-DAP, J-Link, ST-LINK (üreticiye özel), ESP-USB-JTAG (ESP32-Sx’te). En azından TCK, TMS, TDI, TDO, GND ve Vtref’i bağlayın; isteğe bağlı olarak TRST ve SRST’yi de bağlayabilirsiniz.

## OpenOCD ile ilk bağlantı (tarama ve IDCODE)

OpenOCD, JTAG/SWD için fiilî OSS’dir. Desteklenen bir adaptörle zinciri tarayabilir ve IDCODE’ları okuyabilirsiniz:<sup>[[1]](#references)</sup>

- J-Link ile genel örnek:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 dahili USB‑JTAG (harici prob gerekmez):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notlar

- "all ones/zeros" IDCODE alırsanız kablolamayı, gücü, Vtref'i ve portun fuse/option bytes tarafından kilitlenip kilitlenmediğini kontrol edin.
- Bilinmeyen chain'leri başlatırken manuel TAP etkileşimi için OpenOCD düşük seviyeli `irscan`/`drscan` komutlarına bakın.<sup>[[1]](#references)</sup>

## CPU'yu durdurma ve bellek/flash dökümü alma

TAP tanındıktan ve bir target script seçildikten sonra core'u durdurabilir ve bellek bölgelerinin veya dahili flash'ın dökümünü alabilirsiniz. Örnekler (target, base address ve size değerlerini ayarlayın):<sup>[[1]](#references)</sup>

- Başlatma sonrasında genel target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (varsa SBA'yı tercih edin):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD yardımcı aracıyla programlama veya okuma:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Bellek Dökümü İpuçları

- Uzun dökümlerden önce belleği hızlıca kontrol etmek için `mdw/mdh/mdb` kullanın.
- Çok cihazlı zincirlerde hedef olmayan cihazlarda BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir board file kullanın.

## Boundary-scan hileleri (EXTEST/SAMPLE)

CPU debug erişimi kilitli olsa bile boundary-scan hâlâ kullanılabilir durumda olabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:<sup>[[1]](#references)</sup>
- Sistem çalışırken pin durumlarının anlık görüntüsünü almak için SAMPLE kullanın (bus etkinliğini bulun, pin eşlemesini doğrulayın).
- Pinleri sürmek için EXTEST kullanın (ör. kart bağlantıları izin veriyorsa, çevrimdışı okumak amacıyla MCU üzerinden harici SPI flash hatlarını bit-bang yöntemiyle kontrol edin).

FT2232x adaptörüyle temel UrJTAG akışı:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Cihazın BSDL dosyası, boundary register bit sıralamasını bilmek için gereklidir. Bazı üreticilerin üretim sırasında boundary-scan hücrelerini kilitlediğini unutmayın.

## Modern hedefler ve notlar

- ESP32‑S3/C3, yerleşik bir USB‑JTAG köprüsü içerir; OpenOCD harici bir probe olmadan doğrudan USB üzerinden iletişim kurabilir. İlk inceleme ve dump almak için oldukça kullanışlıdır.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) OpenOCD tarafından yaygın olarak desteklenir; çekirdeği güvenli biçimde durdurmak mümkün değilse bellek erişimi için SBA'yı tercih edin.
- Birçok MCU, debug authentication ve yaşam döngüsü durumları kullanır. Güç doğru olduğu hâlde JTAG çalışmıyor gibi görünüyorsa cihaz kapalı duruma fuse'lanmış olabilir veya kimlik doğrulaması yapılmış bir probe gerektiriyor olabilir.

## Savunmalar ve güçlendirme (gerçek cihazlarda karşılaşabilecekleriniz)

- Üretimde JTAG/SWD'yi kalıcı olarak devre dışı bırakın veya kilitleyin (ör. STM32 RDP level 2, PAD JTAG'i devre dışı bırakan ESP eFuse'ları, NXP/Nordic APPROTECT/DPAP).
- Üretim erişimini korurken kimlik doğrulamalı debug gerektirin (ARMv8.2‑A ADIv6 Debug Authentication, OEM tarafından yönetilen challenge-response).
- Kolay erişilebilir test pad'lerini yönlendirmeyin; test via'larını gömün, TAP'i yalıtmak için dirençleri çıkarın veya takın, anahtarlamalı konektörler ya da pogo-pin fikstürleri kullanın.
- Açılışta debug kilidi: TAP'i, secure boot'u uygulayan erken ROM aşamasının arkasında tutun.

## References

- [1] [OpenOCD Kullanıcı Kılavuzu – JTAG Komutları ve yapılandırması](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG hata ayıklaması (USB‑JTAG, OpenOCD kullanımı)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino tabanlı JTAG pin dizilimi tarayıcısı](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
