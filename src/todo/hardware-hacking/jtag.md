# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) bilinmeyen JTAG pinout'larını brute-force ile denemek ve hatta talimat kayıtlarını numaralandırmak için bir Arduino uyumlu MCU veya (deneysel olarak) bir Raspberry Pi'ye yükleyebileceğiniz bir araçtır.

- Arduino: dijital pinleri D2–D11'i 10'a kadar şüpheli JTAG pad'lerine/test noktalarına bağlayın ve Arduino GND'yi hedef GND'ye bağlayın. Hedefi ayrı bir şekilde besleyin, aksi takdirde rayın güvenli olduğunu bilmiyorsanız. 3.3 V mantığını tercih edin (örneğin, Arduino Due) veya 1.8–3.3 V hedefleri incelerken bir seviye dönüştürücü/seri dirençler kullanın.
- Raspberry Pi: Pi yapısı daha az kullanılabilir GPIO sunar (bu nedenle taramalar daha yavaştır); güncel pin haritası ve kısıtlamalar için repoyu kontrol edin.

Flashtan sonra, 115200 baud hızında seri monitörü açın ve yardım için `h` gönderin. Tipik akış:

- `l` yanlış pozitifleri önlemek için döngü geri dönüşlerini bul
- `r` gerekiyorsa dahili pull-up'ları değiştir
- `s` TCK/TMS/TDI/TDO (ve bazen TRST/SRST) için tarama yap
- `y` belgelenmemiş opcode'ları keşfetmek için IR'yi brute-force ile dene
- `x` pin durumlarının sınır tarama anlık görüntüsü

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri gösteren `FOUND!` ile başlayan satırlar göreceksiniz.

İpuçları
- Her zaman toprak paylaşın ve bilinmeyen pinleri hedef Vtref'in üzerine çıkarmayın. Şüphe durumunda, aday pinlerde 100–470 Ω seri dirençler ekleyin.
- Cihaz 4 telli JTAG yerine SWD/SWJ kullanıyorsa, JTAGenum bunu tespit edemeyebilir; SWD araçlarını veya SWJ-DP'yi destekleyen bir adaptörü deneyin.

## Daha güvenli pin avlama ve donanım kurulumu

- Öncelikle bir multimetre ile Vtref ve GND'yi belirleyin. Birçok adaptör, I/O voltajını ayarlamak için Vtref'e ihtiyaç duyar.
- Seviye kaydırma: itme-çekme sinyalleri için tasarlanmış iki yönlü seviye kaydırıcıları tercih edin (JTAG hatları açık-drenaj değildir). JTAG için otomatik yönlendirme I2C kaydırıcılarından kaçının.
- Kullanışlı adaptörler: FT2232H/FT232H kartları (örneğin, Tigard), CMSIS-DAP, J-Link, ST-LINK (satıcıya özgü), ESP-USB-JTAG (ESP32-Sx üzerinde). En azından TCK, TMS, TDI, TDO, GND ve Vtref'i bağlayın; isteğe bağlı olarak TRST ve SRST.

## OpenOCD ile ilk temas (tarama ve IDCODE)

OpenOCD, JTAG/SWD için de facto OSS'dir. Desteklenen bir adaptör ile zinciri tarayabilir ve IDCODE'ları okuyabilirsiniz:

- J-Link ile genel bir örnek:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 yerleşik USB‑JTAG (harici prob gerektirmez):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notlar
- "tüm birler/sıfırlar" IDCODE alırsanız, kablolamayı, gücü, Vtref'i kontrol edin ve portun sigortalar/seçenek baytları tarafından kilitlenmediğinden emin olun.
- Bilinmeyen zincirleri başlatırken manuel TAP etkileşimi için OpenOCD düşük seviyeli `irscan`/`drscan`'e bakın.

## CPU'yu Durdurma ve Bellek/Flash Dump'lama

TAP tanındıktan ve bir hedef betik seçildikten sonra, çekirdeği durdurabilir ve bellek bölgelerini veya dahili flash'ı dökebilirsiniz. Örnekler (hedefi, temel adresleri ve boyutları ayarlayın):

- Başlatmadan sonra genel hedef:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (mümkünse SBA'yı tercih edin):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD yardımcı programı aracılığıyla programlama veya okuma:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Uzun dökümlerden önce belleği kontrol etmek için `mdw/mdh/mdb` kullanın.
- Çoklu cihaz zincirleri için, hedef olmayanlarda BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir kart dosyası kullanın.

## Boundary-scan hileleri (EXTEST/SAMPLE)

CPU hata ayıklama erişimi kilitli olsa bile, boundary-scan hala açığa çıkabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:
- Sistem çalışırken pin durumlarını anlık görüntülemek için SAMPLE kullanın (veri yolu aktivitesini bulun, pin eşlemesini doğrulayın).
- Pinleri sürmek için EXTEST kullanın (örneğin, kart bağlantısı izin veriyorsa, MCU aracılığıyla harici SPI flash hatlarını bit-bang ile okuyun).

FT2232x adaptörü ile minimal UrJTAG akışı:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Bölge kayıt bit sıralamasını bilmek için cihaz BSDL'ye ihtiyacınız var. Bazı satıcıların üretimde sınır tarama hücrelerini kilitlediğine dikkat edin.

## Modern hedefler ve notlar

- ESP32‑S3/C3, yerel bir USB‑JTAG köprüsü içerir; OpenOCD, harici bir prob olmadan doğrudan USB üzerinden iletişim kurabilir. Tahlil ve dökümler için çok kullanışlı.
- RISC‑V hata ayıklama (v0.13+) OpenOCD tarafından geniş ölçüde desteklenmektedir; çekirdek güvenli bir şekilde durdurulamadığında bellek erişimi için SBA'yı tercih edin.
- Birçok MCU, hata ayıklama kimlik doğrulaması ve yaşam döngüsü durumları uygular. JTAG ölü görünüyorsa ancak güç doğruysa, cihaz kapalı bir duruma kilitlenmiş olabilir veya kimlik doğrulaması yapılmış bir prob gerektirebilir.

## Savunmalar ve güçlendirme (gerçek cihazlarda ne beklenmeli)

- Üretimde JTAG/SWD'yi kalıcı olarak devre dışı bırakın veya kilitleyin (örneğin, STM32 RDP seviye 2, PAD JTAG'ı devre dışı bırakan ESP eFuses, NXP/Nordic APPROTECT/DPAP).
- Üretim erişimini korurken kimlik doğrulamalı hata ayıklama gerektirin (ARMv8.2‑A ADIv6 Hata Ayıklama Kimlik Doğrulaması, OEM yönetimli zorluk-cevap).
- Kolay test pad'leri yönlendirmeyin; test vias'larını gömün, TAP'ı izole etmek için dirençleri çıkarın/doldurun, anahtarlama veya pogo-pin aparatları ile konektörler kullanın.
- Güç açma hata ayıklama kilidi: TAP'ı güvenli önyüklemeyi zorlayan erken ROM'un arkasında kapatın.

## Referanslar

- OpenOCD Kullanıcı Kılavuzu – JTAG Komutları ve yapılandırma. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG hata ayıklama (USB‑JTAG, OpenOCD kullanımı). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
