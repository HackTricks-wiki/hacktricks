# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum), Arduino uyumlu bir MCU'ya veya (deneysel olarak) Raspberry Pi'ye yükleyebileceğiniz; bilinmeyen JTAG pin yapılandırmalarını brute-force yöntemiyle bulabilen ve hatta instruction register'ları enumerate edebilen bir araçtır.

- Arduino: D2-D11 arasındaki dijital pinleri, şüpheli en fazla 10 JTAG pad/testpoint'ine bağlayın ve Arduino GND'yi hedef cihazın GND'sine bağlayın. Güvenli olduğundan emin değilseniz hedef cihaza ayrı bir güç kaynağı sağlayın. 3.3 V logic'i (ör. Arduino Due) tercih edin veya 1.8-3.3 V hedefleri incelerken level shifter/seri direnç kullanın.
- Raspberry Pi: Pi build'i daha az kullanılabilir GPIO sunar (bu nedenle taramalar daha yavaştır); güncel pin eşlemesini ve kısıtlamaları repo'dan kontrol edin.

Flash işlemi tamamlandıktan sonra serial monitor'ü 115200 baud hızında açın ve yardım için `h` gönderin. Tipik akış:

- `l` yanlış pozitifleri önlemek için loopback'leri bulur
- `r` gerektiğinde dahili pull-up'ları açıp kapatır
- `s` TCK/TMS/TDI/TDO'yu (ve bazen TRST/SRST'yi) tarar
- `y` belgelenmemiş opcode'ları keşfetmek için IR'ı brute-force yöntemiyle dener
- `x` pin durumlarının boundary-scan anlık görüntüsünü alır

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan anlık görüntüsü](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri belirten ve `FOUND!` ile başlayan satırlar görürsünüz.

İpuçları
- Her zaman ortak bir ground kullanın ve bilinmeyen pinleri hedef Vtref değerinin üzerinde hiçbir zaman sürmeyin. Emin değilseniz aday pinlere 100-470 Ω seri direnç ekleyin.
- Cihaz 4-wire JTAG yerine SWD/SWJ kullanıyorsa JTAGenum bunu algılamayabilir; SWD araçlarını veya SWJ-DP destekleyen bir adapter'ı deneyin.

## Daha güvenli pin arama ve donanım kurulumu

- Önce bir multimetreyle Vtref ve GND'yi belirleyin. Birçok adapter, I/O voltajını ayarlamak için Vtref'e ihtiyaç duyar.
- Level shifting: push-pull sinyalleri için tasarlanmış bidirectional level shifter'ları tercih edin (JTAG hatları open-drain değildir). JTAG için auto-direction I2C shifter'ları kullanmaktan kaçının.
- Kullanışlı adapter'lar: FT2232H/FT232H kartları (ör. Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (ESP32-Sx üzerinde). En azından TCK, TMS, TDI, TDO, GND ve Vtref'i bağlayın; TRST ve SRST isteğe bağlıdır.

## OpenOCD ile ilk temas (tarama ve IDCODE)

OpenOCD, JTAG/SWD için de-facto OSS'dir. Desteklenen bir adapter ile chain'i tarayabilir ve IDCODE'ları okuyabilirsiniz:<sup>[[1]](#references)</sup>

- J-Link ile genel örnek:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 dahili USB‑JTAG (harici probe gerekmez):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notlar
- "all ones/zeros" IDCODE alırsanız kabloları, gücü, Vtref'i ve portun fuse/option bytes tarafından kilitlenip kilitlenmediğini kontrol edin.
- Bilinmeyen chain'leri bring up ederken manuel TAP interaction için OpenOCD'nin düşük seviyeli `irscan`/`drscan` komutlarına bakın.<sup>[[1]](#references)</sup>

## CPU'yu durdurma ve memory/flash dump'ı alma

TAP tanındıktan ve bir target script seçildikten sonra core'u durdurabilir ve memory bölgelerini veya dahili flash'ı dump edebilirsiniz. Örnekler (target, base address'leri ve size'ları uygun şekilde ayarlayın):<sup>[[1]](#references)</sup>

- Init sonrası generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (mevcut olduğunda SBA'yı tercih edin):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD helper ile programlayın veya okuyun:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
İpuçları
- Uzun dökümlerden önce belleği sanity-check etmek için `mdw/mdh/mdb` kullanın.
- Çok cihazlı zincirlerde hedef olmayanlar için BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir board file kullanın.

## Boundary-scan hileleri (EXTEST/SAMPLE)

CPU debug access kilitli olsa bile boundary-scan hâlâ açıkta olabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:<sup>[[1]](#references)</sup>
- Sistem çalışırken pin durumlarının anlık görüntüsünü almak için SAMPLE kullanın (bus etkinliğini bulun, pin eşlemesini doğrulayın).
- Pinleri sürmek için EXTEST kullanın (örneğin, board wiring izin veriyorsa MCU üzerinden harici SPI flash hatlarını bit-bang ile sürerek flash'ı offline okuyun).

FT2232x adapter ile minimal UrJTAG akışı:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Cihazın boundary register bit sıralamasını bilmek için BSDL gerekir. Bazı vendor'ların production aşamasında boundary-scan hücrelerini kilitlediğini unutmayın.

## Modern hedefler ve notlar

- ESP32-S3/C3 native USB-JTAG bridge içerir; OpenOCD harici bir probe olmadan doğrudan USB üzerinden iletişim kurabilir. Triage ve dump'lar için oldukça kullanışlıdır.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) OpenOCD tarafından geniş ölçüde desteklenir; core güvenli şekilde durdurulamıyorsa memory access için SBA'yı tercih edin.
- Birçok MCU, debug authentication ve lifecycle state uygular. Güç doğru olmasına rağmen JTAG çalışmıyor gibi görünüyorsa cihaz closed state'e fuse edilmiş olabilir veya authenticated probe gerektirebilir.

## Defenses and hardening (gerçek cihazlarda karşılaşmayı bekleyebilecekleriniz)

- Production ortamında JTAG/SWD'yi kalıcı olarak devre dışı bırakın veya kilitleyin (ör. STM32 RDP level 2, PAD JTAG'yi devre dışı bırakan ESP eFuse'ları, NXP/Nordic APPROTECT/DPAP).
- Manufacturing access'i korurken authenticated debug gerektirin (ARMv8.2‑A ADIv6 Debug Authentication, OEM tarafından yönetilen challenge-response).
- Kolay erişilebilir test pad'lerini yönlendirmeyin; test via'larını gömün, TAP'i izole etmek için dirençleri kaldırın veya yerleştirin, keying özellikli konektörler ya da pogo-pin fixture'ları kullanın.
- Power-on debug lock: secure boot'u uygulayan erken ROM'un arkasında TAP'i gate'leyin.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
