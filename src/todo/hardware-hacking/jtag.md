# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum**, bilinmeyen JTAG pin dizilimlerini brute-force yöntemiyle bulmak ve instruction register'ları enumerate etmek için Arduino uyumlu bir MCU'ya veya deneysel olarak Raspberry Pi'ye yükleyebileceğiniz bir tool'dur.<sup>[[3]](#references)</sup>

- Arduino: D2–D11 dijital pinlerini şüpheli en fazla 10 JTAG pad/testpoint'ine, Arduino GND'yi ise hedefin GND'sine bağlayın. Rail'in güvenli olduğundan emin değilseniz hedefi ayrı olarak besleyin. 3.3 V logic'i (ör. Arduino Due) tercih edin veya 1.8–3.3 V hedefleri probelarken level shifter/series resistor kullanın.
- Raspberry Pi: Pi build'i daha az kullanılabilir GPIO sunar (bu nedenle scan işlemleri daha yavaştır); güncel pin map'i ve kısıtlamalar için repo'yu kontrol edin.

Flash işleminden sonra serial monitor'ü 115200 baud hızında açın ve yardım için `h` gönderin. Tipik akış:

- `l` false positive'leri önlemek için loopback'leri bulur
- `r` gerekirse internal pull-up'ları toggle eder
- `s` TCK/TMS/TDI/TDO'yu (ve bazen TRST/SRST'yi) scan eder
- `y` belgelenmemiş opcode'ları keşfetmek için IR'ı brute-force eder
- `x` pin durumlarının boundary-scan snapshot'ını alır

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri belirten ve `FOUND!` ile başlayan satırlar görürsünüz.

### JTAGenum Safety Tips

- Her zaman ground'u ortaklayın ve bilinmeyen pin'leri asla hedef Vtref değerinin üzerinde drive etmeyin. Emin değilseniz aday pin'lere 100–470 Ω series resistor ekleyin.
- Cihaz 4-wire JTAG yerine SWD/SWJ kullanıyorsa JTAGenum bunu algılamayabilir; SWD tools'u veya SWJ-DP destekleyen bir adapter'ı deneyin.

## Daha güvenli pin arama ve hardware setup

- Önce bir multimeter ile Vtref ve GND'yi belirleyin. Birçok adapter, I/O voltage'ı ayarlamak için Vtref'e ihtiyaç duyar.
- Level shifting: push-pull signal'lar için tasarlanmış bidirectional level shifter'ları tercih edin (JTAG lines open-drain değildir). JTAG için auto-direction I2C shifter'larından kaçının.
- Kullanışlı adapter'lar: FT2232H/FT232H boards (ör. Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (ESP32-Sx üzerinde). En azından TCK, TMS, TDI, TDO, GND ve Vtref'i bağlayın; TRST ve SRST isteğe bağlıdır.

## OpenOCD ile ilk temas (scan ve IDCODE)

OpenOCD, JTAG/SWD için de-facto OSS'tir. Desteklenen bir adapter ile chain'i scan edebilir ve IDCODE'ları okuyabilirsiniz:<sup>[[1]](#references)</sup>

- J-Link ile generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 dahili USB‑JTAG (harici probe gerekmez):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notlar

- "all ones/zeros" IDCODE alırsanız kabloları, gücü, Vtref'i ve portun fuse/option bytes tarafından kilitlenip kilitlenmediğini kontrol edin.
- Bilinmeyen zincirleri başlatırken manuel TAP etkileşimi için OpenOCD düşük seviyeli `irscan`/`drscan` komutlarına bakın.<sup>[[1]](#references)</sup>

## CPU'yu durdurma ve memory/flash dökümü alma

TAP tanındığında ve bir target script seçildiğinde, core'u durdurabilir ve memory bölgelerinin veya dahili flash'ın dökümünü alabilirsiniz. Örnekleri target, base address ve size değerlerine göre ayarlayın:<sup>[[1]](#references)</sup>

- Init işleminden sonra generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (mevcut olduğunda SBA tercih edilir):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32-S3, OpenOCD helper aracılığıyla programlayın veya okuyun:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Bellek Dökümü İpuçları

- Uzun dökümlerden önce belleği sanity-check etmek için `mdw/mdh/mdb` kullanın.
- Multi-device chain'ler için hedef olmayan cihazlarda BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir board file kullanın.

## Boundary-scan teknikleri (EXTEST/SAMPLE)

CPU debug erişimi kilitli olsa bile boundary-scan hâlâ açıkta olabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:<sup>[[1]](#references)</sup>
- Sistem çalışırken pin durumlarının anlık görüntüsünü almak için SAMPLE kullanın (bus etkinliğini bulun, pin mapping'ini doğrulayın).
- Pin'leri sürmek için EXTEST kullanın (örneğin, board wiring izin veriyorsa harici SPI flash hatlarını MCU üzerinden bit-bang yaparak çevrimdışı okuyun).

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
Cihazın boundary register bit sıralamasını bilmek için BSDL gerekir. Bazı vendor’ların production aşamasında boundary-scan hücrelerini kilitlediğini unutmayın.

## Modern hedefler ve notlar

- ESP32-S3/C3 yerleşik bir USB-JTAG bridge içerir; OpenOCD harici bir probe olmadan doğrudan USB üzerinden iletişim kurabilir. Triage ve dump işlemleri için oldukça kullanışlıdır.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) OpenOCD tarafından geniş ölçüde desteklenir; core güvenli şekilde durdurulamıyorsa bellek erişimi için SBA’yı tercih edin.
- Birçok MCU debug authentication ve lifecycle state uygular. Güç doğru olmasına rağmen JTAG çalışmıyorsa cihaz closed state için fuse’lanmış olabilir veya authenticated bir probe gerektirebilir.

## Defenses ve hardening (gerçek cihazlarda beklenebilecekler)

- Production ortamında JTAG/SWD’yi kalıcı olarak devre dışı bırakın veya kilitleyin (ör. STM32 RDP level 2, PAD JTAG’yi devre dışı bırakan ESP eFuse’ları, NXP/Nordic APPROTECT/DPAP).
- Manufacturing access’i korurken authenticated debug gerektirin (ARMv8.2‑A ADIv6 Debug Authentication, OEM tarafından yönetilen challenge-response).
- Kolay erişilebilir test pad’lerini route etmeyin; test via’larını gömün, TAP’ı izole etmek için resistor’ları kaldırın veya yerleştirin, keying özellikli connector’lar ya da pogo-pin fixture’lar kullanın.
- Power-on debug lock: TAP’ı secure boot uygulayan erken ROM’un arkasında gate edin.

## References

- [1] [OpenOCD Kullanıcı Kılavuzu – JTAG komutları ve yapılandırması](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD kullanımı)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino tabanlı JTAG pinout tarayıcısı](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
