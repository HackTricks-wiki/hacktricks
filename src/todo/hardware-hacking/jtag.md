# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum), Arduino uyumlu bir MCU'ya veya (deneysel olarak) Raspberry Pi'ye yükleyebileceğiniz; bilinmeyen JTAG pin düzenlerini brute-force ile bulabilen ve hatta instruction register'ları enumerate edebilen bir araçtır.

- Arduino: D2–D11 dijital pinlerini, şüpheli 10 adede kadar JTAG pad/testpoint'ine ve Arduino GND'yi hedef GND'ye bağlayın. Rail'in güvenli olduğundan emin değilseniz hedefi ayrı olarak besleyin. 3.3 V logic'i (ör. Arduino Due) tercih edin veya 1.8–3.3 V hedefleri test ederken level shifter/seri dirençler kullanın.
- Raspberry Pi: Pi build'i daha az kullanılabilir GPIO sunar (bu nedenle taramalar daha yavaştır); güncel pin haritası ve kısıtlamalar için repo'yu kontrol edin.

Flash işlemi tamamlandıktan sonra serial monitor'ü 115200 baud ile açın ve yardım için `h` gönderin. Tipik akış:

- `l` false positive'leri önlemek için loopback'leri bulur
- `r` gerekirse dahili pull-up'ları açıp kapatır
- `s` TCK/TMS/TDI/TDO (ve bazen TRST/SRST) için scan yapar
- `y` belgelenmemiş opcode'ları keşfetmek için IR üzerinde brute-force yapar
- `x` pin durumlarının boundary-scan snapshot'ını alır

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin durumlarının boundary-scan snapshot'ı](<../../images/image (774).png>)



Geçerli bir TAP bulunursa, keşfedilen pinleri belirten ve `FOUND!` ile başlayan satırlar görürsünüz.

İpuçları
- Her zaman ground'u ortaklayın ve bilinmeyen pin'leri hedef Vtref'in üzerinde sürmeyin. Emin değilseniz aday pinlere 100–470 Ω seri direnç ekleyin.
- Cihaz 4-wire JTAG yerine SWD/SWJ kullanıyorsa JTAGenum bunu algılamayabilir; SWD araçlarını veya SWJ-DP destekleyen bir adapter'ı deneyin.

## Daha güvenli pin hunting ve donanım kurulumu

- Önce bir multimetre ile Vtref ve GND'yi belirleyin. Birçok adapter, I/O voltage'u ayarlamak için Vtref'e ihtiyaç duyar.
- Level shifting: push-pull signal'lar için tasarlanmış bidirectional level shifter'ları tercih edin (JTAG line'ları open-drain değildir). JTAG için auto-direction I2C shifter'ları kullanmaktan kaçının.
- Kullanışlı adapter'lar: FT2232H/FT232H kartları (ör. Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (ESP32-Sx üzerinde). En azından TCK, TMS, TDI, TDO, GND ve Vtref'i; isteğe bağlı olarak TRST ve SRST'yi bağlayın.

## OpenOCD ile ilk temas (scan ve IDCODE)

OpenOCD, JTAG/SWD için de-facto OSS'tir. Desteklenen bir adapter ile chain'i tarayabilir ve IDCODE'ları okuyabilirsiniz:

- J-Link ile generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 dahili USB‑JTAG (harici probe gerekmez):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notlar
- "all ones/zeros" IDCODE alırsanız kablolamayı, gücü, Vtref’i ve portun fuse/option bytes tarafından kilitlenmediğini kontrol edin.
- Bilinmeyen chain’leri başlatırken manuel TAP etkileşimi için OpenOCD low-level `irscan`/`drscan` komutlarına bakın.<sup>[[1]](#references)</sup>

## CPU’yu durdurma ve memory/flash dökümü alma

TAP tanındıktan ve bir target script seçildikten sonra core’u durdurabilir ve memory bölgelerinin veya internal flash’ın dökümünü alabilirsiniz. Örnekler (target’ı, base address’leri ve size’ları ayarlayın):

- Init sonrasında genel target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (varsa SBA tercih edilir):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD helper ile programlama veya okuma:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
İpuçları
- Uzun dump işlemlerinden önce belleği sanity-check etmek için `mdw/mdh/mdb` kullanın.
- Çok cihazlı zincirlerde hedef olmayan cihazlarda BYPASS ayarlayın veya tüm TAP'leri tanımlayan bir board file kullanın.

## Boundary-scan hileleri (EXTEST/SAMPLE)

CPU debug access kilitli olsa bile boundary-scan hâlâ açık olabilir. UrJTAG/OpenOCD ile şunları yapabilirsiniz:
- Sistem çalışırken pin durumlarının anlık görüntüsünü almak için SAMPLE kullanın (bus activity'yi bulun, pin eşlemesini doğrulayın).
- Pinleri sürmek için EXTEST kullanın (örneğin, board wiring izin veriyorsa MCU üzerinden harici SPI flash hatlarını bit-bang ederek flash'ı offline okuyun).

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

- ESP32-S3/C3 yerel bir USB-JTAG bridge içerir; OpenOCD harici bir probe olmadan doğrudan USB üzerinden iletişim kurabilir. Triage ve dump işlemleri için oldukça kullanışlıdır.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) OpenOCD tarafından yaygın şekilde desteklenir; core güvenli biçimde durdurulamıyorsa memory access için SBA'yı tercih edin.
- Birçok MCU debug authentication ve lifecycle state uygular. Güç doğru olduğu hâlde JTAG çalışmıyor gibi görünüyorsa cihaz closed state için fuse'lanmış olabilir veya authenticated probe gerektirebilir.

## Defenses ve hardening (gerçek cihazlarda beklenenler)

- Production ortamında JTAG/SWD'yi kalıcı olarak devre dışı bırakın veya kilitleyin (ör. STM32 RDP level 2, JTAG PAD'lerini devre dışı bırakan ESP eFuse'ları, NXP/Nordic APPROTECT/DPAP).
- Manufacturing access'i korurken authenticated debug gerektirin (ARMv8.2-A ADIv6 Debug Authentication, OEM tarafından yönetilen challenge-response).
- Kolay erişilebilir test pad'leri yönlendirmeyin; test via'larını gömün, TAP'ı izole etmek için resistor'ları kaldırın veya yerleştirin, keying özellikli connector'lar ya da pogo-pin fixture'lar kullanın.
- Power-on debug lock: secure boot uygulayan erken ROM üzerinden TAP'ı kontrol edin.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
