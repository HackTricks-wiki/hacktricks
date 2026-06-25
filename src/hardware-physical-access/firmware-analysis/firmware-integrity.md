# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**Özel firmware ve/veya derlenmiş binary'ler, integrity veya signature verification açıklarından yararlanmak için yüklenebilir**. Backdoor bind shell derlemesi için aşağıdaki adımlar izlenebilir:

1. firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianness belirlenmelidir.
3. Ortam için Buildroot veya diğer uygun yöntemler kullanılarak bir cross compiler oluşturulabilir.
4. Backdoor, cross compiler kullanılarak derlenebilir.
5. Backdoor, çıkarılan firmware içindeki /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU binary'si, çıkarılan firmware rootfs içine kopyalanabilir.
7. Backdoor, chroot ve QEMU kullanılarak emüle edilebilir.
8. Backdoor, netcat üzerinden erişilebilir.
9. QEMU binary'si, çıkarılan firmware rootfs içinden kaldırılmalıdır.
10. Değiştirilmiş firmware, FMK kullanılarak yeniden paketlenebilir.
11. Backdoor'lu firmware, firmware analysis toolkit (FAT) ile emüle edilerek ve netcat kullanılarak hedef backdoor IP ve portuna bağlanılarak test edilebilir.

Eğer dynamic analysis, bootloader manipulation veya hardware security testing yoluyla zaten bir root shell elde edilmişse, implant veya reverse shell gibi önceden derlenmiş kötü amaçlı binary'ler çalıştırılabilir. Metasploit framework ve 'msfvenom' gibi otomatik payload/implant araçları aşağıdaki adımlar kullanılarak değerlendirilebilir:

1. Hedef firmware mimarisi ve endianness belirlenmelidir.
2. Msfvenom, hedef payload, saldırgan host IP'si, dinleme port numarası, filetype, architecture, platform ve çıktı dosyasını belirtmek için kullanılabilir.
3. Payload, ele geçirilmiş cihaza aktarılmalı ve execution permissions'a sahip olduğu নিশ্চিত edilmelidir.
4. Gelen istekleri işlemek için msfconsole başlatılarak ve ayarlar payload'a göre yapılandırılarak Metasploit hazırlanabilir.
5. meterpreter reverse shell, ele geçirilmiş cihazda çalıştırılabilir.

## Unauthenticated transport bridges to privileged update protocols

Yaygın bir embedded tasarım hatası, **aynı internal command protocol'ü birden fazla transport üzerinden açığa çıkarmak** ama authentication'ı yalnızca bunlardan birinde zorunlu kılmaktır. Örneğin, USB challenge-response gerektirebilirken BLE, unauthenticated **GATT writes** işlemlerini aynı privileged firmware-update handler'a doğrudan iletebilir.

Tipik offensive workflow:

1. BLE GATT database'ini enumerate edin ve resmi mobile app tarafından kullanılan writable characteristics'i belirleyin.
2. App traffic'i sniff edin ve kablolu protokolle eşleşen **magic bytes / opcodes** arayın.
3. Privileged komutları BLE üzerinden **pairing olmadan** replay edin ve sensitive operations'ın hâlâ çalışıp çalışmadığını doğrulayın.
4. Eğer firmware upgrade, config write, debug veya factory-test opcodes erişilebilir durumdaysa, BLE'yi bir **radio-reachable admin port** olarak değerlendirin.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Dikkat edilecek şeyler, reverse yaparken:

- BLE, **pairing/bonding** mi gerektiriyor yoksa düz bir connection yeterli mi?
- Tüm transports aynı internal dispatcher table’a mı yönlendiriliyor?
- Privileged opcodes USB / BLE / UART / Wi-Fi üzerinde farklı mı filtreleniyor?
- Mobile app firmware update, recovery veya diagnostic handlers’ı uzaktan tetikleyebiliyor mu?

## Sadece checksum ile korunan firmware container’lar hâlâ attacker-controlled firmware’dir

Yalnızca **unkeyed checksum** (CRC32, SHA-256, MD5, vb.) ile korunan bir firmware container, bozulma tespiti sağlar, **authenticity** sağlamaz. Attacker update rutinine erişebiliyorsa, image’ı patch’leyebilir, checksum’ı yeniden hesaplayabilir ve arbitrary code flash’layabilir.

RE sırasında kırmızı bayraklar:

- Update code yalnızca `CHK2`, `CRC` veya `SHA256` gibi sona eklenen bir checksum blob’unu doğruluyor.
- Signature verification veya secure-boot root of trust yok.
- Device-bound MAC / HMAC / authenticated encryption kullanılmıyor.
- Recovery mode aynı unauthenticated image formatını kabul ediyor.

Pratik validation akışı:

1. Firmware container’ı çıkarın ve bootloader, main firmware ve integrity metadata’yı belirleyin.
2. Image içinde zararsız bir string veya banner değiştirin.
3. Updater’ın beklediği şekilde checksum’ı tam olarak yeniden hesaplayın.
4. Image’ı normal update path üzerinden yeniden flash’layın.
5. Arbitrary firmware replacement’ı kanıtlamak için boot sırasında değişikliği doğrulayın.

Bu, remotely reachable bir transport üzerinden çalışıyorsa, örneğin BLE/Wi-Fi, bug fiilen **unauthenticated OTA firmware replacement**’tır.

## Güvenilir bir USB peripheral’ı firmware reflashing ile BadUSB’ye dönüştürmek

Hedef cihaz host tarafından USB üzerinden zaten trusted ise, malicious firmware tam yeni bir USB stack uygulamak zorunda olmayabilir. Çoğu zaman çok daha kolay pivot, mevcut **HID support**’u yeniden kullanmaktır.

Faydalı pattern:

1. Cihazın zaten **HID Consumer Control** / media / vendor HID interface olarak enumerate olup olmadığını kontrol edin.
2. Firmware içinde mevcut **HID report descriptor**’ı bulun.
3. Descriptor entry’lerini ekleyin veya değiştirin, böylece cihaz **keyboard** yeteneği de ilan etsin.
4. Yeni bir transport implementation yazmak yerine, zaten HID report gönderen mevcut firmware rutinlerini yeniden kullanın.
5. Host üzerinde komut yazmak için key press + key release report’ları inject edin.

Bu, firmware compromise’ı **host compromise**’a dönüştürür çünkü PC reflashed peripheral’a meşru bir keyboard gibi güvenir.

### Minimum değerlendirme checklist’i

- `dmesg`, Device Manager veya USB descriptors mevcut bir HID interface gösteriyor mu?
- Report descriptor yakınında boş alan veya relocatable descriptor table var mı?
- Mevcut media-control send rutinleri keyboard report’ları için yeniden kullanılabilir mi?
- Host, reflashing sonrası yeni keyboard interface’i otomatik kabul ediyor mu?

## RTOS firmware içinde güvenilir payload execution

Kırılgan trampoline’leri rastgele code path’lere enjekte etmek yerine, normal kullanımda kullanılmayan veya düşük etkili **existing RTOS tasks** arayın.

Bu neden faydalı:

- Scheduler payload’ınızı boot sırasında doğal olarak başlatır.
- Kritik control flow’u bozmazsınız.
- Gecikmeli payload’lar, latency-sensitive bir USB/network handler içinde çalıştırıldıklarına göre watchdog reset’i tetikleme olasılığı daha düşüktür.

İyi hedefler, normal kullanımda pasif görünen diagnostic, factory-test, telemetry veya coprocessor service task’larıdır.

## Hızlı exploit iterasyonu: zararsız protocol handlers’ı yeniden kullanın

Firmware patching mümkün olduktan sonra, RE’yi hızlandırmanın kompakt bir yolu, zararsız bir command handler’ı (örneğin bir **echo/debug opcode**) custom **memory read / write / execute** primitive’leri ile overwrite etmektir. Bu, her deney için tam reflashing ihtiyacını ortadan kaldırır ve özellikle cihaz değiştirilmiş handler’ı hızlı bir wired transport üzerinden destekliyorsa kullanışlıdır.

Bunu şunlar için kullanın:

- Scatter-loaded memory map’leri doğrulamak
- Heap/task state’i canlı incelemek
- Küçük payload’ları flash’a yazmadan önce test etmek
- Function pointer’ları, string’leri ve descriptor table’ları güvenli şekilde geri almak

## Kaynaklar

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
