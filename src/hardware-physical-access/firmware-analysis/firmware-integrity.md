# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Yetkili bir değerlendirmede zayıf veya eksik firmware-signature doğrulaması tespit edildiğinde, değiştirilmiş bir firmware image bütünlük üzerindeki etkiyi gösterebilir. Aşağıdaki lab workflow, orijinal extraction, emulation ve repacking adımlarını korurken bir bind shell ekler.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware, firmware-mod-kit (FMK) kullanılarak extract edilebilir.
2. Hedef firmware architecture ve endianness belirlenmelidir.
3. Ortam için Buildroot veya diğer uygun yöntemler kullanılarak bir cross compiler oluşturulabilir.
4. Backdoor, cross compiler kullanılarak build edilebilir.
5. Backdoor, extract edilmiş firmware içindeki /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU binary'si, extract edilmiş firmware rootfs'ine kopyalanabilir.
7. Backdoor, chroot ve QEMU kullanılarak emulate edilebilir.
8. Backdoor'a netcat üzerinden erişilebilir.
9. QEMU binary'si, extract edilmiş firmware rootfs'inden kaldırılmalıdır.
10. Değiştirilmiş firmware, FMK kullanılarak yeniden paketlenebilir.
11. Backdoored firmware, firmware analysis toolkit (FAT) ile emulate edilerek ve netcat kullanılarak hedef backdoor IP'sine ve portuna bağlanılarak test edilebilir.

Dynamic analysis, bootloader manipulation veya hardware security testing yoluyla zaten bir root shell elde edildiyse, implants veya reverse shells gibi önceden derlenmiş test binary'leri çalıştırılabilir. Metasploit'in `msfvenom` aracı, bu validation workflow için architecture-specific bir payload oluşturabilir:<sup>[[4]](#references)</sup>

1. Hedef firmware architecture ve endianness belirlenmelidir.
2. Msfvenom; hedef payload'u, attacker host IP'sini, listening port numarasını, filetype'ı, architecture'ı, platform'u ve output file'ı belirtmek için kullanılabilir.
3. Payload, compromised device'a aktarılmalı ve execution permissions'a sahip olduğu doğrulanmalıdır.
4. Payload'a göre msfconsole başlatılıp ayarlar yapılandırılarak Metasploit, incoming requests'leri karşılayacak şekilde hazırlanabilir.
5. Meterpreter reverse shell, compromised device üzerinde çalıştırılabilir.

## Unauthenticated transport bridges to privileged update protocols

Yaygın bir embedded design hatası, **aynı internal command protocol'ünü birkaç transport üzerinden sunmak**, ancak authentication'ı bunlardan yalnızca birinde uygulamaktır. Örneğin USB challenge-response gerektirebilirken BLE, unauthenticated **GATT writes** işlemlerini aynı privileged firmware-update handler'a iletebilir.<sup>[[1]](#references)</sup>

Tipik offensive workflow:

1. BLE GATT database'ini enumerate edin ve official mobile app tarafından kullanılan writable characteristics'leri belirleyin.
2. App traffic'i sniff edin ve wired protocol ile eşleşen **magic bytes / opcodes** arayın.
3. Privileged commands'leri **pairing olmadan** BLE üzerinden replay edin ve sensitive operations'ların hâlâ çalışıp çalışmadığını doğrulayın.
4. Firmware upgrade, config write, debug veya factory-test opcodes'larına erişilebiliyorsa BLE'yi **radio-reachable admin port** olarak değerlendirin.

Hızlı kontroller:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Tersine mühendislik sırasında doğrulanması gerekenler:

- BLE yalnızca **pairing/bonding** mi gerektiriyor, yoksa sadece basit bir bağlantı yeterli mi?
- Tüm transport katmanları aynı dahili dispatcher tablosuna mı yönlendiriliyor?
- Privileged opcode'lar USB / BLE / UART / Wi-Fi üzerinde farklı şekilde mi filtreleniyor?
- Mobil uygulama firmware update, recovery veya diagnostic handler'larını uzaktan tetikleyebiliyor mu?

## Yalnızca checksum kullanan firmware container'ları hâlâ saldırgan kontrolündeki firmware'dir

Yalnızca **unkeyed checksum** (CRC32, SHA-256, MD5 vb.) ile korunan bir firmware container, **corruption detection** sağlar; **authenticity** sağlamaz. Saldırgan update routine'e erişebiliyorsa image'ı patch'leyebilir, checksum'ı yeniden hesaplayabilir ve istediği kodu flash'layabilir.<sup>[[1]](#references)</sup>

RE sırasında dikkat edilmesi gereken red flag'ler:

- Update code yalnızca `CHK2`, `CRC` veya `SHA256` gibi sondaki bir checksum blob'unu doğruluyor.
- Signature verification veya secure-boot root of trust bulunmuyor.
- Device-bound MAC / HMAC / authenticated encryption kullanılmıyor.
- Recovery mode aynı unauthenticated image formatını kabul ediyor.

Pratik doğrulama akışı:

1. Firmware container'ı extract edin ve bootloader, main firmware ile integrity metadata'yı belirleyin.
2. Image içindeki zararsız bir string'i veya banner'ı değiştirin.
3. Checksum'ı updater'ın beklediği şekilde yeniden hesaplayın.
4. Image'ı normal update path üzerinden yeniden flash'layın.
5. Arbitrary firmware replacement'ı kanıtlamak için değişikliği boot sırasında doğrulayın.

Bu işlem BLE/Wi-Fi gibi uzaktan erişilebilen bir transport üzerinden çalışıyorsa bug, fiilen **unauthenticated OTA firmware replacement** anlamına gelir.

## Güvenilen bir USB peripheral'ını firmware reflashing ile BadUSB'ye dönüştürme

Hedef cihaz host tarafından USB üzerinden zaten güveniliyorsa malicious firmware'in tamamen yeni bir USB stack uygulaması gerekmeyebilir. Çoğu zaman çok daha kolay bir pivot, **mevcut HID desteğini yeniden kullanmaktır**.<sup>[[1]](#references)</sup>

Yararlı yaklaşım:

1. Cihazın zaten **HID Consumer Control** / media / vendor HID interface olarak enumerate olup olmadığını kontrol edin.
2. Firmware içindeki mevcut **HID report descriptor**'ı bulun.
3. Cihazın ayrıca **keyboard** capability'si olduğunu duyurması için descriptor entry'lerini ekleyin veya değiştirin.
4. Yeni bir transport implementation yazmak yerine, HID report'larını zaten gönderen mevcut firmware routine'lerini yeniden kullanın.
5. Host üzerinde command yazmak için key press + key release report'ları inject edin.

Bu işlem firmware compromise'ı **host compromise**'a dönüştürür; çünkü PC, yeniden flash'lanmış peripheral'ı legitimate bir keyboard olarak kabul eder.

### Minimal assessment checklist

- `dmesg`, Device Manager veya USB descriptor'ları mevcut bir HID interface gösteriyor mu?
- Report descriptor'ın yakınında veya relocatable bir descriptor table içinde boş alan var mı?
- Mevcut media-control send routine'leri keyboard report'ları için yeniden kullanılabilir mi?
- Reflashing sonrasında host yeni keyboard interface'ını otomatik olarak kabul ediyor mu?

## RTOS firmware içinde güvenilir payload execution

Fragile trampoline'leri rastgele code path'lerine eklemek yerine, normal operation sırasında kullanılmayan veya düşük etkili olan **mevcut RTOS task'larını** arayın.<sup>[[1]](#references)</sup>

Bunun yararlı olmasının nedenleri:

- Scheduler, payload'ınızı boot sırasında doğal olarak başlatır.
- Kritik control flow'u bozma riskini önlersiniz.
- Delayed payload'ların, latency-sensitive bir USB/network handler içinde çalıştırılmalarına kıyasla watchdog reset'lerini tetikleme olasılığı daha düşüktür.

İyi hedefler arasında normal kullanımda dormant görünen diagnostic, factory-test, telemetry veya coprocessor service task'ları bulunur.

## Hızlı exploit iteration: benign protocol handler'larını yeniden kullanma

Firmware patching mümkün olduğunda RE'yi hızlandırmanın kompakt bir yolu, zararsız bir command handler'ını (örneğin bir **echo/debug opcode**) custom **memory read / write / execute** primitive'leriyle overwrite etmektir. Bu yöntem her deneme için full reflashing gereksinimini ortadan kaldırır ve özellikle cihaz, değiştirilmiş handler'a hızlı bir wired transport üzerinden erişimi destekliyorsa yararlıdır.<sup>[[1]](#references)</sup>

Bunu şu amaçlarla kullanın:

- Scatter-loaded memory map'lerini doğrulamak
- Heap/task state'i canlı olarak incelemek
- Küçük payload'ları flash'a yazmadan önce test etmek
- Function pointer'ları, string'leri ve descriptor table'ları güvenli şekilde kurtarmak

## References

- [1] [Pwnd Blaster: Hoparlörünüze hiç dokunmadan PC'nizi kullanarak hack'leme](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` nasıl kullanılır](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
