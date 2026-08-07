# Firmware Bütünlüğü

{{#include ../../banners/hacktricks-training.md}}

**Özel firmware ve/veya derlenmiş binary'ler, bütünlük veya imza doğrulama açıklarından yararlanmak için yüklenebilir**. Backdoor bind shell derlemesi için aşağıdaki adımlar izlenebilir:

1. Firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianness belirlenmelidir.
3. Ortam için Buildroot veya diğer uygun yöntemler kullanılarak bir cross compiler oluşturulabilir.
4. Backdoor, cross compiler kullanılarak derlenebilir.
5. Backdoor, çıkarılan firmware'in /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU binary'si, çıkarılan firmware rootfs'ine kopyalanabilir.
7. Backdoor, chroot ve QEMU kullanılarak emüle edilebilir.
8. Backdoor'a netcat üzerinden erişilebilir.
9. QEMU binary'si, çıkarılan firmware rootfs'inden kaldırılmalıdır.
10. Değiştirilmiş firmware, FMK kullanılarak yeniden paketlenebilir.
11. Backdoor eklenmiş firmware, firmware analysis toolkit (FAT) ile emüle edilerek ve netcat kullanılarak hedef backdoor IP'sine ve portuna bağlanılarak test edilebilir.

Dynamic analysis, bootloader manipulation veya hardware security testing yoluyla zaten bir root shell elde edilmişse implant veya reverse shell gibi önceden derlenmiş malicious binary'ler çalıştırılabilir. Metasploit framework ve 'msfvenom' gibi automated payload/implant araçları aşağıdaki adımlar kullanılarak değerlendirilebilir:

1. Hedef firmware mimarisi ve endianness belirlenmelidir.
2. Msfvenom; hedef payload'ı, attacker host IP'sini, listening port numarasını, filetype'ı, mimariyi, platformu ve output file'ı belirtmek için kullanılabilir.
3. Payload, compromised device'a aktarılmalı ve execution permission'larına sahip olduğu doğrulanmalıdır.
4. Metasploit, msfconsole başlatılarak ve ayarlar payload'a uygun şekilde yapılandırılarak gelen istekleri karşılayacak şekilde hazırlanabilir.
5. Meterpreter reverse shell, compromised device üzerinde çalıştırılabilir.

## Privileged update protocol'lerine kimlik doğrulamasız transport bridge'leri

Yaygın bir embedded design hatası, **aynı internal command protocol'ünü birden fazla transport üzerinden sunmak**, ancak authentication'ı bunlardan yalnızca birinde uygulamaktır. Örneğin USB challenge-response gerektirirken BLE, kimlik doğrulaması yapılmamış **GATT writes** işlemlerini aynı privileged firmware-update handler'a yönlendirebilir.<sup>[[1]](#references)</sup>

Tipik offensive workflow:

1. BLE GATT database'ini enumerate edin ve official mobile app tarafından kullanılan writable characteristic'leri belirleyin.
2. App trafiğini sniff edin ve wired protocol ile eşleşen **magic bytes / opcodes** değerlerini arayın.
3. Privileged command'ları **pairing olmadan** BLE üzerinden replay edin ve sensitive operation'ların hâlâ çalışıp çalışmadığını doğrulayın.
4. Firmware upgrade, config write, debug veya factory-test opcode'larına erişilebiliyorsa BLE'yi **radio-reachable admin port** olarak değerlendirin.

Hızlı kontroller:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Reverse engineering sırasında doğrulanması gerekenler:

- BLE **pairing/bonding** gerektiriyor mu, yoksa yalnızca basit bir bağlantı mı?
- Tüm transport'lar aynı internal dispatcher table'a mı yönlendiriliyor?
- Privileged opcode'lar USB / BLE / UART / Wi-Fi üzerinde farklı şekilde filtreleniyor mu?
- Mobile app, firmware update, recovery veya diagnostic handler'larını uzaktan tetikleyebiliyor mu?

## Yalnızca checksum içeren firmware container'ları hâlâ attacker-controlled firmware'dır

Yalnızca **unkeyed checksum** (CRC32, SHA-256, MD5 vb.) ile korunan bir firmware container, **authenticity** değil, bozulma tespiti sağlar. Attacker update routine'e ulaşabiliyorsa image'ı patch'leyebilir, checksum'ı yeniden hesaplayabilir ve arbitrary code flash'layabilir.<sup>[[1]](#references)</sup>

RE sırasında dikkat edilmesi gereken red flag'ler:

- Update code yalnızca `CHK2`, `CRC` veya `SHA256` gibi trailing checksum blob'larını doğruluyor.
- Signature verification veya secure-boot root of trust mevcut değil.
- Device-bound MAC / HMAC / authenticated encryption kullanılmıyor.
- Recovery mode aynı unauthenticated image formatını kabul ediyor.

Pratik doğrulama akışı:

1. Firmware container'ı extract edin ve bootloader, main firmware ve integrity metadata'yı belirleyin.
2. Image içindeki zararsız bir string'i veya banner'ı değiştirin.
3. Checksum'ı updater'ın beklediği şekilde yeniden hesaplayın.
4. Image'ı normal update path üzerinden yeniden flash'layın.
5. Arbitrary firmware replacement'ı kanıtlamak için değişikliği boot sırasında doğrulayın.

Bu işlem BLE/Wi-Fi gibi remotely reachable bir transport üzerinden çalışıyorsa, bug fiilen **unauthenticated OTA firmware replacement** anlamına gelir.

## Trusted bir USB peripheral'ı firmware reflashing ile BadUSB'ye dönüştürme

Hedef device host tarafından USB üzerinden zaten trusted durumdaysa, malicious firmware'ın tamamen yeni bir USB stack implement etmesi gerekmeyebilir. Çoğu zaman çok daha kolay bir pivot, mevcut HID desteğini **yeniden kullanmaktır**.<sup>[[1]](#references)</sup>

Yararlı yöntem:

1. Device'ın zaten **HID Consumer Control** / media / vendor HID interface olarak enumerate olup olmadığını kontrol edin.
2. Firmware içindeki mevcut **HID report descriptor**'ı bulun.
3. Device'ın keyboard capability de ilan etmesi için descriptor entry'lerini ekleyin veya değiştirin.
4. Yeni bir transport implementation yazmak yerine, HID report'larını zaten gönderen mevcut firmware routine'lerini yeniden kullanın.
5. Host üzerinde command yazmak için key press + key release report'ları inject edin.

Bu işlem firmware compromise'u **host compromise**'a dönüştürür; çünkü PC, reflashed peripheral'ı legitimate bir keyboard olarak trust eder.

### Minimal assessment checklist

- `dmesg`, Device Manager veya USB descriptor'ları mevcut bir HID interface gösteriyor mu?
- Report descriptor'ın yakınında spare room veya relocatable bir descriptor table var mı?
- Mevcut media-control send routine'leri keyboard report'ları için yeniden kullanılabilir mi?
- Host, reflashing sonrasında yeni keyboard interface'ını otomatik olarak kabul ediyor mu?

## RTOS firmware içinde reliable payload execution

Fragile trampoline'leri rastgele code path'lerine yerleştirmek yerine, normal operation sırasında kullanılmayan veya düşük etkili olan **mevcut RTOS task**'lerini arayın.<sup>[[1]](#references)</sup>

Bunun yararlı olmasının nedenleri:

- Scheduler, payload'ınızı boot sırasında doğal şekilde başlatır.
- Critical control flow'u bozma riskinden kaçınırsınız.
- Delayed payload'ların, latency-sensitive bir USB/network handler içinde çalıştırıldıklarında watchdog reset'lerini tetikleme olasılığı daha düşüktür.

İyi hedefler; normal kullanımda dormant görünen diagnostic, factory-test, telemetry veya coprocessor service task'leridir.

## Hızlı exploit iteration: benign protocol handler'larını yeniden kullanma

Firmware patch'lemek mümkün olduğunda, RE'yi hızlandırmanın pratik bir yolu zararsız bir command handler'ı (örneğin bir **echo/debug opcode**) custom **memory read / write / execute** primitive'leriyle overwrite etmektir. Bu yöntem her experiment için full reflashing gerektirmez ve özellikle device, değiştirilen handler'a hızlı bir wired transport üzerinden erişimi destekliyorsa kullanışlıdır.<sup>[[1]](#references)</sup>

Bunu şu amaçlarla kullanın:

- Scatter-loaded memory map'lerini doğrulamak
- Heap/task state'i canlı olarak incelemek
- Küçük payload'ları flash'a yazmadan önce test etmek
- Function pointer'ları, string'leri ve descriptor table'larını güvenli şekilde kurtarmak

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
