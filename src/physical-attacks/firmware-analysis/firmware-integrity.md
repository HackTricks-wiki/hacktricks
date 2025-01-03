{{#include ../../banners/hacktricks-training.md}}

## Firmware Bütünlüğü

**Özel firmware ve/veya derlenmiş ikili dosyalar, bütünlük veya imza doğrulama hatalarını istismar etmek için yüklenebilir.** Arka kapı bind shell derlemesi için aşağıdaki adımlar izlenebilir:

1. Firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianlık belirlenmelidir.
3. Ortam için Buildroot veya diğer uygun yöntemler kullanılarak bir çapraz derleyici oluşturulabilir.
4. Arka kapı, çapraz derleyici kullanılarak oluşturulabilir.
5. Arka kapı, çıkarılan firmware'in /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU ikili dosyası, çıkarılan firmware rootfs'ye kopyalanabilir.
7. Arka kapı, chroot ve QEMU kullanılarak taklit edilebilir.
8. Arka kapıya netcat aracılığıyla erişilebilir.
9. QEMU ikili dosyası, çıkarılan firmware rootfs'den kaldırılmalıdır.
10. Değiştirilen firmware, FMK kullanılarak yeniden paketlenebilir.
11. Arka kapılı firmware, firmware analysis toolkit (FAT) ile taklit edilerek ve hedef arka kapı IP'sine ve portuna netcat kullanarak bağlanarak test edilebilir.

Eğer dinamik analiz, önyükleyici manipülasyonu veya donanım güvenlik testi yoluyla bir root shell elde edilmişse, implantlar veya ters shell gibi önceden derlenmiş kötü niyetli ikili dosyalar çalıştırılabilir. Metasploit çerçevesi ve 'msfvenom' gibi otomatik yük/implant araçları aşağıdaki adımlar kullanılarak yararlanılabilir:

1. Hedef firmware mimarisi ve endianlık belirlenmelidir.
2. Msfvenom, hedef yükü, saldırgan ana bilgisayar IP'sini, dinleme port numarasını, dosya türünü, mimariyi, platformu ve çıktı dosyasını belirtmek için kullanılabilir.
3. Yük, ele geçirilmiş cihaza aktarılmalı ve yürütme izinlerinin olduğu doğrulanmalıdır.
4. Metasploit, msfconsole başlatarak ve ayarları yükle göre yapılandırarak gelen istekleri işlemek için hazırlanabilir.
5. Meterpreter ters shell, ele geçirilmiş cihazda çalıştırılabilir.
6. Meterpreter oturumları açıldıkça izlenebilir.
7. Post-exploitation faaliyetleri gerçekleştirilebilir.

Mümkünse, başlangıç betiklerinde bulunan zafiyetler, yeniden başlatmalar arasında bir cihaza kalıcı erişim sağlamak için istismar edilebilir. Bu zafiyetler, başlangıç betikleri güvenilmeyen montajlı konumlarda bulunan koda atıfta bulunduğunda, [sembolik bağlantı](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) yaptığında veya bağımlı olduğunda ortaya çıkar; bu konumlar, kök dosya sistemleri dışında veri depolamak için kullanılan SD kartlar ve flash hacimleri gibi yerlerdir.

## Referanslar

- Daha fazla bilgi için [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
