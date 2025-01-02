{{#include ../../banners/hacktricks-training.md}}

Aşağıdaki adımlar, U-boot gibi cihaz başlangıç yapılandırmalarını ve bootloader'ları değiştirmek için önerilmektedir:

1. **Bootloader'ın Yorumlayıcı Shell'ine Erişim**:

- Başlangıç sırasında, bootloader'ın yorumlayıcı shell'ine erişmek için "0", boşluk veya diğer tanımlanmış "sihirli kodlar" tuşlayın.

2. **Boot Argümanlarını Değiştirin**:

- Bir shell komutunun yürütülmesine izin vermek için boot argümanlarına '`init=/bin/sh`' eklemek için aşağıdaki komutları çalıştırın:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP Sunucusu Kurun**:

- Yerel bir ağ üzerinden görüntüleri yüklemek için bir TFTP sunucusu yapılandırın:
%%%
#setenv ipaddr 192.168.2.2 #cihazın yerel IP'si
#setenv serverip 192.168.2.1 #TFTP sunucu IP'si
#saveenv
#reset
#ping 192.168.2.1 #ağ erişimini kontrol et
#tftp ${loadaddr} uImage-3.6.35 #loadaddr, dosyanın yükleneceği adresi ve TFTP sunucusundaki görüntü dosyasının adını alır
%%%

4. **`ubootwrite.py` Kullanımı**:

- Root erişimi kazanmak için U-boot görüntüsünü yazmak ve değiştirilmiş bir firmware yüklemek için `ubootwrite.py` kullanın.

5. **Debug Özelliklerini Kontrol Edin**:

- Ayrıntılı günlükleme, rastgele çekirdek yükleme veya güvenilmeyen kaynaklardan başlatma gibi debug özelliklerinin etkin olup olmadığını doğrulayın.

6. **Dikkatli Donanım Müdahalesi**:

- Cihazın başlatma sırası sırasında bir pini toprağa bağlarken ve SPI veya NAND flash yongaları ile etkileşimde bulunurken dikkatli olun, özellikle çekirdek açılmadan önce. Pinleri kısa devre yapmadan önce NAND flash yongasının veri sayfasını kontrol edin.

7. **Sahte DHCP Sunucusu Yapılandırın**:
- PXE başlatma sırasında bir cihazın alması için kötü niyetli parametrelerle sahte bir DHCP sunucusu kurun. Metasploit'in (MSF) DHCP yardımcı sunucusu gibi araçları kullanın. 'FILENAME' parametresini `'a";/bin/sh;#'` gibi komut enjeksiyon komutları ile değiştirerek cihaz başlangıç prosedürleri için giriş doğrulamasını test edin.

**Not**: Cihaz pinleri ile fiziksel etkileşim içeren adımlar (\* yıldız ile işaretlenmiş) cihazın zarar görmesini önlemek için son derece dikkatli bir şekilde yaklaşılmalıdır.

## Referanslar

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
