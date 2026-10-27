# Firmware Bütünlüğü

{{#include ../../banners/hacktricks-training.md}}

Yetkili bir değerlendirmede firmware imza doğrulamasının zayıf veya eksik olduğu tespit edilirse, değiştirilmiş bir firmware imajı kullanılarak bütünlük üzerindeki etki gösterilebilir. Aşağıdaki laboratuvar iş akışı, özgün çıkarma, emülasyon ve yeniden paketleme adımlarını korurken bir bind shell ekler.<sup>[[2]](#references)[[3]](#references)</sup>

1. Firmware, firmware-mod-kit (FMK) kullanılarak çıkarılabilir.
2. Hedef firmware mimarisi ve endianness belirlenmelidir.
3. Ortam için Buildroot veya başka uygun yöntemlerle bir cross compiler oluşturulabilir.
4. Backdoor, cross compiler kullanılarak derlenebilir.
5. Backdoor, çıkarılmış firmware’in /usr/bin dizinine kopyalanabilir.
6. Uygun QEMU binary’si, çıkarılmış firmware’in rootfs dizinine kopyalanabilir.
7. Backdoor, chroot ve QEMU kullanılarak emüle edilebilir.
8. Backdoor’a netcat aracılığıyla erişilebilir.
9. QEMU binary’si, çıkarılmış firmware’in rootfs dizininden kaldırılmalıdır.
10. Değiştirilmiş firmware, FMK kullanılarak yeniden paketlenebilir.
11. Backdoor eklenmiş firmware, firmware analysis toolkit (FAT) ile emüle edilerek ve netcat kullanılarak hedef backdoor IP adresine ve portuna bağlanılarak test edilebilir.

Dinamik analiz, bootloader manipülasyonu veya donanım güvenlik testleri yoluyla zaten bir root shell elde edilmişse, implant veya reverse shell gibi önceden derlenmiş test binary’leri çalıştırılabilir. Metasploit’in `msfvenom` aracı, bu doğrulama iş akışı için mimariye özgü bir payload oluşturabilir:<sup>[[4]](#references)</sup>

1. Hedef firmware mimarisi ve endianness belirlenmelidir.
2. Hedef payload, saldırganın host IP adresi, dinleme port numarası, filetype, mimari, platform ve çıktı dosyası belirtmek için Msfvenom kullanılabilir.
3. Payload, ele geçirilmiş cihaza aktarılabilir ve çalıştırma izinlerine sahip olduğu doğrulanabilir.
4. msfconsole başlatılıp ayarlar payload’a göre yapılandırılarak gelen bağlantıları karşılamak üzere Metasploit hazırlanabilir.
5. Meterpreter reverse shell, ele geçirilmiş cihazda çalıştırılabilir.

## Ayrıcalıklı güncelleme protokollerine kimlik doğrulamasız taşıma köprüleri

Yaygın bir gömülü sistem tasarım hatası, **aynı dahili komut protokolünü birden fazla taşıma yöntemi üzerinden sunmak**, ancak kimlik doğrulamayı yalnızca bunlardan birinde uygulamaktır. Örneğin USB üzerinden challenge-response gerekirken BLE, kimlik doğrulamasız **GATT yazmalarını** doğrudan aynı ayrıcalıklı firmware güncelleme işleyicisine iletebilir.<sup>[[1]](#references)</sup>

Tipik saldırı iş akışı:

1. BLE GATT veritabanını numaralandırın ve resmi mobil uygulamanın kullandığı yazılabilir karakteristikleri belirleyin.
2. Uygulama trafiğini dinleyin ve kablolu protokolle eşleşen **magic bytes / opcode** değerlerini arayın.
3. Ayrıcalıklı komutları **eşleştirme yapmadan** BLE üzerinden yeniden gönderin ve hassas işlemlerin hâlâ çalışıp çalışmadığını doğrulayın.
4. Firmware yükseltme, yapılandırma yazma, hata ayıklama veya fabrika testi opcode’larına erişilebiliyorsa BLE’yi **radyo üzerinden erişilebilen bir yönetici portu** olarak değerlendirin.

Hızlı kontroller:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Doğrulama sırasında kontrol edilmesi gerekenler:

- BLE için **eşleştirme/bonding** gerekiyor mu, yoksa düz bir bağlantı yeterli mi?
- Tüm taşıma katmanları aynı dahili dispatcher tablosuna mı yönlendiriliyor?
- Ayrıcalıklı opcode'lar USB / BLE / UART / Wi-Fi üzerinden farklı şekilde mi filtreleniyor?
- Mobil uygulama firmware güncelleme, kurtarma veya tanılama işleyicilerini uzaktan tetikleyebiliyor mu?

## Yalnızca checksum ile korunan firmware kapsayıcıları hâlâ saldırganın kontrolündedir

Yalnızca **anahtarsız bir checksum** (CRC32, SHA-256, MD5 vb.) ile korunan bir firmware kapsayıcısı bozulma tespiti sağlar, **özgünlük doğrulaması sağlamaz**. Saldırgan güncelleme yordamına erişebiliyorsa görüntüyü yamalayabilir, checksum'u yeniden hesaplayabilir ve istediği kodu flash'a yazabilir.<sup>[[1]](#references)</sup>

RE sırasında dikkat edilmesi gereken uyarı işaretleri:

- Güncelleme kodu yalnızca `CHK2`, `CRC` veya `SHA256` gibi sondaki bir checksum verisini doğruluyor.
- İmza doğrulaması veya secure-boot kök güveni yok.
- Cihaza bağlı MAC / HMAC / kimliği doğrulanmış şifreleme kullanılmıyor.
- Kurtarma modu aynı kimliği doğrulanmamış görüntü biçimini kabul ediyor.

Pratik doğrulama akışı:

1. Firmware kapsayıcısını çıkarın; bootloader'ı, ana firmware'i ve bütünlük meta verilerini belirleyin.
2. Görüntüde zararsız bir metni veya banner'ı değiştirin.
3. Checksum'u güncelleyicinin beklediği şekilde yeniden hesaplayın.
4. Görüntüyü normal güncelleme yoluyla yeniden flash'a yazın.
5. İstediğiniz firmware'in yüklendiğini doğrulamak için açılışta değişikliği kontrol edin.

Bu işlem BLE/Wi-Fi gibi uzaktan erişilebilen bir taşıma katmanı üzerinden çalışıyorsa, açık fiilen **kimlik doğrulaması olmadan OTA firmware değiştirme** anlamına gelir.

## Parçalı güncelleme durumu ve yazılabilir bütünlük meta verileri

Bir güncelleyici kurulum sırasında imzalı firmware başlığını doğrulasa da görüntüleri açılışta yalnızca kayıtlı bir bütünlük özetiyle doğrulayabilir. Cypherock X1'de Bootloader, başlığı doğrulamak ve sürüm/boyut bilgilerini RAM'e almak, firmware imzasını RAM'de tutmak, yazılan görüntüyü doğrulamak ve son olarak görüntünün özetini kalıcı Primary Bootloader Data'ya yazmak için ayrı Firewall görevleri çağırıyordu. İmzanın kendisi kalıcı olarak saklanmıyordu. Bu görevler, kimliği doğrulanmış tek bir yükseltme işlemi zorunlu kılınmadan ayrı ayrı çağrılabiliyordu.<sup>[[5]](#references)</sup>

MCU'da kod çalıştırma ve Flash'a yazma erişimiyle, bildirilen saldırı uygulama görüntüsünü yeniden yazıyor, Bootloader RAM'inde Firewall ile paylaşılan sürüm/boyut değerlerini değiştiriyor, ardından kötü amaçlı görüntünün özetini kaydetmek ve normal açılış durumunu geri yüklemek için son meta veri görevini çağırıyordu. Normal açılışta yapılan bütünlük kontrolü, imzayı yeniden doğrulamadan bu özeti kabul ediyordu. Benzer bir güncelleyiciyi incelerken **her görevi hangi bileşenin çağırabildiğini**, doğrulanmış değerlerin nerede tutulduğunu ve açılış kararının, özeti kaydedilen *aynı görüntünün* kimliğini doğrulayıp doğrulamadığını izleyin. Bu durum, yalnızca checksum kullanan görüntü biçimlerinden daha spesifiktir: imza doğrulaması vardı, ancak durum geçişi bu doğrulamaya bağlanmamıştı.<sup>[[5]](#references)</sup>

## Güvenilmeyen firmware ölçümleri üzerinde secure element imzaları

Bir secure element, yalnızca kodun kendisinin sağladığı bir özeti imzalayarak çalışan kodun kimliğini doğrulayamaz. Aynı cüzdanda secure element, cihaz seri numarasını ve MCU üzerinden sağlanan bir cloud nonce'u ile firmware özetinin XOR'unu imzalıyordu. Ele geçirilmiş firmware, farklı baytları çalıştırırken imzalanması için beklenen özeti sunabiliyordu. Eşlik eden istemci firmware sürümünü de cloud'a gönderiyordu; bu nedenle doğrulayıcının beklenen özet karşılaştırması, Flash'ın bağımsız bir okuması yerine hâlâ MCU kaynaklı bir ölçüme dayanıyordu.<sup>[[5]](#references)</sup>

Cihaz tarafındaki sonuç, ayrı bir güven sınırıydı: cloud cihazı kontrol ediyordu, ancak cihaz cloud'un kararını doğrulamıyordu. Değiştirilmiş bir istemci, kurcalanmış bir cihaza yerel başarı bildirebilirdi. Ölçümün kaynağını ve yanıt kimlik doğrulamasını ayrı ayrı test edin; geçerli bir secure-element imzası ve başarı ekranı, yüklü uygulamanın özgün olduğunu tek başına kanıtlamaz.<sup>[[5]](#references)</sup>

Bu güncelleyicinin analiz edilmesini sağlayan korumalı kodun açığa çıkarılmasıyla ilgili bilgi için bkz. [Firewall copy-task firmware acquisition](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Güvenilir bir USB çevre birimini firmware'i yeniden flash'layarak BadUSB'ye dönüştürme

Hedef cihaz USB üzerinden ana bilgisayar tarafından zaten güvenilir kabul ediliyorsa, kötü amaçlı firmware'in tamamen yeni bir USB yığını uygulaması gerekmeyebilir. Daha kolay bir geçiş yolu çoğu zaman **mevcut HID desteğini yeniden kullanmaktır**.<sup>[[1]](#references)</sup>

İzlenebilecek yöntem:

1. Cihazın zaten bir **HID Consumer Control** / medya / üretici HID arayüzü olarak tanınıp tanınmadığını kontrol edin.
2. Firmware'deki mevcut **HID report descriptor**'ı bulun.
3. Cihazın **klavye** özelliğini de duyurması için descriptor girdilerini ekleyin veya değiştirin.
4. Yeni bir taşıma katmanı uygulaması yazmak yerine, HID raporlarını zaten gönderen mevcut firmware yordamlarını yeniden kullanın.
5. Ana bilgisayarda komut yazmak için tuş basma + tuş bırakma raporlarını gönderin.

Bu, firmware'in ele geçirilmesini **ana bilgisayarın ele geçirilmesine** dönüştürür; çünkü PC, yeniden flash'lanan çevre birimini meşru bir klavye olarak kabul eder.

### Asgari değerlendirme kontrol listesi

- `dmesg`, Device Manager veya USB descriptor'ları mevcut bir HID arayüzü gösteriyor mu?
- Report descriptor'ın yakınında kullanılmayan alan veya taşınabilir bir descriptor tablosu var mı?
- Mevcut medya denetimi gönderme yordamları klavye raporları için yeniden kullanılabilir mi?
- Yeniden flash işleminden sonra ana bilgisayar yeni klavye arayüzünü otomatik olarak kabul ediyor mu?

## RTOS firmware içinde güvenilir payload çalıştırma

Rastgele kod yollarına kırılgan trampoline'ler eklemek yerine, normal çalışmada kullanılmayan veya etkisi düşük olan **mevcut RTOS görevlerini** arayın.<sup>[[1]](#references)</sup>

Bunun yararları:

- Scheduler, payload'ınızı açılış sırasında doğal olarak başlatır.
- Kritik kontrol akışını bozma riskini önlersiniz.
- Gecikmeli payload'ların watchdog reset'lerini tetikleme olasılığı, gecikmeye duyarlı bir USB/ağ işleyicisi içinde çalıştırılmalarına kıyasla daha düşüktür.

İyi hedefler arasında normal kullanımda etkin görünmeyen tanılama, fabrika testi, telemetri veya coprocessor hizmet görevleri bulunur.

## Hızlı exploit yinelemesi: zararsız protokol işleyicilerini yeniden kullanma

Firmware yamalanabildiğinde, RE'yi hızlandırmanın pratik bir yolu zararsız bir komut işleyicisini (örneğin bir **echo/debug opcode**) özel **bellek okuma / yazma / çalıştırma** işlevleriyle değiştirmektir. Böylece her deney için baştan flash'a yazma ihtiyacı ortadan kalkar. Bu yöntem, özellikle cihaz değiştirilmiş işleyiciyi hızlı bir kablolu taşıma katmanı üzerinden destekliyorsa kullanışlıdır.<sup>[[1]](#references)</sup>

Bunu şu amaçlarla kullanın:

- Scatter-loaded bellek haritalarını doğrulamak
- Heap/görev durumunu çalışırken incelemek
- Küçük payload'ları flash'a yazmadan önce test etmek
- İşaretçileri, metinleri ve descriptor tablolarını güvenle kurtarmak

## References

- [1] [Pwnd Blaster: Hoparlörünüze dokunmadan onu kullanarak PC'nizi hacklemek](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` nasıl kullanılır](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Cypherock Donanım Cüzdanını Nasıl ve Neden Hack'ledik: Tüm Hikâye](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
