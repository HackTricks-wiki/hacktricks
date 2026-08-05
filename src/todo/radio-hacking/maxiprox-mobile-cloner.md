# Taşınabilir HID MaxiProx 125 kHz Mobil Cloner Oluşturma

{{#include ../../banners/hacktricks-training.md}}

## Amaç
Şebeke elektriğiyle çalışan HID MaxiProx 5375 uzun menzilli 125 kHz okuyucuyu, fiziksel güvenlik değerlendirmeleri sırasında proximity kartlarını sessizce toplayan, sahada kullanılabilir ve pille çalışan bir badge cloner'a dönüştürmek.

Burada ele alınan dönüşüm, TrustedSec'in “Let’s Clone a Cloner – Part 3: Putting It All Together” araştırma serisine dayanır ve nihai cihazın bir sırt çantasına atılıp sahada hemen kullanılabilmesi için mekanik, elektriksel ve RF unsurlarını birleştirir.<sup>[[1]](#references)</sup>

> [!warning]
> Şebeke elektriğiyle çalışan ekipmanları ve Lithium-ion power-bank'leri kullanmak tehlikeli olabilir. Devreye enerji vermeden önce her bağlantıyı **mutlaka** doğrulayın ve okuyucunun detuning yaşamasını önlemek için antenleri, coax kablolarını ve ground plane'leri fabrikadaki tasarımda oldukları şekilde koruyun.

## Malzeme Listesi (BOM)

* HID MaxiProx 5375 okuyucu (veya 12 V HID Prox® uzun menzilli okuyucu)
* ESP RFID Tool v2.2 (ESP32 tabanlı Wiegand sniffer/logger)
* 12 V @ ≥3 A anlaşması yapabilen USB-PD (Power-Delivery) trigger modülü
* 100 W USB-C power-bank (12 V PD profili çıkışı)
* 26 AWG silikon yalıtımlı bağlantı kablosu – kırmızı/beyaz
* Panel tipi SPST toggle switch (beeper kill-switch için)
* NKK AT4072 switch-guard / kazara çalışmayı önleyen kapak
* Havya, solder wick ve lehim sökme pompası
* ABS uyumlu el aletleri: kıl testere, maket bıçağı, düz ve yarım yuvarlak eğeler
* 1/16″ (1,5 mm) ve 1/8″ (3 mm) matkap uçları
* 3 M VHB çift taraflı bant ve Zip-tie'lar

## 1. Güç Alt Sistemi

1. Logic PCB için 5 V üretmek üzere kullanılan fabrika buck-converter daughter-board'u lehimlerini sökerek çıkarın.
2. USB-PD trigger'ı ESP RFID Tool'un yanına monte edin ve trigger'ın USB-C yuvasını muhafazanın dışına yönlendirin.
3. PD trigger, power-bank'ten 12 V anlaşması yapar ve bunu doğrudan MaxiProx'a iletir (okuyucu doğal olarak 10–14 V bekler). Aksesuarları beslemek için ikincil 5 V hattı ESP board'dan alınır.
4. 100 W battery pack, dahili standoff'a tam oturacak şekilde yerleştirilir; böylece ferrite antenna üzerinden geçen **hiçbir** güç kablosu bulunmaz ve RF performansı korunur.

## 2. Beeper Kill-Switch – Sessiz Çalışma

1. MaxiProx logic board üzerindeki iki speaker pad'ini bulun.
2. *Her iki* pad'i tamamen temizleyin, ardından yalnızca **negative** pad'i yeniden lehimleyin.
3. 26 AWG kabloları (beyaz = negative, kırmızı = positive) beeper pad'lerine lehimleyin ve yeni açılan bir kanaldan panel tipi SPST switch'e yönlendirin.
4. Switch açık olduğunda beeper devresi kesilir ve okuyucu tamamen sessiz çalışır; bu, gizli badge toplama için idealdir.
5. Toggle'ın üzerine NKK AT4072 spring-loaded safety cap takın. Bir coping-saw / file kullanarak deliği, switch gövdesinin üzerine geçecek şekilde dikkatlice genişletin. Guard, sırt çantası içinde kazara etkinleştirmeyi önler.

## 3. Muhafaza ve Mekanik Çalışma

• Flush cutter'lar, ardından maket bıçağı ve eğe kullanarak dahili ABS “bump-out” bölümünü *çıkarın*; böylece büyük USB-C battery standoff üzerine düz şekilde oturur.
• USB-C kablosu için muhafaza duvarında iki paralel kanal açın; bu, battery'yi yerinde sabitler ve hareketi/titreşimi ortadan kaldırır.
• Battery'nin **power** button'u için dikdörtgen bir açıklık oluşturun:
1. Konumun üzerine bir kâğıt şablon bantlayın.
2. Dört köşenin tamamına 1/16″ kılavuz delikleri açın.
3. 1/8″ uçla delikleri genişletin.
4. Delikleri bir coping saw ile birleştirin; kenarları eğe ile düzeltin.
✱  Döner Dremel kullanılmadı; yüksek hızlı uç, kalın ABS'yi eritir ve kötü görünümlü bir kenar bırakır.

## 4. Son Montaj

1. MaxiProx logic board'u yeniden takın ve SMA pigtail'i okuyucunun PCB ground pad'ine yeniden lehimleyin.
2. ESP RFID Tool'u ve USB-PD trigger'ı 3 M VHB kullanarak monte edin.
3. Tüm kabloları Zip-tie'larla düzenleyin ve güç kablolarını anten loop'undan **uzakta** tutun.
4. Muhafaza vidalarını battery hafifçe sıkışana kadar sıkın; dahili sürtünme, her kart okumasından sonra cihaz geri tepme yaptığında pack'in yerinden oynamasını önler.

## 5. Menzil ve Shielding Testleri

* 125 kHz **Pupa** test card kullanıldığında taşınabilir cloner, serbest havada **≈ 8 cm** mesafede tutarlı okumalar gerçekleştirdi; bu sonuç şebeke elektriğiyle çalışmaya eşitti.<sup>[[1]](#references)</sup>
* Okuyucunun ince duvarlı metal bir para kutusuna (banka lobisindeki masayı simüle etmek için) yerleştirilmesi menzili ≤ 2 cm'ye düşürdü; bu da önemli metal muhafazaların etkili RF shield olarak davrandığını doğruladı.<sup>[[1]](#references)</sup>

## Kullanım İş Akışı

1. USB-C battery'yi şarj edin, bağlayın ve ana power switch'i çevirin.
2. (İsteğe bağlı) Bench-test sırasında sesli geri bildirimi etkinleştirmek için beeper guard'ı açın; gizli saha kullanımı öncesinde guard'ı kilitleyin.
3. Hedef badge sahibinin yanından geçin; MaxiProx card'ı enerjilendirir ve ESP RFID Tool Wiegand akışını yakalar.
4. Yakalanan credential'ları Wi-Fi veya USB-UART üzerinden dışarı aktarın ve gerektiğinde replay/clone işlemi yapın.

## Sorun Giderme

| Belirti | Olası Neden | Çözüm |
|---------|--------------|------|
| Card sunulduğunda okuyucu yeniden başlıyor | PD trigger 9 V, 12 V yerine anlaşma yaptı | Trigger jumper'larını doğrulayın / daha yüksek güçlü USB-C kablosu deneyin |
| Okuma menzili yok | Battery veya kablolar antenin *üzerinde* duruyor | Kabloları yeniden yönlendirin ve ferrite loop çevresinde 2 cm açıklık bırakın |
| Beeper hâlâ ötüyor | Switch, negative yerine positive hatta bağlanmış | Kill-switch'i **negative** speaker trace'ini kesecek şekilde taşıyın |

## Referanslar

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
