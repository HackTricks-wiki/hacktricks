# Taşınabilir HID MaxiProx 125 kHz Mobil Kopyalayıcı Yapımı

{{#include ../../banners/hacktricks-training.md}}

## Amaç
Şebeke elektriğiyle çalışan HID MaxiProx 5375 uzun menzilli 125 kHz okuyucuyu, fiziksel güvenlik değerlendirmeleri sırasında proximity kartlarını sessizce toplayan, sahada kullanılabilir, pille çalışan bir kart kopyalayıcıya dönüştürmek.

Burada anlatılan dönüşüm, TrustedSec’in “Let’s Clone a Cloner – Part 3: Putting It All Together” araştırma serisine dayanıyor. Son cihazın sırt çantasına atılıp sahada hemen kullanılabilmesi için mekanik, elektriksel ve RF gereksinimlerini bir araya getiriyor.<sup>[[1]](#references)</sup>

> [!warning]
> Şebeke elektriğiyle çalışan ekipmanları ve lityum iyon powerbank’leri kullanmak tehlikeli olabilir. Devreye enerji vermeden **önce** her bağlantıyı doğrulayın; okuyucunun ayarının bozulmasını önlemek için antenleri, koaksiyel kabloları ve toprak düzlemlerini fabrikadaki tasarımla tamamen aynı şekilde bırakın.

## Malzeme Listesi (BOM)

* HID MaxiProx 5375 okuyucu (veya herhangi bir 12 V HID Prox® uzun menzilli okuyucu)
* ESP RFID Tool v2.2 (ESP32 tabanlı Wiegand dinleyici/kayıt aracı)
* 12 V @ ≥3 A müzakere edebilen USB-PD (Power-Delivery) tetikleme modülü
* 100 W USB-C powerbank (12 V PD profili çıkışı verir)
* 26 AWG silikon yalıtımlı bağlantı kablosu – kırmızı/beyaz
* Panele montajlı SPST açma-kapama anahtarı (buzzer devre dışı bırakma anahtarı için)
* NKK AT4072 anahtar koruması / kazara çalışmayı önleyen kapak
* Havya, lehim fitili ve lehim sökme pompası
* ABS ile kullanıma uygun el aletleri: kıl testere, maket bıçağı, düz ve yarım yuvarlak eğeler
* 1/16″ (1,5 mm) ve 1/8″ (3 mm) matkap uçları
* 3 M VHB çift taraflı bant ve kablo bağları

## 1. Güç Alt Sistemi

1. Mantık PCB’sine 5 V sağlamak için kullanılan fabrika tipi buck dönüştürücü ek kartını lehimini sökerek çıkarın.
2. USB-PD tetikleyicisini ESP RFID Tool’un yanına monte edin ve tetikleyicinin USB-C yuvasını kasanın dışına çıkarın.
3. PD tetikleyicisi powerbank’ten 12 V alır ve bunu doğrudan MaxiProx’a iletir (okuyucu doğal olarak 10–14 V bekler). Aksesuarları beslemek için ESP kartından ikincil bir 5 V hattı alınır.
4. RF performansını korumak için 100 W pil paketi, ferrit antenin üzerinden hiçbir güç kablosu geçmeyecek şekilde iç destek çıkıntısına sıfır oturacak biçimde yerleştirilir.

## 2. Buzzer Devre Dışı Bırakma Anahtarı – Sessiz Çalışma

1. MaxiProx mantık kartındaki iki hoparlör pedini bulun.
2. *Her iki* pedi de lehim fitiliyle temizleyin, ardından yalnızca **negatif** pedi yeniden lehimleyin.
3. Buzzer pedlerine 26 AWG kablolar (beyaz = negatif, kırmızı = pozitif) lehimleyin ve yeni açılan bir yuvadan geçirerek panele montajlı SPST anahtara bağlayın.
4. Anahtar açıkken buzzer devresi kesilir ve okuyucu tamamen sessiz çalışır; bu, gizlice kart toplamak için idealdir.
5. Anahtar kolunun üzerine yaylı NKK AT4072 güvenlik kapağını takın. Kapağın anahtar gövdesine geçerek oturacağı ölçüye ulaşana kadar deliği kıl testere/eğe ile dikkatlice genişletin. Koruma, anahtarın sırt çantasında kazara etkinleşmesini önler.

## 3. Kasa ve Mekanik İşlemler

• Büyük USB-C pilin iç destek çıkıntısına düz biçimde oturması için, içteki ABS “çıkıntıyı” yan keskiyle kesin; ardından bıçak ve eğeyle *çıkarın*.
• USB-C kablosu için kasa duvarında birbirine paralel iki kanal açın; bu, pili sabitler ve hareket etmesini/titreşmesini önler.
• Pilin **güç** düğmesi için dikdörtgen bir açıklık açın:
  1. Konumun üzerine kâğıt şablon bantlayın.
  2. Dört köşenin her birine 1/16″ kılavuz delikler açın.
  3. Delikleri 1/8″ uçla genişletin.
  4. Delikleri kıl testereyle birleştirin; kenarları eğeyle düzeltin.  
  ✱ Döner Dremel *kullanılmadı*; yüksek hızlı uç kalın ABS’yi eritir ve kenarları kötü bırakır.

## 4. Son Montaj

1. MaxiProx mantık kartını yeniden takın ve SMA pigtail kablosunu okuyucunun PCB toprak pedine yeniden lehimleyin.
2. ESP RFID Tool’u ve USB-PD tetikleyicisini 3 M VHB kullanarak monte edin.
3. Anten döngüsünden **uzakta** tutarak tüm kabloları kablo bağlarıyla düzenleyin.
4. Pil hafifçe sıkışana kadar kasa vidalarını sıkın; iç sürtünme, her kart okumasından sonra cihazın geri tepmesi sırasında pil paketinin kaymasını önler.

## 5. Menzil ve Kalkanlama Testleri

* 125 kHz **Pupa** test kartı kullanıldığında taşınabilir kopyalayıcı açık havada **≈ 8 cm** mesafede tutarlı okumalar yaptı; bu, şebeke elektriğiyle çalışırken elde edilen sonuçla aynıydı.<sup>[[1]](#references)</sup>
* Okuyucuyu ince duvarlı metal bir para kutusuna yerleştirmek (banka lobisindeki bir masayı taklit etmek için) menzili ≤ 2 cm’ye düşürdü. Bu, büyük metal muhafazaların etkili RF kalkanı işlevi gördüğünü doğruladı.<sup>[[1]](#references)</sup>

## Kullanım Akışı

1. USB-C pili şarj edin, bağlayın ve ana güç anahtarını açın.
2. (İsteğe bağlı) Tezgâhta test ederken sesli geri bildirimi etkinleştirmek için buzzer korumasını açın; sahada gizli kullanım öncesinde korumayı kapatıp kilitleyin.
3. Hedef kart sahibinin yanından geçin; MaxiProx kartı etkinleştirir ve ESP RFID Tool Wiegand akışını yakalar.
4. Yakalanan kimlik bilgilerini Wi-Fi veya USB-UART üzerinden dışarı aktarın ve gerektiği gibi yeniden oynatın/kopyalayın.

## Sorun Giderme

| Belirti | Olası Neden | Çözüm |
|---------|--------------|------|
| Kart okutulunca okuyucu yeniden başlıyor | PD tetikleyicisi 12 V yerine 9 V müzakere etti | Tetikleyici jumper’larını kontrol edin / daha yüksek güçlü bir USB-C kablosu deneyin |
| Okuma menzili yok | Pil veya kablolar antenin *üzerinde* duruyor | Kabloların yönünü değiştirin ve ferrit döngünün çevresinde 2 cm boşluk bırakın |
| Buzzer hâlâ ötüyor | Anahtar negatif yerine pozitif hatta bağlanmış | Devreyi **negatif** hoparlör hattından kesecek şekilde anahtarı taşıyın |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}