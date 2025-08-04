# Taşınabilir HID MaxiProx 125 kHz Mobil Klonlayıcı Oluşturma

{{#include ../../banners/hacktricks-training.md}}

## Hedef
Ağ bağlantılı HID MaxiProx 5375 uzun menzilli 125 kHz okuyucusunu, fiziksel güvenlik değerlendirmeleri sırasında yakınlık kartlarını sessizce toplayan, sahada kullanılabilir, pil ile çalışan bir rozet klonlayıcıya dönüştürmek.

Burada ele alınan dönüşüm, TrustedSec’in “Let’s Clone a Cloner – Part 3: Putting It All Together” araştırma serisine dayanmaktadır ve son cihazın bir sırt çantasına atılıp hemen yerinde kullanılabilmesi için mekanik, elektriksel ve RF unsurlarını birleştirir.

> [!warning]
> Ağ bağlantılı ekipmanları ve Lityum-iyon güç bankalarını manipüle etmek tehlikeli olabilir. Devreyi enerjilendirmeden **önce** her bağlantıyı doğrulayın ve okuyucunun ayarını bozmasını önlemek için antenleri, koaksiyel kabloları ve toprak düzlemlerini fabrika tasarımındaki gibi tam olarak koruyun.

## Malzeme Listesi (BOM)

* HID MaxiProx 5375 okuyucu (veya herhangi bir 12 V HID Prox® uzun menzilli okuyucu)
* ESP RFID Tool v2.2 (ESP32 tabanlı Wiegand sniffer/logger)
* 12 V @ ≥3 A müzakere edebilen USB-PD (Güç Dağıtımı) tetik modülü
* 100 W USB-C güç bankası (12 V PD profili çıkışı)
* 26 AWG silikon yalıtımlı bağlantı kablosu – kırmızı/beyaz
* Panel montaj SPST anahtar (buzzer kapatma anahtarı için)
* NKK AT4072 anahtar koruyucu / kaza geçirmez kapak
* Lehimleme demiri, lehim bezi ve lehim sökme pompası
* ABS sınıfı el aletleri: coping testere, keski bıçağı, düz ve yarım yuvarlak dosyalar
* 1/16″ (1.5 mm) ve 1/8″ (3 mm) matkap uçları
* 3 M VHB çift taraflı bant ve Zip-taklar

## 1. Güç Alt Sistemi

1. Mantık PCB'si için 5 V üretmek üzere kullanılan fabrika buck-dönüştürücü alt kartını lehim sökerek çıkarın.
2. ESP RFID Tool'un yanına bir USB-PD tetik modülü monte edin ve tetik modülünün USB-C soketini muhafazanın dışına yönlendirin.
3. PD tetik modülü, güç bankasından 12 V müzakere eder ve bunu doğrudan MaxiProx'a besler (okuyucu doğal olarak 10–14 V bekler). Herhangi bir aksesuarı beslemek için ESP kartından ikinci bir 5 V hattı alınır.
4. 100 W pil paketi, iç standoff'a tam oturacak şekilde yerleştirilir, böylece ferrit antenin üzerinde **hiç** güç kablosu yoktur ve RF performansı korunur.

## 2. Buzzer Kapatma Anahtarı – Sessiz Çalışma

1. MaxiProx mantık kartındaki iki hoparlör padini bulun.
2. *Her iki* padin temizlenmesini sağlayın, ardından yalnızca **negatif** pad'i yeniden lehimleyin.
3. Buzzer padlerine 26 AWG kabloları (beyaz = negatif, kırmızı = pozitif) lehimleyin ve bunları yeni kesilmiş bir yarıktan panel montaj SPST anahtara yönlendirin.
4. Anahtar açıkken buzzer devresi kesilir ve okuyucu tamamen sessiz çalışır – gizli rozet toplama için idealdir.
5. Anahtarın üzerine NKK AT4072 yaylı güvenlik kapağını yerleştirin. Dikkatlice bir coping testere / dosya ile delik çapını büyütün, anahtar gövdesinin üzerine oturana kadar. Koruyucu, bir sırt çantası içinde kazara etkinleşmeyi önler.

## 3. Muhafaza ve Mekanik Çalışma

• İç ABS “şişkinliğini” *kaldırmak* için düz kesiciler, ardından bir bıçak ve dosya kullanın, böylece büyük USB-C pil düz bir şekilde standoff üzerinde otursun.
• USB-C kablosu için muhafaza duvarında iki paralel kanal açın; bu, pili yerinde kilitler ve hareket/titreşimi ortadan kaldırır.
• Pilin **güç** düğmesi için dikdörtgen bir açıklık oluşturun:
1. Konumun üzerine bir kağıt şablon yapıştırın.
2. Dört köşede 1/16″ pilot delikler açın.
3. 1/8″ uç ile büyütün.
4. Delikleri bir coping testere ile birleştirin; kenarları bir dosya ile bitirin.
✱  Yüksek hızlı uç kalın ABS'yi eritip çirkin bir kenar bıraktığı için bir döner Dremel *kaçınılmıştır*.

## 4. Son Montaj

1. MaxiProx mantık kartını yeniden takın ve SMA pigtail'i okuyucunun PCB toprak pad'ine yeniden lehimleyin.
2. ESP RFID Tool ve USB-PD tetik modülünü 3 M VHB kullanarak monte edin.
3. Tüm kabloları zip-taklarla düzenleyin, güç kablolarını anten halkasından **uzakta** tutun.
4. Muhafaza vidalarını sıkın, böylece pil hafifçe sıkışsın; iç sürtünme, cihaz her kart okuduktan sonra paketin kaymasını önler.

## 5. Menzil ve Kalkan Testleri

* 125 kHz **Pupa** test kartı kullanarak taşınabilir klonlayıcı, serbest havada **≈ 8 cm**'de tutarlı okumalar elde etti – ağ bağlantılı çalışmaya eşdeğer.
* Okuyucuyu ince duvarlı bir metal para kutusunun içine yerleştirmek (bir banka lobisi masası simüle etmek için) menzili ≤ 2 cm'ye düşürdü ve önemli metal muhafazaların etkili RF kalkanları olarak işlev gördüğünü doğruladı.

## Kullanım İş Akışı

1. USB-C pili şarj edin, bağlayın ve ana güç anahtarını çevirin.
2. (İsteğe bağlı) Buzzer koruyucusunu açın ve masa testinde sesli geri bildirim sağlayın; gizli saha kullanımı öncesinde kilitleyin.
3. Hedef rozet sahibinin yanından geçin – MaxiProx kartı enerjilendirecek ve ESP RFID Tool Wiegand akışını yakalayacaktır.
4. Yakalanan kimlik bilgilerini Wi-Fi veya USB-UART üzerinden dökün ve gerektiğinde tekrar oynatın/klonlayın.

## Sorun Giderme

| Belirti | Olası Sebep | Çözüm |
|---------|--------------|------|
| Kart sunulduğunda okuyucu yeniden başlatılıyor | PD tetik 9 V müzakere etti, 12 V değil | Tetik jumper'larını doğrulayın / daha yüksek güçte USB-C kablosu deneyin |
| Okuma menzili yok | Pil veya kablolar antenin *üzerinde* duruyor | Kabloları yeniden yönlendirin ve ferrit halkası etrafında 2 cm boşluk bırakın |
| Buzzer hala ötüyor | Anahtar pozitif hat üzerinde bağlanmış, negatif yerine | Kapatma anahtarını **negatif** hoparlör izini kesmek için taşıyın |

## Referanslar

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
