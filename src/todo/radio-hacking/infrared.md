# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesinin Çalışma Şekli <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar için görünmezdir**. IR dalga boyu **0.7 ile 1000 mikron** arasındadır. Ev aletleri uzaktan kumandaları, veri iletimi için IR sinyali kullanır ve 0.75..1.4 mikron dalga boyu aralığında çalışır. Uzaktan kumandadaki bir mikrodenetleyici, dijital sinyali IR sinyaline dönüştürmek için belirli bir frekansta bir kızılötesi LED'in yanıp sönmesini sağlar.

IR sinyallerini almak için bir **fotoreceiver** kullanılır. Bu, **IR ışığını voltaj darbelerine** dönüştürür, bu da zaten **dijital sinyallerdir**. Genellikle, alıcının içinde **karanlık ışık filtresi** bulunur, bu da **yalnızca istenen dalga boyunun geçmesine izin verir** ve gürültüyü keser.

### IR Protokollerinin Çeşitliliği <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokolleri 3 faktörde farklılık gösterir:

- bit kodlaması
- veri yapısı
- taşıyıcı frekansı — genellikle 36..38 kHz aralığında

#### Bit kodlama yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Darbe Mesafe Kodlaması**

Bitler, darbeler arasındaki boşluğun süresini modüle ederek kodlanır. Darbenin genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Darbe Genişliği Kodlaması**

Bitler, darbe genişliğinin modülasyonu ile kodlanır. Darbe patlamasından sonraki boşluğun genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Faz Kodlaması**

Aynı zamanda Manchester kodlaması olarak da bilinir. Mantıksal değer, darbe patlaması ile boşluk arasındaki geçişin polaritesi ile tanımlanır. "Boşluktan darbe patlamasına" mantık "0"ı, "darbe patlamasından boşluğa" mantık "1"i belirtir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin kombinasyonu ve diğer egzotik yöntemler**

> [!TIP]
> Birkaç tür cihaz için **evrensel olmaya çalışan** IR protokolleri vardır. En ünlüleri RC5 ve NEC'dir. Ne yazık ki, en ünlü **en yaygın anlamına gelmez**. Benim çevremde sadece iki NEC uzaktan kumandası ve hiç RC5 uzaktan kumandası ile karşılaştım.
>
> Üreticiler, aynı cihaz aralığında bile kendi benzersiz IR protokollerini kullanmayı severler (örneğin, TV kutuları). Bu nedenle, farklı şirketlerden ve bazen aynı şirketin farklı modellerinden gelen uzaktan kumandalar, aynı türdeki diğer cihazlarla çalışamaz.

### Bir IR sinyalini keşfetmek

Uzaktan kumanda IR sinyalinin nasıl göründüğünü görmek için en güvenilir yol bir osiloskop kullanmaktır. Bu, alınan sinyali demodüle etmez veya tersine çevirmeden "olduğu gibi" gösterir. Bu, test ve hata ayıklama için faydalıdır. NEC IR protokolü örneğinde beklenen sinyali göstereceğim.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle, kodlanmış bir paketin başında bir önsöz bulunur. Bu, alıcının kazanç seviyesini ve arka planı belirlemesine olanak tanır. Ayrıca, örneğin, Sharp gibi önsözsüz protokoller de vardır.

Daha sonra veri iletilir. Yapı, önsöz ve bit kodlama yöntemi belirli protokol tarafından belirlenir.

**NEC IR protokolü**, bir adres baytı ve cihazın ne yapması gerektiğini anladığı bir komut numarası baytından oluşan kısa bir komut ve basılı tutulan buton sırasında gönderilen bir tekrar kodu içerir. Hem komut hem de tekrar kodu, başlangıçta aynı önsöze sahiptir.

NEC **komutu**, önsözün yanı sıra, cihazın ne yapması gerektiğini anlaması için bir adres baytı ve bir komut numarası baytından oluşur. Adres ve komut numarası baytları, iletimin bütünlüğünü kontrol etmek için ters değerlerle çoğaltılır. Komutun sonunda ek bir durdurma biti vardır.

**Tekrar kodu**, önsözden sonra bir "1" içerir, bu bir durdurma bitidir.

**Mantık "0" ve "1"** için NEC, Darbe Mesafe Kodlaması kullanır: önce bir darbe patlaması iletilir, ardından bir duraklama gelir, duraklamanın uzunluğu bitin değerini belirler.

### Klima Cihazları

Diğer uzaktan kumandalardan farklı olarak, **klima cihazları yalnızca basılan butonun kodunu iletmez**. Ayrıca, **klima makinesi ve uzaktan kumandanın senkronize olduğunu sağlamak için** bir butona basıldığında tüm bilgileri **iletir**.\
Bu, 20ºC olarak ayarlanmış bir makinenin bir uzaktan kumanda ile 21ºC'ye çıkarılmasını ve ardından hala 20ºC olarak ayarlanmış başka bir uzaktan kumanda ile sıcaklığın daha da artırılmaya çalışıldığında, "21ºC"ye (ve 21ºC'de olduğunu düşünerek 22ºC'ye değil) "artırılmasını" önleyecektir.

---

## Saldırılar & Ofansif Araştırmalar <a href="#attacks" id="attacks"></a>

Flipper Zero ile Kızılötesi'ye saldırabilirsiniz:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Akıllı TV / Set-top Box Ele Geçirme (EvilScreen)

Son akademik çalışma (EvilScreen, 2022), **Kızılötesi ile Bluetooth veya Wi-Fi'yi birleştiren çok kanallı uzaktan kumandaların modern akıllı TV'leri tamamen ele geçirmek için kötüye kullanılabileceğini** göstermiştir. Saldırı, yüksek ayrıcalıklı IR hizmet kodlarını kimlik doğrulamalı Bluetooth paketleri ile birleştirerek kanal izolasyonunu aşar ve fiziksel erişim olmadan rastgele uygulama başlatmalarına, mikrofon aktivasyonuna veya fabrika ayarlarına sıfırlamaya olanak tanır. Farklı satıcılardan sekiz ana akım TV — ISO/IEC 27001 uyumunu iddia eden bir Samsung modeli dahil — savunmasız olduğu doğrulandı. Önlem almak, satıcı yazılımı düzeltmeleri gerektirir veya kullanılmayan IR alıcılarını tamamen devre dışı bırakmayı gerektirir.

### IR LED'leri ile Hava Boşluğu Veri Sızdırma (aIR-Jumper ailesi)

Güvenlik kameraları, yönlendiriciler veya hatta kötü niyetli USB bellekler genellikle **gece görüşü IR LED'leri** içerir. Araştırmalar, kötü amaçlı yazılımların bu LED'leri (<10–20 kbit/s basit OOK ile) **duvarlar ve pencereler aracılığıyla sırları dışarı sızdırmak için modüle edebileceğini** göstermektedir. Işık görünür spektrumun dışındadır, bu nedenle operatörler nadiren fark eder. Karşı önlemler:

* Hassas alanlarda IR LED'lerini fiziksel olarak koruyun veya çıkarın
* Kamera LED görev döngüsünü ve yazılım bütünlüğünü izleyin
* Pencerelerde ve gözetim kameralarında IR-kesme filtreleri kullanın

Bir saldırgan, **komutları** ağa sızdırmak için güçlü IR projektörleri kullanarak verileri güvensiz kameralara geri yansıtabilir.

### Uzun Menzilli Kaba Kuvvet & Genişletilmiş Protokoller ile Flipper Zero 1.0

Firmware 1.0 (Eylül 2024), **ekstra IR protokolleri ve isteğe bağlı harici amplifikatör modülleri** ekledi. Evrensel uzaktan kumanda kaba kuvvet moduyla birleştirildiğinde, Flipper, yüksek güçlü bir diyot kullanarak 30 m mesafeden çoğu kamu TV'sini/klima cihazını devre dışı bırakabilir veya yeniden yapılandırabilir.

---

## Araçlar & Pratik Örnekler <a href="#tooling" id="tooling"></a>

### Donanım

* **Flipper Zero** – öğrenme, tekrar oynatma ve sözlük kaba kuvvet modları ile taşınabilir verici alıcı.
* **Arduino / ESP32** + IR LED / TSOP38xx alıcı – ucuz DIY analizör/verici. `Arduino-IRremote` kütüphanesi ile birleştirin (v4.x >40 protokolü destekler).
* **Mantık analizörleri** (Saleae/FX2) – protokol bilinmediğinde ham zamanlamaları yakalar.
* **IR patlayıcıya sahip akıllı telefonlar** (örneğin, Xiaomi) – hızlı saha testi ancak sınırlı menzil.

### Yazılım

* **`Arduino-IRremote`** – aktif olarak bakımı yapılan C++ kütüphanesi:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Gücü
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – ham yakalamaları içe aktaran ve protokolü otomatik olarak tanımlayan GUI çözücüler + Pronto/Arduino kodu üreten.
* **LIRC / ir-keytable (Linux)** – komut satırından IR almak ve enjekte etmek:
```bash
sudo ir-keytable -p nec,rc5 -t   # canlı döküm çözülmüş tarama kodları
irsend SEND_ONCE samsung KEY_POWER
```

---

## Savunma Önlemleri <a href="#defense" id="defense"></a>

* Gerekmediğinde, kamu alanlarında dağıtılan cihazlardaki IR alıcılarını devre dışı bırakın veya kapatın.
* Akıllı TV'ler ile uzaktan kumandalar arasında *eşleştirme* veya kriptografik kontroller uygulayın; ayrıcalıklı "hizmet" kodlarını izole edin.
* Sınıflandırılmış alanlarda optik gizli kanalları kırmak için IR-kesme filtreleri veya sürekli dalga dedektörleri kullanın.
* Kontrol edilebilir IR LED'leri sergileyen kameraların/IoT cihazlarının yazılım bütünlüğünü izleyin.

## Referanslar

- [Flipper Zero Kızılötesi blog yazısı](https://blog.flipperzero.one/infrared/)
- EvilScreen: Uzaktan kumanda taklidi ile Akıllı TV ele geçirme (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
