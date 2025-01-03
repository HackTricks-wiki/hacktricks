# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesinin Çalışma Şekli <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar için görünmezdir**. IR dalga boyu **0.7 ile 1000 mikron** arasındadır. Ev aletleri uzaktan kumandaları, veri iletimi için IR sinyali kullanır ve 0.75..1.4 mikron dalga boyu aralığında çalışır. Uzaktan kumandadaki bir mikrodenetleyici, dijital sinyali IR sinyaline dönüştürerek belirli bir frekansta bir kızılötesi LED'in yanıp sönmesini sağlar.

IR sinyallerini almak için bir **fotoreceiver** kullanılır. Bu, **IR ışığını voltaj darbelerine dönüştürür**, bu da zaten **dijital sinyallerdir**. Genellikle, alıcının içinde **karanlık ışık filtresi** bulunur; bu, **yalnızca istenen dalga boyunun geçmesine izin verir** ve gürültüyü keser.

### IR Protokollerinin Çeşitliliği <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokolleri 3 faktörde farklılık gösterir:

- bit kodlaması
- veri yapısı
- taşıyıcı frekansı — genellikle 36..38 kHz aralığında

#### Bit Kodlama Yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Darbe Mesafe Kodlaması**

Bitler, darbeler arasındaki boşluğun süresini modüle ederek kodlanır. Darbenin genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Darbe Genişliği Kodlaması**

Bitler, darbe genişliğinin modülasyonu ile kodlanır. Darbe patlamasından sonraki boşluğun genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Faz Kodlaması**

Aynı zamanda Manchester kodlaması olarak da bilinir. Mantıksal değer, darbe patlaması ile boşluk arasındaki geçişin polaritesi ile tanımlanır. "Boşluktan darbe patlamasına" mantık "0"ı, "darbe patlamasından boşluğa" mantık "1"i belirtir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotiklerin kombinasyonu**

> [!NOTE]
> Birkaç cihaz türü için **evrensel olmaya çalışan** IR protokolleri vardır. En ünlüleri RC5 ve NEC'dir. Ne yazık ki, en ünlü **en yaygın anlamına gelmez**. Benim çevremde sadece iki NEC uzaktan kumandası ve hiç RC5 uzaktan kumandası ile karşılaştım.
>
> Üreticiler, aynı cihaz aralığında bile kendi benzersiz IR protokollerini kullanmayı severler (örneğin, TV kutuları). Bu nedenle, farklı şirketlerden ve bazen aynı şirketin farklı modellerinden gelen uzaktan kumandalar, aynı türdeki diğer cihazlarla çalışamaz.

### Bir IR Sinyalini Keşfetmek

Uzaktan kumanda IR sinyalinin nasıl göründüğünü görmek için en güvenilir yol bir osiloskop kullanmaktır. Bu, alınan sinyali demodüle etmez veya tersine çevirmeden "olduğu gibi" gösterir. Bu, test ve hata ayıklama için faydalıdır. NEC IR protokolü örneğinde beklenen sinyali göstereceğim.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle, kodlanmış bir paketin başında bir önsöz bulunur. Bu, alıcının kazanç seviyesini ve arka planı belirlemesine olanak tanır. Ayrıca, örneğin, Sharp gibi önsözsüz protokoller de vardır.

Sonra veri iletilir. Yapı, önsöz ve bit kodlama yöntemi belirli protokol tarafından belirlenir.

**NEC IR protokolü**, bir kısa komut ve buton basılıyken gönderilen bir tekrar kodu içerir. Hem komut hem de tekrar kodu, başlangıçta aynı önsöze sahiptir.

NEC **komutu**, önsözün yanı sıra, cihazın ne yapılması gerektiğini anlaması için bir adres baytı ve bir komut numarası baytından oluşur. Adres ve komut numarası baytları, iletimin bütünlüğünü kontrol etmek için ters değerlerle çoğaltılır. Komutun sonunda ek bir durdurma biti vardır.

**Tekrar kodu**, önsözden sonra bir "1" içerir, bu bir durdurma bitidir.

**Mantık "0" ve "1"** için NEC, Darbe Mesafe Kodlaması kullanır: önce bir darbe patlaması iletilir, ardından bir duraklama gelir, duraklamanın uzunluğu bitin değerini belirler.

### Klima Cihazları

Diğer uzaktan kumandalardan farklı olarak, **klima cihazları yalnızca basılan butonun kodunu iletmez**. Ayrıca, **butona basıldığında tüm bilgileri iletir** ve böylece **klima makinesi ve uzaktan kumanda senkronize olur**.\
Bu, 20ºC olarak ayarlanmış bir makinenin bir uzaktan kumanda ile 21ºC'ye çıkarılmasını ve ardından hala 20ºC olarak ayarlanmış başka bir uzaktan kumanda ile sıcaklığın daha da artırılmaya çalışıldığında, "21ºC"ye (ve 21ºC'de olduğunu düşünerek 22ºC'ye değil) "arttırılmasını" önler.

### Saldırılar

Flipper Zero ile Kızılötesi'ye saldırabilirsiniz:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## Referanslar

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../banners/hacktricks-training.md}}
