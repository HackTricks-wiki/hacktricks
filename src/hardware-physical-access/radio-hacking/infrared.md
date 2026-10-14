# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesi Bağlantı Noktası Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar tarafından görülemez**. Kızılötesi dalga boyu **0,7 ile 1000 mikron** arasındadır. Ev tipi uzaktan kumandalar veri iletimi için kızılötesi sinyal kullanır ve 0,75..1,4 mikron dalga boyu aralığında çalışır. Uzaktan kumandadaki bir mikrodenetleyici, kızılötesi LED'in belirli bir frekansta yanıp sönmesini sağlayarak dijital sinyali kızılötesi sinyale dönüştürür.

Kızılötesi sinyalleri almak için **fot alıcı** kullanılır. Bu alıcı, **kızılötesi ışığı gerilim darbelerine dönüştürür**; bunlar zaten **dijital sinyallerdir**. Alıcının içinde genellikle **koyu renkli bir optik filtre** bulunur. Bu filtre, **yalnızca istenen dalga boyunun geçmesine izin verir** ve paraziti engeller.<sup>[[1]](#references)</sup>

### Kızılötesi Protokol Çeşitliliği <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Kızılötesi protokolleri 3 faktöre göre farklılık gösterir:<sup>[[1]](#references)</sup>

- bit kodlama
- veri yapısı
- taşıyıcı frekansı — genellikle 36..38 kHz aralığındadır

#### Bit kodlama yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Darbe Mesafesi Kodlaması**

Bitler, darbeler arasındaki boşluğun süresi değiştirilerek kodlanır. Darbenin kendisinin genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Darbe Genişliği Kodlaması**

Bitler, darbe genişliği değiştirilerek kodlanır. Darbe dizisinden sonraki boşluğun genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Faz Kodlaması**

Manchester kodlaması olarak da bilinir. Mantıksal değer, darbe dizisi ile boşluk arasındaki geçişin polaritesiyle belirlenir. "Boşluktan darbe dizisine" geçiş mantıksal "0"ı, "darbe dizisinden boşluğa" geçiş mantıksal "1"i belirtir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer sıra dışı yöntemlerin birleşimi**

> [!TIP]
> Birkaç cihaz türünde **evrensel olmaya çalışan** kızılötesi protokolleri vardır. En bilinenleri RC5 ve NEC'dir. Ne yazık ki, en bilinen **en yaygın olan demek değildir**. Kendi ortamımda yalnızca iki NEC uzaktan kumandayla karşılaştım, RC5 kullananlara ise hiç rastlamadım.
>
> Üreticiler, aynı cihaz grubunda (örneğin, TV kutuları) bile kendi benzersiz kızılötesi protokollerini kullanmayı sever. Bu nedenle, farklı şirketlerin ve bazen aynı şirketin farklı modellerinin uzaktan kumandaları, aynı türdeki diğer cihazlarla çalışamaz.

### Kızılötesi Sinyali İnceleme

Uzaktan kumandanın kızılötesi sinyalinin nasıl göründüğünü görmenin en güvenilir yolu bir osiloskop kullanmaktır. Osiloskop alınan sinyali demodüle etmez veya tersine çevirmez; sinyal yalnızca "olduğu gibi" görüntülenir. Bu, test ve hata ayıklama için kullanışlıdır. Beklenen sinyali NEC kızılötesi protokolü örneği üzerinden göstereceğim.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kodlanmış paketin başında genellikle bir önsöz bulunur. Bu, alıcının kazanç seviyesini ve arka planı belirlemesini sağlar. Örneğin Sharp gibi önsöz kullanmayan protokoller de vardır.

Ardından veri iletilir. Yapı, önsöz ve bit kodlama yöntemi kullanılan protokole bağlıdır.

**NEC kızılötesi protokolü**, kısa bir komut ve düğmeye basılı tutulduğu sürece gönderilen bir tekrar kodu içerir. Hem komutun hem de tekrar kodunun başında aynı önsöz bulunur.

NEC **komutu**, önsözün yanı sıra bir adres baytı ve cihazın ne yapması gerektiğini anlamasını sağlayan bir komut numarası baytından oluşur. İletimin bütünlüğünü denetlemek için adres ve komut numarası baytları ters değerleriyle tekrarlanır. Komutun sonunda ek bir dur biti bulunur.

**Tekrar kodunda**, önsözden sonra dur biti olan bir "1" bulunur.

NEC, **mantıksal "0" ve "1"** için Darbe Mesafesi Kodlaması kullanır: önce bir darbe dizisi iletilir, ardından bir duraklama gelir; bu duraklamanın uzunluğu bitin değerini belirler.

### Klimalar

Diğer uzaktan kumandalardan farklı olarak **klimalar yalnızca basılan düğmenin kodunu iletmez**. Bir düğmeye basıldığında **tüm bilgileri de iletirler**. Böylece **klima ve uzaktan kumanda senkronize kalır**.\
Bu sayede, 20ºC'ye ayarlanmış bir klimanın sıcaklığı bir uzaktan kumandayla 21ºC'ye yükseltildikten sonra, sıcaklığı hâlâ 20ºC olarak gösteren başka bir uzaktan kumandayla tekrar yükseltilmeye çalışıldığında sıcaklık 22ºC yerine yanlışlıkla 21ºC'ye "yükseltilmez".<sup>[[1]](#references)</sup>

---

## Saldırılar ve Ofansif Araştırmalar <a href="#attacks" id="attacks"></a>

Flipper Zero ile kızılötesine saldırabilirsiniz:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Ele Geçirme (EvilScreen)

Yakın tarihli bir akademik çalışma (EvilScreen, 2022), kızılötesini Bluetooth veya Wi-Fi ile birleştiren **çok kanallı uzaktan kumandaların modern smart-TV'leri tamamen ele geçirmek için kötüye kullanılabileceğini** gösterdi. Saldırı, yüksek ayrıcalıklı kızılötesi servis kodlarını kimliği doğrulanmış Bluetooth paketleriyle zincirleyerek kanal yalıtımını atlatır ve fiziksel erişim olmadan herhangi bir uygulamanın başlatılmasına, mikrofonun etkinleştirilmesine veya fabrika ayarlarına sıfırlamaya olanak tanır. ISO/IEC 27001 uyumluluğu iddiasında bulunan bir Samsung modeli de dahil olmak üzere, farklı üreticilere ait sekiz yaygın TV'nin savunmasız olduğu doğrulandı. Bu açığı gidermek için üreticilerin firmware düzeltmeleri yapması veya kullanılmayan kızılötesi alıcıları tamamen devre dışı bırakması gerekir.<sup>[[2]](#references)</sup>

### IR LED'ler Üzerinden Air-Gapped Veri Sızdırma (aIR-Jumper ailesi)

Güvenlik kameralarında genellikle **gece görüşü için kızılötesi LED'ler** bulunur. aIR-Jumper prototipi, bu LED'leri kontrol eden malware'in **pencereler üzerinden dışarıdaki bir kameraya sırları sızdırabildiğini** gösterdi. Her güvenlik kamerası için onlarca metre mesafeden **20 bit/s** hıza ulaşılabiliyordu. Ters yönde ise araştırmacılar, yüzlerce metreden kilometrelere uzanan mesafelerde **100 bit/s'den yüksek** hızda veri sızdırmayı gösterdi.<sup>[[3]](#references)</sup> Işık görünür spektrumun dışında olduğundan, operatörler bunu fark etmeyebilir. Karşı önlemler şunları içerir:

* Hassas alanlardaki IR LED'leri fiziksel olarak koruyun veya çıkarın
* Kamera LED'lerinin görev döngüsünü ve firmware bütünlüğünü izleyin
* Pencerelere ve güvenlik kameralarına IR kesici filtreler takın

Bir saldırgan, güvenli olmayan kameralara veri göndererek ağa komut **sızdırmak** için güçlü IR projektörleri de kullanabilir.

### Flipper Zero 1.0 ile Uzun Menzilli Brute-Force ve Genişletilmiş Protokoller

Firmware 1.0 (Eylül 2024), evrensel uzaktan kumanda kütüphanesini genişletti ve microSD'den kızılötesi varlık dosyalarının dinamik olarak yüklenmesini ekledi.<sup>[[4]](#references)</sup> Öğrenme ve evrensel uzaktan kumanda işlevleri, yakındaki TV'lere ve klimalara karşı bilinen komutları yeniden oynatabilir veya deneyebilir. Menzil; yayıcıya, optiğe, ortam ışığına ve alıcıya büyük ölçüde bağlıdır. Harici IR donanımı bu menzili artırabilir, ancak sabit bir mesafe varsayılmamalıdır.

---

## Araçlar ve Pratik Örnekler <a href="#tooling" id="tooling"></a>

### Donanım

* **Flipper Zero** – öğrenme, yeniden oynatma ve sözlük brute-force modlarına sahip taşınabilir alıcı-verici (yukarıya bakın).
* **Arduino / ESP32** + IR LED / TSOP38xx alıcısı – düşük maliyetli, kendin yap analizör/verici. `Arduino-IRremote` kütüphanesiyle birleştirin (v4.x, 40'tan fazla protokolü destekler).
* **Mantık analizörleri** (Saleae/FX2) – protokol bilinmediğinde ham zamanlamaları yakalar.
* **IR blaster özellikli akıllı telefonlar** (ör. Xiaomi) – sahada hızlı test için uygundur ancak menzilleri sınırlıdır.

### Yazılım

* **`Arduino-IRremote`** – aktif olarak bakımı yapılan C++ kütüphanesi:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – Ham yakalamaları içe aktaran, protokolü otomatik tanımlayan ve Pronto/Arduino kodu oluşturan GUI decoder'ları.
* **LIRC / ir-keytable (Linux)** – Komut satırından IR alma ve gönderme:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Savunma Önlemleri <a href="#defense" id="defense"></a>

* Gerekli olmadığında halka açık alanlardaki cihazların IR alıcılarını devre dışı bırakın veya üzerlerini kapatın.
* Smart TV'ler ile uzaktan kumandalar arasında *eşleştirme* veya kriptografik kontroller uygulayın; ayrıcalıklı “servis” kodlarını yalıtın.
* Optik covert channel'ları kesmek için gizli alanların çevresine IR-cut filtreleri veya sürekli dalga dedektörleri yerleştirin.
* Kontrol edilebilir IR LED'leri olan kamera/IoT cihazlarının firmware bütünlüğünü izleyin.

## References

- [1] [Flipper Zero Kızılötesi blog yazısı](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Çok Kanallı Uzaktan Kumanda Taklidiyle Smart TV Ele Geçirme (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Güvenlik Kameraları ve Kızılötesi (IR) Üzerinden Gizli Air-Gap Veri Sızdırma/İçeri Sızma (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Yayımlandı](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - kullanım ve protokol belgeleri](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
