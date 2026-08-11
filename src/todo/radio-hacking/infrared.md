# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesi Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar tarafından görülemez**. IR dalga boyu **0,7 ile 1000 mikron** arasındadır. Ev tipi kumandalar veri iletimi için IR sinyali kullanır ve 0,75..1,4 mikron dalga boyu aralığında çalışır. Kumandadaki bir microcontroller, infrared LED'i belirli bir frekansta yanıp sönecek şekilde çalıştırarak dijital sinyali IR sinyaline dönüştürür.

IR sinyallerini almak için bir **photoreceiver** kullanılır. Bu bileşen **IR ışığını, zaten **digital signals** olan gerilim darbelerine dönüştürür**. Genellikle alıcının içinde, **yalnızca istenen dalga boyunun geçmesine izin veren** ve gürültüyü kesen bir **dark light filter** bulunur.<sup>[[1]](#references)</sup>

### IR Protocols Çeşitliliği <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocols 3 faktörde farklılık gösterir:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — genellikle 36..38 kHz aralığında

#### Bit encoding yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bitler, darbeler arasındaki boşluğun süresi modüle edilerek kodlanır. Darbenin genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bitler, darbe genişliği modüle edilerek kodlanır. Darbe kümesinden sonraki boşluğun genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Bu yöntem Manchester encoding olarak da bilinir. Mantıksal değer, darbe kümesi ile boşluk arasındaki geçişin polaritesiyle belirlenir. "Space to pulse burst" logic "0", "pulse burst to space" ise logic "1" anlamına gelir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotik yöntemlerin kombinasyonu**

> [!TIP]
> Birden fazla cihaz türü için **universal olmaya çalışan** IR protocols vardır. En ünlüleri RC5 ve NEC'tir. Ne yazık ki, en ünlü olanın **en yaygın olduğu anlamına gelmez**. Benim çevremde yalnızca iki NEC kumandasıyla karşılaştım ve hiç RC5 kumandası görmedim.
>
> Üreticiler, aynı cihaz aralığı içinde bile (örneğin TV-boxes) kendi benzersiz IR protocols'larını kullanmayı sever. Bu nedenle farklı şirketlerin kumandaları ve bazen aynı şirketin farklı modellerine ait kumandalar, aynı türdeki diğer cihazlarla çalışamaz.

### Bir IR sinyalini inceleme

Kumandanın IR sinyalinin nasıl göründüğünü anlamanın en güvenilir yolu oscilloscope kullanmaktır. Alınan sinyali demodüle veya tersine çevirmez; yalnızca sinyali "olduğu gibi" görüntüler. Bu, test ve debugging için kullanışlıdır. NEC IR protocol örneği üzerinden beklenen sinyali göstereceğim.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle kodlanmış bir paketin başlangıcında bir preamble bulunur. Bu, alıcının gain seviyesini ve arka planı belirlemesini sağlar. Örneğin Sharp gibi preamble içermeyen protocols da vardır.

Ardından data iletilir. Yapı, preamble ve bit encoding yöntemi belirli protocol tarafından belirlenir.

**NEC IR protocol**, kısa bir command ve düğmeye basılı tutulduğu sürece gönderilen bir repeat code içerir. Hem command hem de repeat code başlangıçta aynı preamble'a sahiptir.

NEC **command**, preamble'a ek olarak, cihazın ne yapılması gerektiğini anlamasını sağlayan bir address byte ve command-number byte içerir. İletimin bütünlüğünü kontrol etmek için address ve command-number byte'ları ters değerleriyle birlikte yinelenir. Command'ın sonunda ek bir stop bit bulunur.

**Repeat code**, preamble'dan sonra stop bit olan bir "1" içerir.

**Logic "0" ve "1"** için NEC, Pulse Distance Encoding kullanır: önce bir pulse burst gönderilir, ardından uzunluğu bitin değerini belirleyen bir duraklama gelir.

### Air Conditioners

Diğer kumandalardan farklı olarak **air conditioners yalnızca basılan düğmenin code'unu göndermez**. Ayrıca **tüm bilgileri de gönderir**; böylece **air conditioned machine ile kumandanın senkronize olması** sağlanır.\
Bu, 20ºC'ye ayarlanmış bir machine'in bir kumandayla 21ºC'ye çıkarılmasını ve ardından sıcaklığı hâlâ 20ºC olarak tutan başka bir kumanda kullanıldığında, bu kumandanın sıcaklığı 21ºC'ye "çıkarmasını" (21ºC'de olduğunu düşünerek 22ºC'ye değil) önler.<sup>[[1]](#references)</sup>

---

## Saldırılar ve Offensive Research <a href="#attacks" id="attacks"></a>

Infrared'a Flipper Zero ile saldırabilirsiniz:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Yakın tarihli academic work (EvilScreen, 2022), **Infrared'ı Bluetooth veya Wi-Fi ile birleştiren multi-channel remotes cihazlarının modern smart-TV'leri tamamen ele geçirmek için kötüye kullanılabileceğini** gösterdi. Saldırı, yüksek ayrıcalıklı IR service code'larını authenticated Bluetooth packets ile birlikte kullanarak channel-isolation'ı atlar ve fiziksel erişim olmadan arbitrary app launch'larına, microphone activation'a veya factory-reset işlemine izin verir. Farklı vendor'lara ait, ISO/IEC 27001 uyumluluğu iddiasındaki bir Samsung modeli de dahil olmak üzere sekiz mainstream TV'nin vulnerable olduğu doğrulandı. Mitigation için vendor firmware fixes uygulanması veya kullanılmayan IR receivers'ların tamamen devre dışı bırakılması gerekir.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration via IR LEDs (aIR-Jumper family)

Security cameras genellikle **night-vision IR LEDs** içerir. aIR-Jumper prototype, bu LED'leri kontrol eden malware'in pencereler üzerinden, onlarca metre mesafedeki harici bir camera'ya, **surveillance camera başına saniyede 20 bit'e kadar** secret exfiltration yapabildiğini gösterdi. Ters yönde researchers, yüzlerce metre ile kilometre arasındaki mesafelerde **saniyede 100 bit'ten daha yüksek** hızlarda infiltration gerçekleştirdi.<sup>[[3]](#references)</sup> Işık görünür spectrum dışında olduğundan operators bunu fark etmeyebilir. Countermeasures şunları içerir:

* Hassas alanlardaki IR LEDs'leri fiziksel olarak shield edin veya çıkarın
* Camera LED duty-cycle ve firmware integrity'yi monitor edin
* Pencerelere ve surveillance cameras'a IR-cut filters yerleştirin

Bir attacker, insecure cameras'a data flashing yoluyla network'e commands **infiltrate** etmek için güçlü IR projectors da kullanabilir.

### Long-Range Brute-Force ve Flipper Zero 1.0 ile Extended Protocols

Firmware 1.0 (September 2024), universal-remotes library'yi genişletti ve infrared asset files'ın microSD'den dynamic loading özelliğini ekledi.<sup>[[4]](#references)</sup> Learning ve universal-remote işlevleri, yakındaki TVs ve air conditioners'a bilinen commands'ları replay edebilir veya deneyebilir. Menzil; emitter, optics, ambient light ve receiver'a büyük ölçüde bağlıdır; external IR hardware menzili artırabilir, ancak sabit bir mesafe varsayılmamalıdır.

---

## Tooling ve Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay ve dictionary-bruteforce modes özelliklerine sahip portable transceiver (yukarıya bakın).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – ucuz DIY analyser/transmitter. `Arduino-IRremote` library ile birleştirin (v4.x, 40'tan fazla protocol destekler).
* **Logic analysers** (Saleae/FX2) – protocol bilinmediğinde raw timings yakalar.
* **IR-blaster içeren smartphones** (ör. Xiaomi) – hızlı field test için uygundur, ancak menzili sınırlıdır.

### Software

* **`Arduino-IRremote`** – aktif olarak sürdürülen C++ library:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw captures içe aktaran, protocol'ü otomatik olarak belirleyen ve Pronto/Arduino code üreten GUI decoders.
* **LIRC / ir-keytable (Linux)** – command line üzerinden IR alır ve inject eder:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Gerekmiyorsa public spaces'a yerleştirilen devices üzerindeki IR receivers'ları devre dışı bırakın veya kapatın.
* Smart-TVs ve remotes arasında *pairing* veya cryptographic checks zorunlu kılın; ayrıcalıklı "service" codes'ları izole edin.
* Optical covert channels'ı kesmek için classified areas çevresine IR-cut filters veya continuous-wave detectors yerleştirin.
* Controllable IR LEDs sunan cameras/IoT appliances'ın firmware integrity'sini monitor edin.

## References

- [1] [Flipper Zero Infrared blog yazısı](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Multi-channel Remote Control Mimicry üzerinden Smart TV Hijacking](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Security Cameras ve Infrared (IR) üzerinden Covert Air-Gap Exfiltration/Infiltration](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero Blog - Firmware 1.0 Released](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - kullanım ve protocol documentation](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
