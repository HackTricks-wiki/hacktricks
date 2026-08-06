# Kızılötesi

{{#include ../../banners/hacktricks-training.md}}

## Kızılötesi Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar tarafından görülemez**. IR dalga boyu **0,7 ile 1000 mikron** arasındadır. Ev tipi uzaktan kumandalar veri iletimi için IR sinyali kullanır ve 0,75..1,4 mikron dalga boyu aralığında çalışır. Uzaktan kumandadaki bir microcontroller, infrared LED'in belirli bir frekansta yanıp sönmesini sağlayarak dijital sinyali IR sinyaline dönüştürür.

IR sinyallerini almak için bir **photoreceiver** kullanılır. Bu bileşen **IR ışığını voltage pulse'larına dönüştürür**; bunlar zaten **digital signal'lerdir**. Genellikle receiver'ın içinde, **yalnızca istenen dalga boyunun geçmesine izin veren** ve paraziti kesen bir **dark light filter** bulunur.<sup>[[1]](#references)</sup>

### IR Protocol'lerinin Çeşitliliği <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocol'leri 3 faktöre göre farklılık gösterir:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — genellikle 36..38 kHz aralığında

#### Bit Encoding Yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bit'ler, pulse'lar arasındaki space süresinin modüle edilmesiyle encode edilir. Pulse'ın kendisinin genişliği sabittir.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bit'ler pulse genişliğinin modüle edilmesiyle encode edilir. Pulse burst sonrasındaki space'in genişliği sabittir.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Bu yöntem Manchester encoding olarak da bilinir. Logical value, pulse burst ile space arasındaki geçişin polarity'si tarafından belirlenir. "Space to pulse burst" logic "0" değerini, "pulse burst to space" ise logic "1" değerini belirtir.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotik yöntemlerin kombinasyonu**

> [!TIP]
> Birkaç cihaz türü için **universal olmaya çalışan** IR protocol'leri vardır. En ünlüleri RC5 ve NEC'tir. Ne yazık ki, en ünlü olmak **en yaygın olmak anlamına gelmez**. Benim çevremde yalnızca iki NEC uzaktan kumandasıyla karşılaştım ve hiç RC5 uzaktan kumandası görmedim.
>
> Üreticiler, aynı cihaz aralığı içinde bile (örneğin TV-box'lar) kendilerine özgü IR protocol'lerini kullanmayı sever. Bu nedenle farklı şirketlerin uzaktan kumandaları ve bazen aynı şirketin farklı modellerine ait uzaktan kumandalar, aynı türdeki diğer cihazlarla çalışamaz.

### Bir IR Sinyalini İncelemek

Uzaktan kumandanın IR sinyalinin nasıl göründüğünü anlamanın en güvenilir yolu oscilloscope kullanmaktır. Oscilloscope, alınan sinyali demodulate veya invert etmez; sinyal olduğu gibi görüntülenir. Bu, testing ve debugging için kullanışlıdır. NEC IR protocol'ü örneğinde beklenen sinyali göstereceğim.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle encoded packet'ın başında bir preamble bulunur. Bu, receiver'ın gain seviyesini ve arka planı belirlemesini sağlar. Örneğin Sharp gibi preamble içermeyen protocol'ler de vardır.

Daha sonra data iletilir. Structure, preamble ve bit encoding yöntemi belirli protocol tarafından belirlenir.

**NEC IR protocol'ü**, kısa bir command ve düğmeye basılı tutulduğu sırada gönderilen bir repeat code içerir. Hem command hem de repeat code, başlangıçta aynı preamble'a sahiptir.

NEC **command'ı**, preamble'a ek olarak, cihazın ne yapılması gerektiğini anlamasını sağlayan bir address byte ve command-number byte içerir. Transmission integrity'sini kontrol etmek için address ve command-number byte'ları inverse değerleriyle duplicate edilir. Command'ın sonunda ek bir stop bit bulunur.

**Repeat code**, preamble'dan sonra stop bit olan bir "1" içerir.

NEC, **logic "0" ve "1"** için Pulse Distance Encoding kullanır: önce bir pulse burst iletilir, ardından uzunluğu bit'in değerini belirleyen bir pause gelir.

### Klimalar

Diğer uzaktan kumandaların aksine, **klimalar yalnızca basılan düğmenin code'unu iletmez**. Ayrıca bir düğmeye basıldığında **tüm bilgileri de iletir**; bunun amacı **klima cihazı ile uzaktan kumandanın senkronize olmasını sağlamaktır**.\
Bu sayede 20ºC'ye ayarlanmış bir cihaz bir uzaktan kumandayla 21ºC'ye yükseltildikten sonra, sıcaklığı hâlâ 20ºC olarak tutan başka bir uzaktan kumandayla tekrar yükseltildiğinde, cihazın sıcaklığı 21ºC'ye "yükseltmesi" (21ºC'de olduğunu düşünerek 22ºC'ye değil) önlenmiş olur.<sup>[[1]](#references)</sup>

---

## Saldırılar ve Offensive Research <a href="#attacks" id="attacks"></a>

Infrared'a Flipper Zero ile saldırabilirsiniz:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Yakın tarihli academic work (EvilScreen, 2022), **Infrared'ı Bluetooth veya Wi-Fi ile birleştiren multi-channel uzaktan kumandaların modern smart-TV'leri tamamen hijack etmek için abuse edilebileceğini** gösterdi. Bu attack, yüksek ayrıcalıklı IR service code'larını authenticated Bluetooth packet'larıyla zincirleyerek channel-isolation'ı bypass eder ve physical access olmadan arbitrary app launch, microphone activation veya factory-reset yapılmasına olanak tanır. ISO/IEC 27001 uyumluluğu iddiasındaki bir Samsung modeli de dahil olmak üzere farklı vendor'lara ait sekiz mainstream TV'nin vulnerable olduğu doğrulandı. Mitigation için vendor firmware fix'leri veya kullanılmayan IR receiver'ların tamamen devre dışı bırakılması gerekir.<sup>[[2]](#references)</sup>

### IR LED'ler Üzerinden Air-Gapped Data Exfiltration (aIR-Jumper family)

Security camera'lar, router'lar ve hatta malicious USB stick'ler sıklıkla **night-vision IR LED'leri** içerir. Research, malware'in bu LED'leri modüle ederek (basit OOK ile <10–20 kbit/s) **duvarlar ve pencereler üzerinden, onlarca metre uzaklığa yerleştirilmiş harici bir camera'ya secret'ları exfiltrate edebileceğini** gösteriyor.<sup>[[3]](#references)</sup> Işık visible spectrum'un dışında olduğundan operator'ler bunu nadiren fark eder. Counter-measure'lar:

* Hassas alanlardaki IR LED'leri fiziksel olarak shield edin veya çıkarın
* Camera LED duty-cycle'ını ve firmware integrity'sini monitor edin
* Pencerelere ve surveillance camera'lara IR-cut filter'lar yerleştirin

Bir attacker, insecure camera'lara data flashing yaparak command'ları network'e **infiltrate etmek** için güçlü IR projector'lar da kullanabilir.

### Flipper Zero 1.0 ile Long-Range Brute-Force ve Extended Protocol'ler

Firmware 1.0 (September 2024), **düzinelerce ek IR protocol'ü ve isteğe bağlı harici amplifier module'lerini** ekledi. Universal-remote brute-force mode ile birlikte kullanıldığında Flipper, yüksek güçlü bir diode kullanarak 30 m'ye kadar mesafeden çoğu public TV/AC cihazını disable veya reconfigure edebilir.

---

## Tooling ve Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay ve dictionary-bruteforce mode'larına sahip portable transceiver (yukarıya bakın).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – düşük maliyetli DIY analyser/transmitter. `Arduino-IRremote` library'siyle birleştirin (v4.x >40 protocol'ü destekler).
* **Logic analyser'lar** (Saleae/FX2) – protocol bilinmediğinde raw timing'leri capture eder.
* **IR-blaster'lı smartphone'lar** (ör. Xiaomi) – hızlı field test için kullanışlıdır ancak range'i sınırlıdır.

### Software

* **`Arduino-IRremote`** – aktif olarak maintain edilen C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw capture'ları import eden, protocol'ü otomatik olarak identify eden ve Pronto/Arduino code'u oluşturan GUI decoder'lar.
* **LIRC / ir-keytable (Linux)** – command line üzerinden IR receive ve inject etmek için:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Gerekli olmadığında public space'lerde kullanılan cihazların IR receiver'larını disable edin veya üzerlerini kapatın.
* Smart-TV'ler ile uzaktan kumandalar arasında *pairing* veya cryptographic check'ler enforce edin; privileged "service" code'larını isolate edin.
* Classified area'ların çevresine IR-cut filter'lar veya continuous-wave detector'lar yerleştirerek optical covert channel'ları engelleyin.
* Controllable IR LED'lere sahip camera/IoT appliance'ların firmware integrity'sini monitor edin.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
