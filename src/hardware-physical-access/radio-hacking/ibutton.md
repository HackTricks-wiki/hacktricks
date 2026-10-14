# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giriş

iButton, **madeni para şeklindeki metal bir muhafazaya** yerleştirilmiş elektronik bir kimlik anahtarı için kullanılan genel bir addır. Dallas Touch Memory veya kontak belleği olarak da adlandırılır. Sıklıkla yanlışlıkla “manyetik” bir anahtar olarak anılsa da içinde **manyetik hiçbir şey yoktur**. Aslında, dijital bir protokolle çalışan tam donanımlı bir **mikroçip** içinde gizlidir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton adı, dayanıklı madeni para şeklindeki paketi ve kontak düzenini tanımlar. Tutucular arasında plastik anahtarlıklar, yüzükler ve kolyeler bulunur.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Her iki kontak da okuyucuya temas ettiğinde cihaz güç alır ve veri alışverişi yapar. Girintili kontak geometrisi dış topraklama kontaklarının temas etmesini engelliyorsa, anahtarı okuyucu duvarına doğru eğmek teması yeniden sağlayabilir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim anahtarları 1-Wire protokolünü kullanır: Tek bir veri kontağı çift yönlü trafiği taşır ve aynı zamanda parazitik güç sağlayabilir; metal gövde ise dönüş kontağıdır. Denetleyici işlemleri başlatır ve cihaz yanıt verir.<sup>[[2]](#references)</sup>

Anahtar (Slave) interkom (Master) ile temas ettiğinde, interkomun sağladığı güçle anahtarın içindeki çip açılır ve anahtar başlatılır. Ardından interkom anahtarın kimliğini ister. Şimdi bu süreci daha ayrıntılı inceleyeceğiz.

Flipper, anahtar okurken denetleyici; kayıtlı bir kimliği okuyucuya sunarken ise emüle edilen cihaz olarak çalışabilir.<sup>[[1]](#references)</sup>

### Dallas, Cyfral ve Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasına bakın.<sup>[[1]](#references)</sup>

### Saldırılar

iButton'lara Flipper Zero ile saldırılabilir:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero ile iButton'ı evcilleştirmek](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Yazılım üzerinden 1-Wire iletişimi](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
