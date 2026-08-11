# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giriş

iButton, **madeni para şeklindeki metal bir muhafazaya** yerleştirilmiş elektronik bir kimlik anahtarı için kullanılan genel bir addır. Ayrıca Dallas Touch Memory veya contact memory olarak da adlandırılır. Sıklıkla yanlışlıkla “manyetik” bir anahtar olarak anılsa da içinde **hiçbir manyetik unsur** bulunmaz. Aslında içinde dijital bir protokol üzerinden çalışan tam teşekküllü bir **microchip** gizlidir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton adı, dayanıklı madeni para şeklindeki muhafazayı ve kontak düzenini ifade eder. Taşıyıcılar arasında plastik anahtarlıklar, yüzükler ve kolyeler bulunur.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Her iki kontak okuyucuya temas ettiğinde cihaz güç alır ve veri alışverişi yapar. Girintili kontak geometrisi dış toprak kontaklarının birbirine temas etmesini engelliyorsa anahtarı okuyucunun duvarına doğru eğmek teması yeniden sağlayabilir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim anahtarları 1-Wire protocol kullanır: bir veri kontağı çift yönlü trafiği taşır ve parazitik güç de sağlayabilir; metal muhafaza ise dönüş kontağıdır. Controller işlemleri başlatır ve cihaz yanıt verir.<sup>[[2]](#references)</sup>

Anahtar (Slave) intercom'a (Master) temas ettiğinde anahtarın içindeki chip intercom tarafından beslenerek açılır ve anahtar başlatılır. Ardından intercom anahtar ID'sini ister. Şimdi bu sürece daha ayrıntılı olarak bakacağız.

Flipper, bir anahtarı okurken controller olarak ve kayıtlı bir identifier'ı okuyucuya sunarken emulated device olarak çalışabilir.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom keys

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasına bakın.<sup>[[1]](#references)</sup>

### Saldırılar

iButton'lara Flipper Zero ile saldırılabilir:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Flipper Zero ile iButton'ı evcilleştirme](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — yazılım üzerinden 1-Wire iletişimi](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
