# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giriş

iButton, **madeni para şeklindeki metal bir kap** içinde paketlenmiş bir elektronik kimlik anahtarının genel adıdır. Aynı zamanda **Dallas Touch** Memory veya temas belleği olarak da adlandırılır. Sıklıkla “mıknatıslı” anahtar olarak yanlış bir şekilde anılsa da, içinde **mıknatıslı** hiçbir şey yoktur. Aslında, içinde dijital bir protokol üzerinde çalışan tam teşekküllü bir **mikroçip** gizlidir.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle, iButton anahtarın ve okuyucunun fiziksel formunu ifade eder - iki temas noktası olan yuvarlak bir madeni para. Etrafındaki çerçeve için, en yaygın delikli plastik tutucudan halkalar, kolyeler vb. olmak üzere birçok varyasyon vardır.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Anahtar okuyucuya ulaştığında, **temas noktaları birbirine değiyor** ve anahtar kimliğini **iletmek** için güç alıyor. Bazen anahtar **hemen okunmaz** çünkü bir interkomun **temas PSD'si olması gerekenden daha büyüktür**. Bu durumda, anahtarın dış konturları ve okuyucu birbirine değemez. Eğer durum buysa, anahtarı okuyucunun duvarlarından birinin üzerine basmanız gerekecek.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas anahtarları, 1-wire protokolünü kullanarak veri alışverişi yapar. Veri transferi için yalnızca bir temas noktası (!!) ile her iki yönde, anahtardan köleye ve tersine. 1-wire protokolü, Master-Slave modeline göre çalışır. Bu topolojide, Master her zaman iletişimi başlatır ve Slave onun talimatlarını takip eder.

Anahtar (Slave) interkomla (Master) temas ettiğinde, anahtarın içindeki çip açılır, interkom tarafından güçlendirilir ve anahtar başlatılır. Ardından interkom anahtar kimliğini talep eder. Şimdi bu süreci daha ayrıntılı inceleyeceğiz.

Flipper, hem Master hem de Slave modlarında çalışabilir. Anahtar okuma modunda, Flipper bir okuyucu olarak hareket eder, yani Master olarak çalışır. Anahtar taklit modunda ise, Flipper bir anahtar gibi davranır, Slave modundadır.

### Dallas, Cyfral & Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasını kontrol edin.

### Saldırılar

iButton'lar Flipper Zero ile saldırıya uğrayabilir:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referanslar

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
