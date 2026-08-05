# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giriş

iButton, **madeni para şeklindeki metal bir muhafazaya** yerleştirilmiş elektronik bir kimlik anahtarı için kullanılan genel bir addır. Ayrıca Dallas Touch Memory veya contact memory olarak da adlandırılır. Genellikle yanlışlıkla “manyetik” anahtar olarak anılsa da içinde **manyetik hiçbir şey yoktur**. Aslında içinde dijital bir protokol üzerinden çalışan tam teşekküllü bir **mikroçip** gizlidir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle iButton, anahtarın ve okuyucunun fiziksel biçimini ifade eder - iki temas noktası bulunan yuvarlak bir madeni para. Anahtarı çevreleyen çerçeve için, delikli en yaygın plastik tutucudan halkalara, kolyelere vb. pek çok farklı seçenek vardır.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Anahtar okuyucuya ulaştığında **temas noktaları birbirine dokunur** ve anahtara **kimliğini iletmesi** için güç verilir. Bazen **intercom'un temas PSD'si olması gerekenden daha büyük** olduğu için anahtar **hemen okunmaz**. Bu nedenle anahtarın ve okuyucunun dış hatları birbirine dokunamaz. Durum buysa anahtarı okuyucunun duvarlarından birine bastırmanız gerekir.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas anahtarları, 1-wire protokolünü kullanarak veri alışverişi yapar. Her iki yöndeki veri aktarımı için - master'dan slave'e ve tersi yönde - yalnızca bir veri temas noktası (!!) kullanılır. 1-wire protokolü Master-Slave modeline göre çalışır. Bu topolojide Master iletişimi her zaman başlatır ve Slave onun talimatlarını izler.

Anahtar (Slave) intercom'a (Master) temas ettiğinde, anahtarın içindeki çip intercom tarafından sağlanan güçle açılır ve anahtar başlatılır. Bunun ardından intercom anahtarın kimliğini ister. Şimdi bu sürece daha ayrıntılı olarak bakacağız.

Flipper hem Master hem de Slave modlarında çalışabilir. Anahtar okuma modunda Flipper bir okuyucu gibi davranır; yani Master olarak çalışır. Anahtar emülasyonu modunda ise Flipper anahtar gibi davranır ve Slave modundadır.

### Dallas, Cyfral ve Metakom anahtarları

Bu anahtarların nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasına bakın.<sup>[[1]](#references)</sup>

### Saldırılar

iButton'lara Flipper Zero ile saldırılabilir:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referanslar

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
