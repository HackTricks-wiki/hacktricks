# iButton

{{#include ../../banners/hacktricks-training.md}}

## Giriş

iButton, **bozuk para şeklindeki metal bir kapsül** içine yerleştirilmiş elektronik bir identification key için kullanılan genel bir addır. Ayrıca Dallas Touch Memory veya contact memory olarak da adlandırılır. Sıklıkla yanlış şekilde “manyetik” key olarak anılsa da içinde **manyetik hiçbir şey yoktur**. Aslında içerisinde dijital bir protokol üzerinden çalışan tam teşekküllü bir **microchip** gizlidir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton nedir? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Genellikle iButton, key'in ve okuyucunun fiziksel biçimini ifade eder: iki kontağı olan yuvarlak bir bozuk para. Key'i çevreleyen çerçeve için, delikli en yaygın plastik tutucudan halkalara, kolyelere ve benzerlerine kadar çok sayıda varyasyon bulunur.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Key okuyucuya ulaştığında, **kontaklar birbirine dokunur** ve key, ID'sini **iletmek** için güç alır. Bazen bir intercom'un **contact PSD'si olması gerekenden daha büyük** olduğu için key hemen **okunmaz**. Bu nedenle key'in ve okuyucunun dış hatları birbirine dokunamayabilir. Böyle bir durumda key'i okuyucunun duvarlarından birine bastırmanız gerekir.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protokolü** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas key'leri, 1-wire protokolünü kullanarak veri alışverişi yapar. Her iki yöndeki veri aktarımı için yalnızca tek bir data kontağı (!!) kullanılır; Master'dan Slave'e ve tersi yönde. 1-wire protokolü Master-Slave modeline göre çalışır. Bu topolojide iletişimi her zaman Master başlatır ve Slave, Master'ın talimatlarını izler.

Key (Slave) intercom'a (Master) temas ettiğinde, key'in içindeki chip intercom tarafından beslenerek açılır ve key initialize edilir. Bunun ardından intercom key'in ID'sini ister. Şimdi bu sürece daha ayrıntılı olarak bakacağız.

Flipper hem Master hem de Slave modlarında çalışabilir. Key okuma modunda Flipper, okuyucu gibi davranır; yani Master olarak çalışır. Key emulation modunda ise Flipper bir key gibi davranır ve Slave modundadır.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom key'leri

Bu key'lerin nasıl çalıştığı hakkında bilgi için [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) sayfasına bakın.<sup>[[1]](#references)</sup>

### Saldırılar

iButton'lara Flipper Zero ile saldırılabilir:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referanslar

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
