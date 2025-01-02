# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Giriş

125kHz etiketlerinin nasıl çalıştığı hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Eylemler

Bu tür etiketler hakkında daha fazla bilgi için [**bu girişi okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Oku

Kart bilgisini **okumaya** çalışır. Sonra bunları **taklit** edebilir.

> [!WARNING]
> Bazı interkomların, okumadan önce bir yazma komutu göndererek anahtar kopyalamaktan kendilerini korumaya çalıştığını unutmayın. Yazma başarılı olursa, o etiket sahte olarak kabul edilir. Flipper RFID'yi taklit ettiğinde, okuyucunun bunu orijinalinden ayırt etmesi için bir yol yoktur, bu nedenle böyle bir sorun ortaya çıkmaz.

### Manuel Ekle

Verileri manuel olarak belirterek Flipper Zero'da **sahte kartlar oluşturabilirsiniz** ve ardından bunu taklit edebilirsiniz.

#### Kartlardaki Kimlikler

Bazen, bir kart aldığınızda, kartta görünür şekilde yazılı olan kimliği (veya bir kısmını) bulacaksınız.

- **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kartta **son 3'ü 5 baytın açık bir şekilde okunması mümkündür**.\
Diğer 2'si karttan okuyamazsanız brute-force ile bulunabilir.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Bu HID kartında da aynı durum geçerlidir; burada yalnızca 3 bayttan 2'si kartta basılı olarak bulunabilir.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Taklit/Yaz

Bir kartı **kopyaladıktan** veya kimliği **manuel olarak girdikten** sonra, bunu Flipper Zero ile **taklit etmek** veya gerçek bir karta **yazmak** mümkündür.

## Referanslar

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
