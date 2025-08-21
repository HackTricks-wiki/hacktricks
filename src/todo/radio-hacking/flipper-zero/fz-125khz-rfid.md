# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

125kHz etiketlerin nasıl çalıştığı hakkında daha fazla bilgi için kontrol edin:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

Bu tür etiketler hakkında daha fazla bilgi için [**bu girişi okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Kart bilgisini **okumaya** çalışır. Sonra bunu **taklit** edebilir.

> [!WARNING]
> Bazı interkomların, okuma işleminden önce bir yazma komutu göndererek anahtar kopyalamaya karşı kendilerini korumaya çalıştığını unutmayın. Yazma başarılı olursa, o etiket sahte olarak kabul edilir. Flipper RFID'yi taklit ettiğinde, okuyucunun bunu orijinalinden ayırt etmesi için bir yolu yoktur, bu nedenle böyle bir sorun ortaya çıkmaz.

### Add Manually

Flipper Zero'da **verileri belirterek sahte kartlar oluşturabilirsiniz** ve ardından bunu taklit edebilirsiniz.

#### IDs on cards

Bazen, bir kart aldığınızda, kartın görünür kısmında ID'sinin (veya bir kısmının) yazılı olduğunu bulabilirsiniz.

- **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kartta **son 3'ü 5 baytın açık bir şekilde okunması** mümkündür.\
Diğer 2'si karttan okuyamazsanız brute-force ile bulunabilir.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Bu HID kartında da aynı durum geçerlidir; kartta yalnızca 3 bayttan 2'si basılı olarak bulunabilir.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Bir kartı **kopyaladıktan** veya ID'yi **manuel olarak** girdikten sonra, bunu Flipper Zero ile **taklit** etmek veya gerçek bir karta **yazmak** mümkündür.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
