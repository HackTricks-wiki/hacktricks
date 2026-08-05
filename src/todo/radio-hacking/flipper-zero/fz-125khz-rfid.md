# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Giriş

125kHz tag'lerin nasıl çalıştığı hakkında daha fazla bilgi için:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## İşlemler

Bu tür tag'ler hakkında daha fazla bilgi için [**bu girişi okuyun**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Oku

Kart bilgilerini **okumayı** dener. Ardından bunları **emüle** edebilir.<sup>[[1]](#references)</sup>

> [!WARNING]
> Bazı intercom'ların, yazma komutu göndermeden önce okumayı engelleyerek kendilerini key duplication'a karşı korumaya çalıştığını unutmayın. Yazma başarılı olursa bu tag sahte kabul edilir. Flipper RFID'i emüle ettiğinde okuyucunun onu orijinalden ayırt etmesinin bir yolu yoktur; bu nedenle böyle bir sorun oluşmaz.

### Manuel Olarak Ekle

Verileri manuel olarak belirterek Flipper Zero'da **sahte kartlar oluşturabilir** ve ardından bunları emüle edebilirsiniz.

#### Kartlardaki ID'ler

Bazen bir kart aldığınızda, kartın ID'sinin (veya bir kısmının) üzerinde görünür şekilde yazılı olduğunu görürsünüz.

- **EM Marin**

Örneğin, bu EM-Marin kartında fiziksel kart üzerindeki 5 byte'ın son 3'ünü **açık olarak okumak** mümkündür.\
Karttan okuyamıyorsanız diğer 2 byte brute-force ile bulunabilir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Bu HID kartında da aynı durum geçerlidir; 3 byte'tan yalnızca 2'si kartın üzerine basılmış olarak bulunabilir.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emüle Et/Yaz

Bir kartı **kopyaladıktan** veya ID'sini **manuel olarak girdikten** sonra, kartı Flipper Zero ile **emüle etmek** ya da gerçek bir karta **yazmak** mümkündür.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Flipper Zero ile RFID Protocols'e Giriş](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
