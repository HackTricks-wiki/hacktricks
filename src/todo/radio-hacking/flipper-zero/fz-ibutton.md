# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

iButton teknolojisi hakkında arka plan bilgisi için bkz.:

{{#ref}}
../ibutton.md
{{#endref}}

## Tasarım

Aşağıdaki görselde **mavi** alan, okuma amacıyla fiziksel bir iButton'ın Flipper Zero'nun kontaklarına nasıl yerleştirileceğini gösterir. **Yeşil** alan, emülasyon sırasında hangi kontakların bir okuyucuya temas etmesi gerektiğini gösterir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## İşlemler

### Oku

Okuma modunda Flipper Zero, kontaklarına bir anahtarın dokunmasını bekler, protokolü algılar ve protokolü anahtar kimliğinin üzerinde görüntüler. Yerleşik uygulama Dallas, Cyfral ve Metakom erişim kontrolü anahtarlarını destekler.<sup>[[2]](#references)</sup>

### Manuel olarak ekle

Dallas, Cyfral ve Metakom protokolleri için anahtar verilerini manuel olarak girebilirsiniz.<sup>[[2]](#references)</sup>

### Emüle et

Fiziksel bir anahtardan okunmuş veya manuel olarak girilmiş fark etmeksizin, kaydedilmiş bir anahtarı emüle edebilirsiniz.<sup>[[2]](#references)</sup>

> [!TIP]
> Yerleşik kontaklar okuyucuya ulaşamıyorsa veri ve toprak kontaklarını GPIO pinleri üzerinden bağlayın.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - Reading iButton keys](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
