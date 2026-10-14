# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

iButton teknolojisi hakkında arka plan bilgisi için şuraya bakın:

{{#ref}}
../ibutton.md
{{#endref}}

## Tasarım

Aşağıdaki görselde **mavi** alan, fiziksel bir iButton'ı okumak için Flipper Zero'nun kontaklarına nasıl yerleştireceğinizi gösterir. **Yeşil** alan ise öykünme sırasında hangi kontakların okuyucuya değmesi gerektiğini gösterir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## İşlemler

### Oku

Read modunda Flipper Zero, bir anahtarın kontaklarına değmesini bekler, protokolü algılar ve protokolü anahtar kimliğinin üzerinde görüntüler. Yerleşik uygulama Dallas, Cyfral ve Metakom erişim kontrolü anahtarlarını destekler.<sup>[[2]](#references)</sup>

### Elle ekle

Dallas, Cyfral ve Metakom protokolleri için anahtar verilerini elle girebilirsiniz.<sup>[[2]](#references)</sup>

### Öykün

Fiziksel bir anahtardan okunmuş veya elle girilmiş olmasına bakılmaksızın, kaydedilmiş bir anahtarı öykünebilirsiniz.<sup>[[2]](#references)</sup>

> [!TIP]
> Yerleşik kontaklar okuyucuya ulaşamıyorsa, GPIO pinleri üzerinden veri ve toprak kontaklarını bağlayın.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper Zero ile iButton Anahtarlarını Kontrol Altına Almak](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero belgeleri - iButton anahtarlarını okuma](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

