# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

Farklı güvenlik açıkları, [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi, **python iç verilerini okumanıza izin verebilir ancak kod çalıştırmanıza izin vermez**. Bu nedenle, bir pentester bu okuma izinlerinden en iyi şekilde yararlanarak **hassas ayrıcalıkları elde etmeli ve güvenlik açığını yükseltmelidir**.

### Flask - Gizli anahtarı oku

Bir Flask uygulamasının ana sayfasında muhtemelen bu **gizli anahtarın yapılandırıldığı** **`app`** global nesnesi olacaktır.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, bu nesneye erişmek için herhangi bir gadget kullanarak **global nesnelere erişmek** mümkündür [**Python sandbox'larını atlama sayfasından**](bypass-python-sandboxes/).

**Açığın farklı bir python dosyasında olduğu** durumda, ana dosyaya ulaşmak için dosyaları geçmek üzere bir gadget'a ihtiyacınız var, böylece **global nesne `app.secret_key`'e erişebilir** ve Flask gizli anahtarını değiştirebilir ve bu anahtarı bilerek [**yetki yükseltme**] yapabilirsiniz (../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Bu yazıdan [şu şekilde bir payload](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu yükü kullanarak **`app.secret_key`**'i (uygulamanızdaki adı farklı olabilir) değiştirin, böylece yeni ve daha fazla yetkiye sahip flask çerezlerini imzalayabilirsiniz.

### Werkzeug - machine_id ve node uuid

[**Bu yazıdan bu yükleri kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node'una erişebileceksiniz, bunlar **gerekli anahtarlar**dır [**Werkzeug pin'ini oluşturmak için**](../../network-services-pentesting/pentesting-web/werkzeug.md) kullanabileceğiniz, eğer **hata ayıklama modu etkinse** `/console`'da python konsoluna erişmek için:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> **app.py**'nin **sunucunun yerel yolu**'nu almak için web sayfasında bazı **hatalar** oluşturduğunuzu unutmayın, bu da size **yolu verecektir**.

Eğer zafiyet farklı bir python dosyasındaysa, ana python dosyasından nesnelere erişmek için önceki Flask numarasını kontrol edin.

{{#include ../../banners/hacktricks-training.md}}
