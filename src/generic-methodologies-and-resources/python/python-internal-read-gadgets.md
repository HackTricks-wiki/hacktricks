# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi farklı güvenlik açıkları, **python iç verilerini okumanıza izin verebilir ancak kod çalıştırmanıza izin vermez**. Bu nedenle, bir pentester bu okuma izinlerini en iyi şekilde kullanarak **hassas ayrıcalıkları elde etmeli ve güvenlik açığını yükseltmelidir**.

### Flask - Gizli anahtarı oku

Bir Flask uygulamasının ana sayfasında muhtemelen bu **gizli anahtarın yapılandırıldığı** **`app`** global nesnesi bulunacaktır.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, bu nesneye erişmek için herhangi bir gadget kullanarak **global nesnelere erişmek** mümkündür [**Python sandbox'larını atlama sayfasından**](bypass-python-sandboxes/index.html).

**Açığın farklı bir python dosyasında olduğu** durumda, ana dosyaya ulaşmak için dosyaları geçmek üzere bir gadget'a ihtiyacınız var, böylece **global nesne `app.secret_key`'e erişebilir** ve Flask gizli anahtarını değiştirebilir ve bu anahtarı bilerek [**yetki yükseltme**] yapabilirsiniz (../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Bu yazıdan [şu şekilde bir payload](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu yükü kullanarak **`app.secret_key`**'i (uygulamanızdaki adı farklı olabilir) değiştirin, böylece yeni ve daha fazla yetkiye sahip flask çerezlerini imzalayabilirsiniz.

### Werkzeug - machine_id ve node uuid

[**Bu yazıdan bu yükleri kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node'una erişebileceksiniz, bu da [**Werkzeug pin'ini oluşturmak için**](../../network-services-pentesting/pentesting-web/werkzeug.md) ihtiyaç duyduğunuz **ana sırlar**dır. Eğer **hata ayıklama modu etkinse**, `/console`'da python konsoluna erişmek için kullanabilirsiniz:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Dikkat edin ki, web sayfasında bazı **hatalar** oluşturarak **app.py** dosyasının **sunucunun yerel yolunu** alabilirsiniz.

Eğer zafiyet farklı bir python dosyasındaysa, ana python dosyasından nesnelere erişmek için önceki Flask numarasını kontrol edin.

{{#include ../../banners/hacktricks-training.md}}
