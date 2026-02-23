# Python — wewnętrzne read gadgets

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Różne podatności, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) czy [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą pozwolić na odczyt wewnętrznych danych Pythona, ale nie umożliwią wykonania kodu. W związku z tym pentester będzie musiał maksymalnie wykorzystać te uprawnienia do odczytu, aby uzyskać wrażliwe przywileje i eskalować podatność.

### Flask - odczyt tajnego klucza

Główna strona aplikacji Flask prawdopodobnie będzie miała globalny obiekt **`app`**, w którym skonfigurowany jest **tajny klucz**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku można uzyskać dostęp do tego obiektu, używając dowolnego gadgetu do **access global objects** ze strony [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

W sytuacji, gdy **the vulnerability is in a different python file**, potrzebny jest gadget do przechodzenia po plikach, aby dostać się do głównego pliku i **access the global object `app.secret_key`**, żeby zmienić sekret Flask i móc [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Taki payload jak ten [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego payloadu, aby **zmienić `app.secret_key`** (nazwa w Twojej aplikacji może być inna), aby móc podpisać nowe ciasteczka flask o wyższych uprawnieniach.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) będziesz w stanie uzyskać dostęp do węzłów **machine_id** i **uuid**, które są **głównymi sekretami**, których potrzebujesz do [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md), który pozwoli Ci uzyskać dostęp do konsoli Pythona w `/console`, jeśli **tryb debugowania jest włączony:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Zauważ, że możesz uzyskać **lokalną ścieżkę serwera do `app.py`** poprzez wygenerowanie pewnego **błędu** na stronie, który **poda ci ścieżkę**.

Jeśli podatność znajduje się w innym pliku python, sprawdź poprzedni trik Flask, aby uzyskać dostęp do obiektów z głównego pliku python.

### Django - SECRET_KEY and settings module

Obiekt ustawień Django jest cachowany w `sys.modules` po uruchomieniu aplikacji. Mając jedynie prymitywy do odczytu możesz leak the **`SECRET_KEY`**, poświadczenia bazy danych lub signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Jeśli podatny gadget znajduje się w innym module, najpierw przeszukaj globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Gdy klucz jest znany, możesz sfałszować Django signed cookies lub tokens w podobny sposób jak Flask.

### Zmienne środowiskowe / cloud creds przez załadowane moduły

Wiele jails nadal importuje `os` lub `sys` gdzieś. Możesz nadużyć dowolnej osiągalnej funkcji `__init__.__globals__`, aby pivotować do już zaimportowanego modułu `os` i dumpować **zmienne środowiskowe** zawierające API tokens, cloud keys lub flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Jeśli indeks podklasy jest filtrowany, użyj loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Zmienne środowiskowe są często jedynymi sekretami potrzebnymi do przejścia od odczytu do pełnego przejęcia (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) pozwalał na **class pollution** przez spreparowane żądania komponentu. Ustawienie ścieżki właściwości takiej jak `__init__.__globals__` pozwalało atakującemu dotrzeć do globalnych zmiennych modułu komponentu i dowolnych zaimportowanych modułów (np. `settings`, `os`, `sys`). Stamtąd można leak `SECRET_KEY`, `DATABASES` lub poświadczenia usług bez wykonania kodu. Łańcuch exploitów jest czysto read-based i wykorzystuje te same wzorce dunder-gadget co powyżej.

### Gadget collections for chaining

Najnowsze CTFy (np. jailCTF 2025) pokazują niezawodne read chains zbudowane wyłącznie przy użyciu attribute access i enumeracji subclass. Listy utrzymywane przez społeczność takie jak [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogują setki minimalnych gadgetów, które można łączyć, aby przejść od obiektów do `__globals__`, `sys.modules` i w końcu do danych wrażliwych. Użyj ich, aby szybko dostosować się, gdy indeksy lub nazwy klas różnią się między minorowymi wersjami Pythona.



## Referencje

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
