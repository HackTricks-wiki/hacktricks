# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Różne luki, takie jak [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) lub [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), mogą pozwolić na **odczyt danych wewnętrznych Pythona, ale nie pozwolą na wykonanie kodu**. Dlatego pentester musi maksymalnie wykorzystać te uprawnienia do odczytu, aby **uzyskać wrażliwe uprawnienia i eskalować lukę**.

### Flask - Odczyt klucza tajnego

Główna strona aplikacji Flask prawdopodobnie będzie miała globalny obiekt **`app`**, w którym **ten sekret jest skonfigurowany**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym przypadku możliwe jest uzyskanie dostępu do tego obiektu, używając dowolnego gadżetu do **uzyskiwania dostępu do obiektów globalnych** z [**strony Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

W przypadku, gdy **vulnerability znajduje się w innym pliku python**, potrzebujesz gadżetu do przeszukiwania plików, aby dotrzeć do głównego, aby **uzyskać dostęp do obiektu globalnego `app.secret_key`**, aby zmienić klucz tajny Flask i móc [**eskalować uprawnienia** znając ten klucz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego opisu](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego ładunku, aby **zmienić `app.secret_key`** (nazwa w twojej aplikacji może być inna), aby móc podpisywać nowe i bardziej uprzywilejowane ciasteczka flask.

### Werkzeug - machine_id i node uuid

[**Używając tych ładunków z tego opisu**](https://vozec.fr/writeups/tweedle-dum-dee/) będziesz mógł uzyskać dostęp do **machine_id** i **uuid** węzła, które są **głównymi sekretami**, których potrzebujesz, aby [**wygenerować pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md), którego możesz użyć do uzyskania dostępu do konsoli pythona w `/console`, jeśli **tryb debugowania jest włączony:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Zauważ, że możesz uzyskać **lokalną ścieżkę serwera do `app.py`** generując jakiś **błąd** na stronie internetowej, co **da ci ścieżkę**.

Jeśli luka znajduje się w innym pliku python, sprawdź poprzedni trik Flask, aby uzyskać dostęp do obiektów z głównego pliku python.

{{#include ../../banners/hacktricks-training.md}}
