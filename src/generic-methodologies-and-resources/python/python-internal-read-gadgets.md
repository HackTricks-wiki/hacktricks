# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Verschiedene Schwachstellen wie [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) oder [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) könnten es Ihnen ermöglichen, **interne Python-Daten zu lesen, aber nicht, Code auszuführen**. Daher muss ein Pentester das Beste aus diesen Leseberechtigungen machen, um **sensible Berechtigungen zu erlangen und die Schwachstelle auszunutzen**.

### Flask - Geheimen Schlüssel lesen

Die Hauptseite einer Flask-Anwendung wird wahrscheinlich das **`app`** globale Objekt haben, wo dieses **Geheimnis konfiguriert ist**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Fall ist es möglich, auf dieses Objekt zuzugreifen, indem man einfach ein beliebiges Gadget verwendet, um **auf globale Objekte** von der [**Seite zum Umgehen von Python-Sandboxen**](bypass-python-sandboxes/) zuzugreifen.

Im Fall, dass **die Schwachstelle in einer anderen Python-Datei** liegt, benötigt man ein Gadget, um Dateien zu durchlaufen, um zur Hauptdatei zu gelangen, um **auf das globale Objekt `app.secret_key`** zuzugreifen, um den Flask-Geheimschlüssel zu ändern und in der Lage zu sein, [**die Berechtigungen zu eskalieren** mit diesem Schlüssel](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ein Payload wie dieser [aus diesem Bericht](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Verwenden Sie diese Payload, um **`app.secret_key`** zu ändern (der Name in Ihrer App könnte anders sein), um neue und privilegierte Flask-Cookies signieren zu können.

### Werkzeug - machine_id und node uuid

[**Mit diesen Payloads aus diesem Bericht**](https://vozec.fr/writeups/tweedle-dum-dee/) können Sie auf die **machine_id** und die **uuid** des Knotens zugreifen, die die **Hauptgeheimnisse** sind, die Sie benötigen, um [**den Werkzeug-Pin zu generieren**](../../network-services-pentesting/pentesting-web/werkzeug.md), den Sie verwenden können, um auf die Python-Konsole in `/console` zuzugreifen, wenn der **Debug-Modus aktiviert ist:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Beachten Sie, dass Sie den **lokalen Pfad des Servers zu `app.py`** erhalten können, indem Sie einen **Fehler** auf der Webseite erzeugen, der Ihnen **den Pfad** gibt.

Wenn die Schwachstelle in einer anderen Python-Datei liegt, überprüfen Sie den vorherigen Flask-Trick, um auf die Objekte aus der Haupt-Python-Datei zuzugreifen.

{{#include ../../banners/hacktricks-training.md}}
