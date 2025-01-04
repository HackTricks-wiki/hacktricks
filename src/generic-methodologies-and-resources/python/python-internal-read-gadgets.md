# Python Interne Lees Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

Verskillende kwesbaarhede soos [**Python Formaat Strings**](bypass-python-sandboxes/index.html#python-format-string) of [**Klas Besoedeling**](class-pollution-pythons-prototype-pollution.md) mag jou toelaat om **python interne data te lees maar sal jou nie toelaat om kode uit te voer nie**. Daarom sal 'n pentester die meeste van hierdie lees toestemmings moet maak om **sensitiewe voorregte te verkry en die kwesbaarheid te eskaleer**.

### Flask - Lees geheime sleutel

Die hoofblad van 'n Flask-toepassing sal waarskynlik die **`app`** globale objek hê waar hierdie **geheime sleutel geconfigureer is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te verkry net deur enige gadget te gebruik om **globale objekte te bekom** van die [**Bypass Python sandboxes page**](bypass-python-sandboxes/).

In die geval waar **die kwesbaarheid in 'n ander python-lêer is**, benodig jy 'n gadget om lêers te traverseer om by die hoof een te kom om **toegang tot die globale objek `app.secret_key`** te verkry om die Flask geheime sleutel te verander en in staat te wees om [**privileges te eskaleer** deur hierdie sleutel te ken](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

'n Payload soos hierdie [van hierdie skrywe](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Gebruik hierdie payload om **`app.secret_key`** (die naam in jou app mag anders wees) te verander om nuwe en meer bevoegde flask koekies te kan teken.

### Werkzeug - machine_id en node uuid

[**Deur hierdie payload uit hierdie skrywe te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy toegang hê tot die **machine_id** en die **uuid** node, wat die **hoofdokumente** is wat jy nodig het om [**die Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) wat jy kan gebruik om toegang te verkry tot die python konsole in `/console` as die **foutopsporing modus geaktiveer is:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Let daarop dat jy die **bediener se plaaslike pad na die `app.py`** kan kry deur 'n **fout** op die webblad te genereer wat jou **die pad** sal **gee**.

As die kwesbaarheid in 'n ander python-lêer is, kyk na die vorige Flask-truk om toegang tot die objekte van die hoof python-lêer te verkry.

{{#include ../../banners/hacktricks-training.md}}
