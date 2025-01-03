# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Različite ranjivosti kao što su [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ili [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) mogu vam omogućiti da **pročitate interne podatke iz Pythona, ali neće vam omogućiti da izvršite kod**. Stoga, pentester će morati da iskoristi ova prava čitanja da **dobije osetljive privilegije i eskalira ranjivost**.

### Flask - Pročitajte tajni ključ

Glavna stranica Flask aplikacije verovatno će imati **`app`** globalni objekat gde je ovaj **tajni ključ konfigurisan**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom slučaju je moguće pristupiti ovom objektu koristeći bilo koji gadget za **pristup globalnim objektima** sa [**strane za zaobilaženje Python sandboxes**](bypass-python-sandboxes/).

U slučaju kada **je ranjivost u drugom python fajlu**, potreban vam je gadget za pretraživanje fajlova kako biste došli do glavnog da **pristupite globalnom objektu `app.secret_key`** kako biste promenili Flask tajni ključ i mogli da [**povećate privilegije** znajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog izveštaja](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da **promenite `app.secret_key`** (ime u vašoj aplikaciji može biti drugačije) kako biste mogli da potpišete nove i privilegovanije flask kolačiće.

### Werkzeug - machine_id i node uuid

[**Koristeći ove payload iz ovog izveštaja**](https://vozec.fr/writeups/tweedle-dum-dee/) moći ćete da pristupite **machine_id** i **uuid** node, koji su **glavne tajne** koje su vam potrebne da [**generišete Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) koji možete koristiti za pristup python konzoli u `/console` ako je **debug mode omogućen:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Imajte na umu da možete dobiti **lokalnu putanju servera do `app.py`** generišući neku **grešku** na veb stranici koja će **dati putanju**.

Ako je ranjivost u drugom python fajlu, proverite prethodni Flask trik za pristup objektima iz glavnog python fajla.

{{#include ../../banners/hacktricks-training.md}}
