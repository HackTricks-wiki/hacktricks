# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Diverse vulnerabilità come [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) potrebbero consentirti di **leggere i dati interni di python ma non ti permetteranno di eseguire codice**. Pertanto, un pentester dovrà sfruttare al massimo queste autorizzazioni di lettura per **ottenere privilegi sensibili e aumentare la vulnerabilità**.

### Flask - Leggi la chiave segreta

La pagina principale di un'applicazione Flask avrà probabilmente l'oggetto globale **`app`** dove questa **segreta è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto semplicemente utilizzando qualsiasi gadget per **accedere agli oggetti globali** dalla [**pagina di Bypass Python sandboxes**](bypass-python-sandboxes/).

Nel caso in cui **la vulnerabilità si trovi in un file python diverso**, hai bisogno di un gadget per attraversare i file per arrivare a quello principale e **accedere all'oggetto globale `app.secret_key`** per cambiare la chiave segreta di Flask e poter [**escalare i privilegi** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa questo payload per **cambiare `app.secret_key`** (il nome nella tua app potrebbe essere diverso) per poter firmare nuovi e più privilegiati cookie flask.

### Werkzeug - machine_id e node uuid

[**Utilizzando questi payload da questo writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) sarai in grado di accedere al **machine_id** e al **uuid** node, che sono i **principali segreti** di cui hai bisogno per [**generare il pin di Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) che puoi usare per accedere alla console python in `/console` se la **modalità debug è abilitata:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Nota che puoi ottenere il **percorso locale del server per `app.py`** generando qualche **errore** nella pagina web che ti **darà il percorso**.

Se la vulnerabilità si trova in un file python diverso, controlla il trucco Flask precedente per accedere agli oggetti dal file python principale.

{{#include ../../banners/hacktricks-training.md}}
