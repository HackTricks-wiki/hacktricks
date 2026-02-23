# Python Εσωτερικά Gadgets Ανάγνωσης

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Διάφορες ευπάθειες όπως οι [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ή [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) μπορεί να σας επιτρέψουν να διαβάσετε εσωτερικά δεδομένα της Python αλλά δεν θα σας επιτρέψουν να εκτελέσετε κώδικα. Επομένως, ένας pentester θα χρειαστεί να αξιοποιήσει στο έπακρο αυτά τα δικαιώματα ανάγνωσης για να αποκτήσει ευαίσθητα προνόμια και να κλιμακώσει την ευπάθεια.

### Flask - Read secret key

Η κύρια σελίδα μιας εφαρμογής Flask πιθανότατα θα έχει το παγκόσμιο αντικείμενο **`app`** όπου αυτό το **μυστικό είναι διαμορφωμένο**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτή την περίπτωση μπορείτε να αποκτήσετε πρόσβαση σε αυτό το αντικείμενο απλώς χρησιμοποιώντας οποιοδήποτε gadget για να **αποκτήσετε πρόσβαση στα global objects** από τη [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Στην περίπτωση που **η ευπάθεια βρίσκεται σε διαφορετικό python αρχείο**, χρειάζεστε ένα gadget για να διασχίσετε τα αρχεία και να φτάσετε στο κύριο ώστε να **προσπελάσετε το global αντικείμενο `app.secret_key`** για να αλλάξετε το Flask secret key και να μπορείτε να [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα payload σαν αυτό [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Χρησιμοποίησε αυτό το payload για να **αλλάξεις `app.secret_key`** (το όνομα στην εφαρμογή σου μπορεί να είναι διαφορετικό) ώστε να μπορείς να υπογράφεις νέα και πιο προνομιακά flask cookies.

### Werkzeug - machine_id και node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορέσεις να αποκτήσεις πρόσβαση στο **machine_id** και στον κόμβο **uuid**, που είναι τα **main secrets** που χρειάζεσαι για να [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) το οποίο μπορείς να χρησιμοποιήσεις για να αποκτήσεις πρόσβαση στο python console στο `/console` αν το **debug mode** είναι ενεργοποιημένο:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Σημειώστε ότι μπορείτε να πάρετε την **τοπική διαδρομή του server προς το `app.py`** προκαλώντας κάποιο **σφάλμα** στη σελίδα web το οποίο θα **σας δώσει τη διαδρομή**.

Αν η ευπάθεια βρίσκεται σε διαφορετικό αρχείο python, δείτε το προηγούμενο κόλπο του Flask για να αποκτήσετε πρόσβαση στα αντικείμενα από το κύριο αρχείο python.

### Django - SECRET_KEY and settings module

Το αντικείμενο settings του Django αποθηκεύεται στο `sys.modules` μόλις ξεκινήσει η εφαρμογή. Με μόνο δυνατότητες ανάγνωσης μπορείτε να leak το **`SECRET_KEY`**, τα διαπιστευτήρια της βάσης δεδομένων ή τα signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Αν το ευάλωτο gadget βρίσκεται σε άλλο module, διατρέξτε πρώτα τα globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Μόλις το κλειδί γίνει γνωστό μπορείτε να πλαστογραφήσετε Django signed cookies ή tokens με παρόμοιο τρόπο όπως στο Flask.

### Μεταβλητές περιβάλλοντος / cloud creds μέσω φορτωμένων modules

Πολλά jails εξακολουθούν να εισάγουν `os` ή `sys` κάπου. Μπορείτε να καταχραστείτε οποιαδήποτε προσβάσιμη συνάρτηση `__init__.__globals__` για να pivot στο ήδη εισαχθέν `os` module και να dump **environment variables** που περιέχουν API tokens, cloud keys ή flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Αν ο δείκτης υποκλάσης είναι φιλτραρισμένος, χρησιμοποίησε loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Οι μεταβλητές περιβάλλοντος είναι συχνά τα μόνα μυστικά που απαιτούνται για να μεταβείτε από ανάγνωση σε πλήρη συμβιβασμό (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) επέτρεπε **class pollution** μέσω ειδικά διαμορφωμένων αιτημάτων component. Η ρύθμιση μιας διαδρομής ιδιότητας όπως `__init__.__globals__` επέτρεπε σε έναν επιτιθέμενο να προσεγγίσει τα globals του module του component και οποιαδήποτε εισαχθέντα modules (π.χ. `settings`, `os`, `sys`). Από εκεί μπορείτε να leak `SECRET_KEY`, `DATABASES` ή διαπιστευτήρια υπηρεσιών χωρίς εκτέλεση κώδικα. Η αλυσίδα εκμετάλλευσης είναι καθαρά βασισμένη στην ανάγνωση και χρησιμοποιεί τα ίδια dunder-gadget μοτίβα όπως παραπάνω.

### Gadget collections for chaining

Πρόσφατα CTFs (π.χ. jailCTF 2025) δείχνουν αξιόπιστες αλυσίδες ανάγνωσης κατασκευασμένες μόνο με πρόσβαση σε ιδιότητες και απαρίθμηση υποκλάσεων. Λίστες που διατηρούνται από την κοινότητα όπως [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) καταγράφουν εκατοντάδες ελάχιστα gadgets που μπορείτε να συνδυάσετε για να μεταβείτε από αντικείμενα σε `__globals__`, `sys.modules` και τελικά σε ευαίσθητα δεδομένα. Χρησιμοποιήστε τα για γρήγορη προσαρμογή όταν δείκτες ή ονόματα κλάσεων διαφέρουν μεταξύ μικρών εκδόσεων του Python.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
