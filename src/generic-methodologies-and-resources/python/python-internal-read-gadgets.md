# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

Διαφορετικές ευπάθειες όπως [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) ή [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) μπορεί να σας επιτρέψουν να **διαβάσετε εσωτερικά δεδομένα της python αλλά δεν θα σας επιτρέψουν να εκτελέσετε κώδικα**. Επομένως, ένας pentester θα χρειαστεί να εκμεταλλευτεί αυτές τις άδειες ανάγνωσης για να **αποκτήσει ευαίσθητα προνόμια και να κλιμακώσει την ευπάθεια**.

### Flask - Read secret key

Η κύρια σελίδα μιας εφαρμογής Flask θα έχει πιθανώς το **`app`** παγκόσμιο αντικείμενο όπου αυτή η **μυστική ρύθμιση είναι διαμορφωμένη**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτή την περίπτωση, είναι δυνατό να αποκτήσετε πρόσβαση σε αυτό το αντικείμενο απλά χρησιμοποιώντας οποιοδήποτε gadget για **να αποκτήσετε πρόσβαση σε παγκόσμια αντικείμενα** από τη σελίδα [**Bypass Python sandboxes**](bypass-python-sandboxes/).

Στην περίπτωση όπου **η ευπάθεια είναι σε διαφορετικό αρχείο python**, χρειάζεστε ένα gadget για να διασχίσετε τα αρχεία ώστε να φτάσετε στο κύριο για **να αποκτήσετε πρόσβαση στο παγκόσμιο αντικείμενο `app.secret_key`** για να αλλάξετε το μυστικό κλειδί του Flask και να μπορείτε να [**κλιμακώσετε προνόμια** γνωρίζοντας αυτό το κλειδί](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα payload όπως αυτό [από αυτή την αναφορά](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Χρησιμοποιήστε αυτό το payload για να **αλλάξετε το `app.secret_key`** (το όνομα στην εφαρμογή σας μπορεί να είναι διαφορετικό) ώστε να μπορείτε να υπογράφετε νέα και πιο προνομιακά cookies flask.

### Werkzeug - machine_id και node uuid

[**Χρησιμοποιώντας αυτά τα payload από αυτή τη γραφή**](https://vozec.fr/writeups/tweedle-dum-dee/) θα μπορείτε να αποκτήσετε πρόσβαση στο **machine_id** και το **uuid** node, τα οποία είναι τα **κύρια μυστικά** που χρειάζεστε για να [**δημιουργήσετε το Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) που μπορείτε να χρησιμοποιήσετε για να αποκτήσετε πρόσβαση στην κονσόλα python στο `/console` αν είναι **ενεργοποιημένη η λειτουργία αποσφαλμάτωσης:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Σημειώστε ότι μπορείτε να αποκτήσετε την **τοπική διαδρομή του διακομιστή για το `app.py`** δημιουργώντας κάποιο **σφάλμα** στη σελίδα web που θα **σας δώσει τη διαδρομή**.

Αν η ευπάθεια είναι σε διαφορετικό αρχείο python, ελέγξτε το προηγούμενο κόλπο Flask για να αποκτήσετε πρόσβαση στα αντικείμενα από το κύριο αρχείο python.

{{#include ../../banners/hacktricks-training.md}}
