# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Différentes vulnérabilités telles que [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) ou [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) pourraient vous permettre de **lire des données internes de python mais ne permettront pas d'exécuter du code**. Par conséquent, un pentester devra tirer le meilleur parti de ces permissions de lecture pour **obtenir des privilèges sensibles et escalader la vulnérabilité**.

### Flask - Lire la clé secrète

La page principale d'une application Flask aura probablement l'objet global **`app`** où cette **clé secrète est configurée**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce cas, il est possible d'accéder à cet objet en utilisant simplement n'importe quel gadget pour **accéder aux objets globaux** depuis la [**page de contournement des sandboxes Python**](bypass-python-sandboxes/).

Dans le cas où **la vulnérabilité se trouve dans un fichier python différent**, vous avez besoin d'un gadget pour traverser les fichiers afin d'atteindre le principal pour **accéder à l'objet global `app.secret_key`** afin de changer la clé secrète de Flask et pouvoir [**escalader les privilèges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [provenant de cette analyse](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez ce payload pour **changer `app.secret_key`** (le nom dans votre application peut être différent) afin de pouvoir signer de nouveaux cookies flask avec plus de privilèges.

### Werkzeug - machine_id et node uuid

[**En utilisant ces payloads de cet article**](https://vozec.fr/writeups/tweedle-dum-dee/), vous pourrez accéder au **machine_id** et au **uuid** node, qui sont les **principaux secrets** dont vous avez besoin pour [**générer le pin Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que vous pouvez utiliser pour accéder à la console python dans `/console` si le **mode debug est activé :**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Notez que vous pouvez obtenir le **chemin local du serveur vers le `app.py`** en générant une **erreur** sur la page web qui vous **donnera le chemin**.

Si la vulnérabilité se trouve dans un autre fichier python, vérifiez le truc Flask précédent pour accéder aux objets depuis le fichier python principal.

{{#include ../../banners/hacktricks-training.md}}
