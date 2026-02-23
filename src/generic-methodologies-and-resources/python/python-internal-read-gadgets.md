# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

Different vulnerabilities such as [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) or [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) might allow you to **read python internal data but won't allow you to execute code**. Therefore, a pentester will need to make the most of these read permissions to **obtain sensitive privileges and escalate the vulnerability**.

### Flask - Lees geheime sleutel

Die hoofblad van 'n Flask-toepassing sal waarskynlik die **`app`** globale objek hê waar hierdie **geheim gekonfigureer is**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In hierdie geval is dit moontlik om toegang tot hierdie objek te kry deur net enige gadget te gebruik om **toegang tot globale objekte** vanaf die [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Indien **die kwesbaarheid in 'n ander python-lêer is**, benodig jy 'n gadget om deur lêers te navigeer om by die hooflêer uit te kom om **toegang tot die globale objek `app.secret_key`** te kry, om Flask se geheime sleutel te verander en in staat te wees om [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

'n payload soos hierdie [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Gebruik hierdie payload om **`app.secret_key` te verander** (die naam in jou app kan anders wees) sodat jy nuwe flask cookies met meer privileges kan teken.

### Werkzeug - machine_id en node uuid

[**Deur hierdie payloads uit hierdie writeup te gebruik**](https://vozec.fr/writeups/tweedle-dum-dee/) sal jy toegang hê tot die **machine_id** en die **uuid** node, wat die **hoof geheime** is wat jy nodig het om [**die Werkzeug pin te genereer**](../../network-services-pentesting/pentesting-web/werkzeug.md) wat jy kan gebruik om toegang tot die python console in `/console` te kry as die **debug mode** aangeskakel is:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Let wel dat jy die **bediener se plaaslike pad na die `app.py`** kan kry deur 'n **error** op die webblad te veroorsaak wat jou die pad sal gee.

As die kwesbaarheid in 'n ander python-lêer is, kyk na die vorige Flask-truuk om toegang tot die objekte van die hoof python-lêer te kry.

### Django - SECRET_KEY and settings module

Die Django settings-object word in `sys.modules` gebuffer sodra die toepassing begin. Met slegs read primitives kan jy die **`SECRET_KEY`**, database credentials of signing salts leak:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
As die kwesbare gadget in 'n ander module is, deurloop eers globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Sodra die sleutel bekend is, kan jy Django signed cookies of tokens vervals op 'n soortgelyke manier as met Flask.

### Omgewingsveranderlikes / cloud creds via gelaaide modules

Baie jails importeer steeds `os` of `sys` iewers. Jy kan enige bereikbare funksie se `__init__.__globals__` misbruik om na die reeds-ingevoerde `os`-module te pivot en **omgewingsveranderlikes** wat API tokens, cloud keys of flags bevat, te dump:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
As die subklas-indeks gefiltreer is, gebruik loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Omgewingsveranderlikes is dikwels die enigste geheime wat benodig word om van read na volledige kompromie oor te gaan (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) het **class pollution** toegelaat via vervaardigde component-aanvrae. Deur 'n eiendomspad soos `__init__.__globals__` te stel, kan 'n aanvaller by die component-module se globals en enige geïmporteerde modules (bv. `settings`, `os`, `sys`) uitkom. Van daar kan jy leak `SECRET_KEY`, `DATABASES` of diensbewyse sonder kode-uitvoering verkry. Die exploit chain is suiwer read-based en gebruik dieselfde dunder-gadget-patrone as hierbo.

### Gadget collections for chaining

Onlangse CTFs (bv. jailCTF 2025) wys betroubare read chains wat slegs gebou is met attribute access en subclass enumeration. Community-maintained lists soos [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) katalogiseer honderde minimale gadgets wat jy kan kombineer om van objekte na `__globals__`, `sys.modules` en uiteindelik sensitiewe data te navigeer. Gebruik dit om vinnig aan te pas wanneer indeksies of klasname tussen Python minor weergawes verskil.



## Verwysings

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
