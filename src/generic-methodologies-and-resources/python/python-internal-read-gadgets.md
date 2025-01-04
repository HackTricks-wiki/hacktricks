# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Información Básica

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) podrían permitirte **leer datos internos de python pero no te permitirán ejecutar código**. Por lo tanto, un pentester necesitará aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer clave secreta

La página principal de una aplicación Flask probablemente tendrá el **objeto global `app`** donde esta **secreta está configurada**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso, es posible acceder a este objeto utilizando cualquier gadget para **acceder a objetos globales** de la [**página de Bypass Python sandboxes**](bypass-python-sandboxes/).

En el caso de que **la vulnerabilidad esté en un archivo python diferente**, necesitas un gadget para recorrer archivos y llegar al principal para **acceder al objeto global `app.secret_key`** para cambiar la clave secreta de Flask y poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Una carga útil como esta [de este informe](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utiliza esta carga útil para **cambiar `app.secret_key`** (el nombre en tu aplicación podría ser diferente) para poder firmar nuevas y más privilegiadas cookies de flask.

### Werkzeug - machine_id y node uuid

[**Usando estas cargas útiles de este informe**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder al **machine_id** y al **uuid** del nodo, que son los **secretos principales** que necesitas para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puedes usar para acceder a la consola de python en `/console` si el **modo de depuración está habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> Tenga en cuenta que puede obtener la **ruta local del servidor al `app.py`** generando algún **error** en la página web que **le dará la ruta**.

Si la vulnerabilidad está en un archivo python diferente, consulte el truco de Flask anterior para acceder a los objetos desde el archivo python principal.

{{#include ../../banners/hacktricks-training.md}}
