# Gadgets de Lectura Interna de Python

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Información Básica

Diferentes vulnerabilidades como [**Cadenas de Formato en Python**](bypass-python-sandboxes/#python-format-string) o [**Contaminación de Clases**](class-pollution-pythons-prototype-pollution.md) podrían permitirte **leer datos internos de Python pero no ejecutar código**. Por lo tanto, un pentester necesitará aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`** donde esta **clave secreta está configurada**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto simplemente utilizando cualquier gadget para **acceder a objetos globales** desde la [**página de Bypass Python sandboxes**](bypass-python-sandboxes/).

En el caso en que **la vulnerabilidad se encuentre en un archivo Python diferente**, se necesita un gadget para atravesar archivos y llegar al principal para **acceder al objeto global `app.secret_key`** y cambiar la clave secreta de Flask y poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Una carga útil como esta [de este análisis](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilice esta carga útil para **cambiar `app.secret_key`** (el nombre en su aplicación puede ser diferente) para poder firmar nuevas y más privilegiadas cookies de Flask.

### Werkzeug - machine\_id y node uuid

[**Utilizando esta carga útil de este informe**](https://vozec.fr/writeups/tweedle-dum-dee/) podrá acceder al **machine\_id** y al nodo **uuid**, que son los **secretos principales** que necesita para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puede usar para acceder a la consola de Python en `/console` si el **modo de depuración está habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Ten en cuenta que puedes obtener la **ruta local de los servidores al `app.py`** generando algún **error** en la página web que te **proporcione la ruta**.
{% endhint %}

Si la vulnerabilidad está en un archivo python diferente, revisa el truco anterior de Flask para acceder a los objetos desde el archivo python principal.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
