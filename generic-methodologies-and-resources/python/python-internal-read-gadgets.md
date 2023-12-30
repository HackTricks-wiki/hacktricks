# Python Internal Read Gadgets

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) podrían permitirte **leer datos internos de python pero no ejecutar código**. Por lo tanto, un pentester necesitará aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`** donde se configura esta **clave secreta**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto simplemente utilizando cualquier gadget para **acceder a objetos globales** desde la [**página de Bypass Python sandboxes**](bypass-python-sandboxes/).

En el caso de que **la vulnerabilidad esté en un archivo python diferente**, necesitas un gadget para recorrer archivos hasta llegar al principal para **acceder al objeto global `app.secret_key`** para cambiar la clave secreta de Flask y poder [**escalar privilegios conociendo esta clave**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload como este [de este writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utiliza este payload para **cambiar `app.secret_key`** (el nombre en tu aplicación podría ser diferente) para poder firmar nuevas cookies de flask con más privilegios.

### Werkzeug - machine\_id y node uuid

[**Usando estos payloads de este artículo**](https://vozec.fr/writeups/tweedle-dum-dee/) podrás acceder al **machine\_id** y al **uuid** del nodo, que son los **secretos principales** que necesitas para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puedes usar para acceder a la consola de python en `/console` si el **modo de depuración está habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Ten en cuenta que puedes obtener la **ruta local del servidor al `app.py`** generando algún **error** en la página web que **te proporcionará la ruta**.
{% endhint %}

Si la vulnerabilidad está en un archivo python diferente, revisa el truco anterior de Flask para acceder a los objetos desde el archivo python principal.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
