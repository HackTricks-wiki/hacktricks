# Gadgets de Lectura Interna de Python

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

Diferentes vulnerabilidades como [**Python Format Strings**](bypass-python-sandboxes/#python-format-string) o [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) pueden permitirte **leer datos internos de Python pero no te permitirán ejecutar código**. Por lo tanto, un pentester deberá aprovechar al máximo estos permisos de lectura para **obtener privilegios sensibles y escalar la vulnerabilidad**.

### Flask - Leer clave secreta

La página principal de una aplicación Flask probablemente tendrá el objeto global **`app`** donde se configura este **secreto**.
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
En este caso es posible acceder a este objeto simplemente usando cualquier gadget para **acceder a objetos globales** de la página [**Bypass Python sandboxes**](bypass-python-sandboxes/).

En el caso en que **la vulnerabilidad se encuentre en un archivo Python diferente**, se necesita un gadget para recorrer archivos y llegar al archivo principal para **acceder al objeto global `app.secret_key`** y cambiar la clave secreta de Flask y así poder [**escalar privilegios** conociendo esta clave](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Una carga útil como esta [de este writeup](https://ctftime.org/writeup/36082):

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

Utilice esta carga útil para **cambiar `app.secret_key`** (el nombre en su aplicación puede ser diferente) para poder firmar nuevas y más privilegiadas cookies de flask.

### Werkzeug - machine\_id y node uuid

[**Usando estas cargas útiles de este artículo**](https://vozec.fr/writeups/tweedle-dum-dee/) podrá acceder al **machine\_id** y al nodo **uuid**, que son los **secretos principales** que necesita para [**generar el pin de Werkzeug**](../../network-services-pentesting/pentesting-web/werkzeug.md) que puede usar para acceder a la consola de Python en `/console` si el **modo de depuración está habilitado:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
{% hint style="warning" %}
Ten en cuenta que puedes obtener la **ruta local del servidor al archivo `app.py`** generando algún **error** en la página web que te **proporcione la ruta**.
{% endhint %}

Si la vulnerabilidad se encuentra en un archivo Python diferente, revisa el truco anterior de Flask para acceder a los objetos desde el archivo Python principal.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
