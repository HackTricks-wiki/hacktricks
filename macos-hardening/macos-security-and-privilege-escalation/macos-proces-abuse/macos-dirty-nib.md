# macOS Dirty NIB

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica fue tomada del post** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Información Básica

Los archivos NIB se utilizan en el ecosistema de desarrollo de Apple para **definir elementos de la interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Creados con la herramienta Interface Builder, contienen **objetos serializados** como ventanas, botones y campos de texto, que se cargan en tiempo de ejecución para presentar la UI diseñada. Aunque todavía se utilizan, Apple ha pasado a recomendar Storyboards para una representación más visual del flujo de UI de una aplicación.

{% hint style="danger" %}
Además, los **archivos NIB** también pueden usarse para **ejecutar comandos arbitrarios** y si se modifica un archivo NIB en una App, **Gatekeeper aún permitirá ejecutar la app**, por lo que pueden usarse para **ejecutar comandos arbitrarios dentro de aplicaciones**.
{% endhint %}

## Inyección Dirty NIB <a href="#dirtynib" id="dirtynib"></a>

Primero necesitamos crear un nuevo archivo NIB, usaremos XCode para la mayor parte de la construcción. Comenzamos agregando un Objeto a la interfaz y establecemos la clase en NSAppleScript:

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Para el objeto necesitamos establecer la propiedad inicial `source`, lo que podemos hacer usando Atributos de Tiempo de Ejecución Definidos por el Usuario:

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Esto configura nuestro gadget de ejecución de código, que simplemente va a **ejecutar AppleScript a petición**. Para activar realmente la ejecución del AppleScript, por ahora solo agregaremos un botón (por supuesto, puedes ser creativo con esto ;). El botón se vinculará al objeto `Apple Script` que acabamos de crear, e **invocará el selector `executeAndReturnError:`**:

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Para las pruebas, simplemente usaremos el Apple Script de:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
Y si ejecutamos esto en el depurador de XCode y presionamos el botón:

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Con nuestra capacidad para ejecutar código AppleScript arbitrario desde un NIB, a continuación necesitamos un objetivo. Elijamos Pages para nuestra demostración inicial, que por supuesto es una aplicación de Apple y ciertamente no debería ser modificable por nosotros.

Primero haremos una copia de la aplicación en `/tmp/`:
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Luego lanzaremos la aplicación para evitar cualquier problema con Gatekeeper y permitir que las cosas se almacenen en caché:
```bash
open -W -g -j /Applications/Pages.app
```
Después de lanzar (y matar) la aplicación por primera vez, necesitaremos sobrescribir un archivo NIB existente con nuestro archivo DirtyNIB. Para fines de demostración, vamos a sobrescribir el NIB del Panel de Acerca de para poder controlar la ejecución:
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Una vez que hayamos sobrescrito el nib, podemos desencadenar la ejecución seleccionando el elemento del menú `About`:

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Si observamos Pages más de cerca, vemos que tiene un privilegio privado que permite el acceso a las Fotos de un usuario:

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Así que podemos poner a prueba nuestro POC **modificando nuestro AppleScript para robar fotos** del usuario sin solicitar permiso:

{% code overflow="wrap" %}
```applescript
use framework "Cocoa"
use framework "Foundation"

set grabbed to current application's NSData's dataWithContentsOfFile:"/Users/xpn/Pictures/Photos Library.photoslibrary/originals/6/68CD9A98-E591-4D39-B038-E1B3F982C902.gif"

grabbed's writeToFile:"/Users/xpn/Library/Containers/com.apple.iWork.Pages/Data/wtf.gif" atomically:1
```
{% endcode %}

{% hint style="danger" %}
[**Ejemplo de archivo .xib malicioso que ejecuta código arbitrario.**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)
{% endhint %}

## Crea tu propio DirtyNIB



## Restricciones de Lanzamiento

Básicamente **impiden ejecutar aplicaciones fuera de sus ubicaciones esperadas**, así que si copias una aplicación protegida por Restricciones de Lanzamiento a `/tmp` no podrás ejecutarla.\
[**Encuentra más información en este post**](../macos-security-protections/#launch-constraints)**.**

Sin embargo, al analizar el archivo **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`** aún puedes encontrar **aplicaciones que no están protegidas por Restricciones de Lanzamiento** por lo que aún podrías **inyectar** archivos **NIB** en ubicaciones arbitrarias en **esas** (consulta el enlace anterior para aprender cómo encontrar estas aplicaciones).

## Protecciones Extra

Desde macOS Somona, hay algunas protecciones que **impiden escribir dentro de las Apps**. Sin embargo, aún es posible eludir esta protección si, antes de ejecutar tu copia del binario, cambias el nombre de la carpeta Contents:

1. Toma una copia de `CarPlay Simulator.app` a `/tmp/`
2. Renombra `/tmp/Carplay Simulator.app/Contents` a `/tmp/CarPlay Simulator.app/NotCon`
3. Lanza el binario `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` para cachear dentro de Gatekeeper
4. Sobrescribe `NotCon/Resources/Base.lproj/MainMenu.nib` con nuestro archivo `Dirty.nib`
5. Renombra a `/tmp/CarPlay Simulator.app/Contents`
6. Lanza `CarPlay Simulator.app` de nuevo

{% hint style="success" %}
Parece que esto ya no es posible porque macOS **impide modificar archivos** dentro de los paquetes de aplicaciones.\
Por lo tanto, después de ejecutar la app para cachearla con Gatekeeper, no podrás modificar el paquete.\
Y si cambias, por ejemplo, el nombre del directorio Contents a **NotCon** (como se indica en el exploit), y luego ejecutas el binario principal de la app para cachearlo con Gatekeeper, **se activará un error y no se ejecutará**.
{% endhint %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
