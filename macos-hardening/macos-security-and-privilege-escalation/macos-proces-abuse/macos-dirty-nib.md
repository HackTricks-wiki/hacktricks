# macOS Dirty NIB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica fue tomada del artículo** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/)

## Información básica

Los archivos NIB se utilizan en el ecosistema de desarrollo de Apple para **definir elementos de interfaz de usuario (UI)** y sus interacciones dentro de una aplicación. Creados con la herramienta Interface Builder, contienen **objetos serializados** como ventanas, botones y campos de texto, que se cargan en tiempo de ejecución para presentar la interfaz de usuario diseñada. Aunque aún se utilizan, Apple ha pasado a recomendar Storyboards para una representación más visual del flujo de la interfaz de usuario de una aplicación.

{% hint style="danger" %}
Además, los **archivos NIB** también se pueden utilizar para **ejecutar comandos arbitrarios** y si se modifica un archivo NIB en una aplicación, **Gatekeeper seguirá permitiendo ejecutar la aplicación**, por lo que se pueden utilizar para **ejecutar comandos arbitrarios dentro de las aplicaciones**.
{% endhint %}

## Inyección de Dirty NIB <a href="#dirtynib" id="dirtynib"></a>

Primero, necesitamos crear un nuevo archivo NIB, utilizaremos XCode para la mayor parte de la construcción. Comenzamos agregando un objeto a la interfaz y establecemos la clase en NSAppleScript:

<figure><img src="../../../.gitbook/assets/image (681).png" alt="" width="380"><figcaption></figcaption></figure>

Para el objeto, necesitamos establecer la propiedad inicial `source`, lo cual podemos hacer utilizando Atributos de Tiempo de Ejecución Definidos por el Usuario:

<figure><img src="../../../.gitbook/assets/image (682).png" alt="" width="563"><figcaption></figcaption></figure>

Esto configura nuestro gadget de ejecución de código, que simplemente va a **ejecutar AppleScript a pedido**. Para activar la ejecución del AppleScript, simplemente agregaremos un botón por ahora (por supuesto, puedes ser creativo con esto ;). El botón se vinculará al objeto `Apple Script` que acabamos de crear y **invocará el selector `executeAndReturnError:`**:

<figure><img src="../../../.gitbook/assets/image (683).png" alt="" width="563"><figcaption></figcaption></figure>

Para las pruebas, simplemente utilizaremos el Apple Script de:
```bash
set theDialogText to "PWND"
display dialog theDialogText
```
Y si ejecutamos esto en el depurador de XCode y presionamos el botón:

<figure><img src="../../../.gitbook/assets/image (684).png" alt="" width="563"><figcaption></figcaption></figure>

Con nuestra capacidad para ejecutar código AppleScript arbitrario desde un NIB, a continuación necesitamos un objetivo. Elegiremos Pages para nuestra demostración inicial, que es, por supuesto, una aplicación de Apple y ciertamente no debería ser modificable por nosotros.

Primero haremos una copia de la aplicación en `/tmp/`:
```bash
cp -a -X /Applications/Pages.app /tmp/
```
Luego lanzaremos la aplicación para evitar problemas con Gatekeeper y permitir que las cosas se almacenen en caché:
```bash
open -W -g -j /Applications/Pages.app
```
Después de lanzar (y cerrar) la aplicación por primera vez, necesitaremos sobrescribir un archivo NIB existente con nuestro archivo DirtyNIB. Para fines de demostración, simplemente vamos a sobrescribir el archivo NIB del Panel Acerca de para poder controlar la ejecución:
```bash
cp /tmp/Dirty.nib /tmp/Pages.app/Contents/Resources/Base.lproj/TMAAboutPanel.nib
```
Una vez que hayamos sobrescrito el nib, podemos activar la ejecución seleccionando el elemento de menú `Acerca de`:

<figure><img src="../../../.gitbook/assets/image (685).png" alt="" width="563"><figcaption></figcaption></figure>

Si observamos Pages más de cerca, veremos que tiene un privilegio privado que permite acceder a las fotos de los usuarios:

<figure><img src="../../../.gitbook/assets/image (686).png" alt="" width="479"><figcaption></figcaption></figure>

Por lo tanto, podemos poner a prueba nuestra prueba de concepto modificando nuestro AppleScript para robar fotos del usuario sin solicitar permiso:

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

## Restricciones de lanzamiento

Básicamente, **impiden la ejecución de aplicaciones fuera de sus ubicaciones esperadas**, por lo que si copias una aplicación protegida por Restricciones de lanzamiento a `/tmp`, no podrás ejecutarla.\
[**Encuentra más información en esta publicación**](../macos-security-protections/#launch-constraints)**.**

Sin embargo, al analizar el archivo **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**, aún puedes encontrar **aplicaciones que no están protegidas por Restricciones de lanzamiento**, por lo que aún puedes **inyectar** archivos **NIB** en ubicaciones arbitrarias en **esas aplicaciones** (consulta el enlace anterior para aprender cómo encontrar estas aplicaciones).

## Protecciones adicionales

A partir de macOS Somona, existen algunas protecciones que **impiden escribir dentro de las aplicaciones**. Sin embargo, aún es posible eludir esta protección si, antes de ejecutar tu copia del binario, cambias el nombre de la carpeta Contents:

1. Haz una copia de `CarPlay Simulator.app` en `/tmp/`
2. Cambia el nombre de `/tmp/Carplay Simulator.app/Contents` a `/tmp/CarPlay Simulator.app/NotCon`
3. Ejecuta el binario `/tmp/CarPlay Simulator.app/NotCon/MacOS/CarPlay Simulator` para almacenarlo en la memoria caché de Gatekeeper
4. Sobrescribe `NotCon/Resources/Base.lproj/MainMenu.nib` con nuestro archivo `Dirty.nib`
5. Cambia el nombre a `/tmp/CarPlay Simulator.app/Contents`
6. Vuelve a ejecutar `CarPlay Simulator.app`

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
