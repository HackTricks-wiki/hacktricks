# Artefactos del navegador

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Usa [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefactos del navegador <a href="#3def" id="3def"></a>

Cuando hablamos de artefactos del navegador, nos referimos al historial de navegación, marcadores, lista de archivos descargados, datos de caché, etc.

Estos artefactos son archivos almacenados en carpetas específicas del sistema operativo.

Cada navegador almacena sus archivos en un lugar diferente que otros navegadores y todos tienen nombres diferentes, pero todos almacenan (la mayoría de las veces) el mismo tipo de datos (artefactos).

Veamos los artefactos más comunes almacenados por los navegadores.

* **Historial de navegación:** Contiene datos sobre el historial de navegación del usuario. Puede ser utilizado para rastrear si el usuario ha visitado algunos sitios maliciosos, por ejemplo.
* **Datos de autocompletado:** Estos son los datos que el navegador sugiere en función de lo que más buscas. Puede ser utilizado en conjunto con el historial de navegación para obtener más información.
* **Marcadores:** Autoexplicativo.
* **Extensiones y complementos:** Autoexplicativo.
* **Caché:** Al navegar por sitios web, el navegador crea todo tipo de datos de caché (imágenes, archivos javascript, etc.) por muchas razones. Por ejemplo, para acelerar el tiempo de carga de los sitios web. Estos archivos de caché pueden ser una gran fuente de datos durante una investigación forense.
* **Inicios de sesión:** Autoexplicativo.
* **Favicons:** Son los pequeños iconos que se encuentran en las pestañas, URL, marcadores y similares. Pueden ser utilizados como otra fuente para obtener más información sobre el sitio web o los lugares que visitó el usuario.
* **Sesiones del navegador:** Autoexplicativo.
* **Descargas**: Autoexplicativo.
* **Datos de formulario:** Todo lo que se escribe dentro de los formularios a menudo es almacenado por el navegador, por lo que la próxima vez que el usuario ingrese algo dentro de un formulario, el navegador puede sugerir datos ingresados previamente.
* **Miniaturas:** Autoexplicativo.
* **Custom Dictionary.txt**: Palabras agregadas al diccionario por el usuario.

## Firefox

Firefox crea la carpeta de perfiles en \~/_**.mozilla/firefox/**_ (Linux), en **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro de esta carpeta, debería aparecer el archivo _**profiles.ini**_ con el nombre(s) del perfil(es) de usuario.\
Cada perfil tiene una variable "**Path**" con el nombre de la carpeta donde se almacenarán sus datos. La carpeta debería estar **presente en el mismo directorio donde existe el archivo \_profiles.ini**\_\*\*. Si no lo está, probablemente fue eliminado.

Dentro de la carpeta **de cada perfil** (_\~/.mozilla/firefox/\<ProfileName>/_) debería poder encontrar los siguientes archivos interesantes:

* _**places.sqlite**_ : Historial (moz\_\_places), marcadores (moz\_bookmarks) y descargas (moz\_\_annos). En Windows, la herramienta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) se puede utilizar para leer el historial dentro de _**places.sqlite**_.
  * Consulta para volcar el historial: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
    * Tenga en cuenta que el tipo de enlace es un número que indica:
      * 1: El usuario siguió un enlace
      * 2: El usuario escribió la URL
      * 3: El usuario utilizó un favorito
      * 4: Cargado desde Iframe
      * 5: Accedido a través de redirección HTTP 301
      * 6: Accedido a través de redirección HTTP 302
      * 7: Archivo descargado
      * 8: El usuario siguió un enlace dentro de un Iframe
  * Consulta para volcar descargas: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
  *
* _**bookmarkbackups/**_ : Copias de seguridad de marcadores
* _**formhistory.sqlite**_ : **Datos de formularios web** (como correos electrónicos)
* _**handlers.json**_ : Manejadores de protocolos (como, qué aplicación va a manejar el protocolo _mailto://_)
* _**persdict.dat**_ : Palabras agregadas al diccionario
* _**addons.json**_ y \_**extensions.sqlite** \_ : Complementos y extensiones instalados
* _**cookies.sqlite**_ : Contiene **cookies**. [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) se puede utilizar en Windows para inspeccionar este archivo.
*   _**cache2/entries**_ o _**startupCache**_ : Datos de caché (\~350MB). También se pueden utilizar trucos como la **talladura de datos** para obtener los archivos guardados en la caché. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) se puede utilizar para ver los **archivos guardados en la caché**.

    Información que se puede obtener:

    * URL, recuento de recuperación, nombre de archivo, tipo de contenido, tamaño de archivo, hora de la última modificación, hora de la última recuperación, servidor de última modificación, respuesta del servidor
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Configuraciones y preferencias
* _**
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome crea el perfil dentro del directorio del usuario _**\~/.config/google-chrome/**_ (Linux), en _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), o en \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
La mayoría de la información se guardará dentro de las carpetas _**Default/**_ o _**ChromeDefaultData/**_ dentro de las rutas indicadas anteriormente. Aquí se pueden encontrar los siguientes archivos interesantes:

* _**History**_: URLs, descargas e incluso palabras clave buscadas. En Windows, se puede utilizar la herramienta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) para leer el historial. La columna "Tipo de transición" significa:
  * Link: El usuario hizo clic en un enlace
  * Typed: La URL fue escrita
  * Auto Bookmark
  * Auto Subframe: Add
  * Start page: Página de inicio
  * Form Submit: Un formulario fue completado y enviado
  * Reloaded
* _**Cookies**_: Cookies. Se puede utilizar [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) para inspeccionar las cookies.
* _**Cache**_: Caché. En Windows, se puede utilizar la herramienta [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) para inspeccionar la caché.
* _**Bookmarks**_: Marcadores
* _**Web Data**_: Historial de formularios
* _**Favicons**_: Favicons
* _**Login Data**_: Información de inicio de sesión (nombres de usuario, contraseñas...)
* _**Current Session**_ y _**Current Tabs**_: Datos de sesión actual y pestañas actuales
* _**Last Session**_ y _**Last Tabs**_: Estos archivos contienen los sitios que estaban activos en el navegador cuando se cerró Chrome.
* _**Extensions**_: Carpeta de extensiones y complementos
* **Thumbnails** : Miniaturas
* **Preferences**: Este archivo contiene una gran cantidad de información útil, como plugins, extensiones, sitios que utilizan geolocalización, pop-ups, notificaciones, DNS prefetching, excepciones de certificados y mucho más. Si está intentando investigar si se habilitó o no una configuración específica de Chrome, es probable que encuentre esa configuración aquí.
* **Anti-phishing integrado en el navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
  * Simplemente puede buscar "safebrowsing" y buscar `{"enabled: true,"}` en el resultado para indicar que la protección contra phishing y malware está activada.

## **Recuperación de datos de bases de datos SQLite**

Como se puede observar en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas utilizando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer almacena **datos** y **metadatos** en diferentes ubicaciones. Los metadatos permitirán encontrar los datos.

Los **metadatos** se pueden encontrar en la carpeta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` donde VX puede ser V01, V16 o V24.\
En la carpeta anterior, también se puede encontrar el archivo V01.log. En caso de que el **tiempo modificado** de este archivo y el archivo WebcacheVX.data **sean diferentes**, es posible que deba ejecutar el comando `esentutl /r V01 /d` para **solucionar** posibles **
