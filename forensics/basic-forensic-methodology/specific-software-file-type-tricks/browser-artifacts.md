# Artefactos del Navegador

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefactos de Navegadores <a href="#id-3def" id="id-3def"></a>

Cuando hablamos de artefactos de navegadores nos referimos a, historial de navegación, marcadores, lista de archivos descargados, datos de caché, etc.

Estos artefactos son archivos almacenados dentro de carpetas específicas en el sistema operativo.

Cada navegador almacena sus archivos en un lugar diferente al de otros navegadores y todos tienen nombres distintos, pero todos almacenan (la mayoría de las veces) el mismo tipo de datos (artefactos).

Echemos un vistazo a los artefactos más comunes almacenados por los navegadores.

* **Historial de Navegación:** Contiene datos sobre el historial de navegación del usuario. Puede ser utilizado para rastrear si el usuario ha visitado sitios maliciosos, por ejemplo.
* **Datos de Autocompletar:** Son los datos que el navegador sugiere basado en lo que más buscas. Puede ser utilizado en conjunto con el historial de navegación para obtener más información.
* **Marcadores:** Autoexplicativo.
* **Extensiones y Complementos:** Autoexplicativo.
* **Caché:** Al navegar por sitios web, el navegador crea todo tipo de datos de caché (imágenes, archivos javascript, etc.) por varias razones. Por ejemplo, para acelerar el tiempo de carga de los sitios web. Estos archivos de caché pueden ser una gran fuente de datos durante una investigación forense.
* **Inicios de Sesión:** Autoexplicativo.
* **Favicons:** Son los pequeños iconos que se encuentran en las pestañas, URLs, marcadores y similares. Pueden ser utilizados como otra fuente para obtener más información sobre el sitio web o lugares visitados por el usuario.
* **Sesiones del Navegador:** Autoexplicativo.
* **Descargas:** Autoexplicativo.
* **Datos de Formularios:** Cualquier cosa escrita dentro de formularios es a menudo almacenada por el navegador, así que la próxima vez que el usuario ingrese algo en un formulario, el navegador puede sugerir datos previamente ingresados.
* **Miniaturas:** Autoexplicativo.
* **Diccionario Personalizado.txt**: Palabras añadidas al diccionario por el usuario.

## Firefox

Firefox crea la carpeta de perfiles en \~/_**.mozilla/firefox/**_ (Linux), en **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro de esta carpeta, el archivo _**profiles.ini**_ debería aparecer con el nombre(s) del perfil(es) del usuario.\
Cada perfil tiene una variable "**Path**" con el nombre de la carpeta donde se almacenarán sus datos. La carpeta debe estar **presente en el mismo directorio donde el \_profiles.ini**\_\*\* existe\*\*. Si no está, entonces, probablemente fue eliminada.

Dentro de la carpeta **de cada perfil** (_\~/.mozilla/firefox/\<ProfileName>/_) podrás encontrar los siguientes archivos interesantes:

* _**places.sqlite**_ : Historial (moz_places), marcadores (moz_bookmarks) y descargas (moz_annos). En Windows, la herramienta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) puede ser utilizada para leer el historial dentro de _**places.sqlite**_.
* Consulta para volcar el historial: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Nota que un tipo de enlace es un número que indica:
* 1: El usuario siguió un enlace
* 2: El usuario escribió la URL
* 3: El usuario usó un favorito
* 4: Cargado desde Iframe
* 5: Accedido vía redirección HTTP 301
* 6: Accedido vía redirección HTTP 302
* 7: Archivo descargado
* 8: El usuario siguió un enlace dentro de un Iframe
* Consulta para volcar descargas: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Copias de seguridad de marcadores
* _**formhistory.sqlite**_ : **Datos de formularios web** (como correos electrónicos)
* _**handlers.json**_ : Manejadores de protocolo (como, qué aplicación va a manejar el protocolo _mailto://_)
* _**persdict.dat**_ : Palabras añadidas al diccionario
* _**addons.json**_ y _**extensions.sqlite**_ : Complementos y extensiones instalados
* _**cookies.sqlite**_ : Contiene **cookies.** [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) puede ser utilizado en Windows para inspeccionar este archivo.
*   _**cache2/entries**_ o _**startupCache**_ : Datos de caché (\~350MB). Técnicas como **data carving** también pueden ser utilizadas para obtener los archivos guardados en la caché. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) puede ser utilizado para ver los **archivos guardados en la caché**.

Información que se puede obtener:

* URL, conteo de acceso, nombre de archivo, tipo de contenido, tamaño de archivo, última vez modificado, última vez accedido, última modificación del servidor, respuesta del servidor
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Configuraciones y preferencias
* _**downloads.sqlite**_ : Base de datos antigua de descargas (ahora está dentro de places.sqlite)
* _**thumbnails/**_ : Miniaturas
* _**logins.json**_ : Nombres de usuario y contraseñas encriptados
* **Protección anti-phishing integrada en el navegador:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Devolverá "safebrowsing.malware.enabled" y "phishing.enabled" como falso si la configuración de búsqueda segura ha sido desactivada
* _**key4.db**_ o _**key3.db**_ : ¿Clave maestra?

Para intentar descifrar la contraseña maestra, puedes usar [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con el siguiente script y llamada puedes especificar un archivo de contraseñas para fuerza bruta:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
```markdown
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome crea el perfil dentro del home del usuario _**\~/.config/google-chrome/**_ (Linux), en _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), o en _**/Users/$USER/Library/Application Support/Google/Chrome/**_ (MacOS).
La mayoría de la información se guardará dentro de las carpetas _**Default/**_ o _**ChromeDefaultData/**_ en las rutas indicadas anteriormente. Aquí puedes encontrar los siguientes archivos interesantes:

* _**History**_: URLs, descargas e incluso palabras clave buscadas. En Windows, puedes usar la herramienta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para leer el historial. La columna "Tipo de Transición" significa:
  * Link: El usuario hizo clic en un enlace
  * Typed: La URL fue escrita
  * Auto Bookmark
  * Auto Subframe: Añadir
  * Start page: Página de inicio
  * Form Submit: Un formulario fue llenado y enviado
  * Reloaded
* _**Cookies**_: Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) se puede usar para inspeccionar las cookies.
* _**Cache**_: Caché. En Windows, puedes usar la herramienta [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) para inspeccionar la caché.
* _**Bookmarks**_: Marcadores
* _**Web Data**_: Historial de formularios
* _**Favicons**_: Favicons
* _**Login Data**_: Información de inicio de sesión (nombres de usuario, contraseñas...)
* _**Current Session**_ y _**Current Tabs**_: Datos de la sesión actual y pestañas actuales
* _**Last Session**_ y _**Last Tabs**_: Estos archivos contienen los sitios que estaban activos en el navegador cuando Chrome se cerró por última vez.
* _**Extensions**_: Carpeta de extensiones y complementos
* **Thumbnails** : Miniaturas
* **Preferences**: Este archivo contiene una gran cantidad de buena información como plugins, extensiones, sitios que usan geolocalización, popups, notificaciones, prefetching de DNS, excepciones de certificados y mucho más. Si estás tratando de investigar si una configuración específica de Chrome estaba habilitada, probablemente encontrarás esa configuración aquí.
* **Protección anti-phishing integrada en el navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Puedes simplemente buscar por "**safebrowsing**" y buscar `{"enabled: true,"}` en el resultado para indicar que la protección contra phishing y malware está activada.

## **Recuperación de Datos de Bases de Datos SQLite**

Como puedes observar en las secciones anteriores, tanto Chrome como Firefox usan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas usando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer almacena **datos** y **metadatos** en diferentes ubicaciones. Los metadatos permitirán encontrar los datos.

Los **metadatos** se pueden encontrar en la carpeta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` donde VX puede ser V01, V16 o V24.\
En la carpeta anterior, también puedes encontrar el archivo V01.log. En caso de que el **tiempo modificado** de este archivo y el archivo WebcacheVX.data **sean diferentes**, es posible que necesites ejecutar el comando `esentutl /r V01 /d` para **corregir** posibles **incompatibilidades**.

Una vez **recuperado** este artefacto (Es una base de datos ESE, photorec puede recuperarlo con las opciones Exchange Database o EDB) puedes usar el programa [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abrirlo. Una vez **abierto**, ve a la tabla llamada "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dentro de esta tabla, puedes encontrar en qué otras tablas o contenedores se guarda cada parte de la información almacenada. Siguiendo eso, puedes encontrar las **ubicaciones de los datos** almacenados por los navegadores y los **metadatos** que están dentro.

**Ten en cuenta que esta tabla indica metadatos de la caché para otras herramientas de Microsoft también (por ejemplo, skype)**

### Cache

Puedes usar la herramienta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) para inspeccionar la caché. Necesitas indicar la carpeta donde has extraído la fecha de la caché.

#### Metadatos

La información de metadatos sobre la caché almacena:

* Nombre del archivo en el disco
* SecureDIrectory: Ubicación del archivo dentro de los directorios de caché
* AccessCount: Número de veces que se guardó en la caché
* URL: El origen de la URL
* CreationTime: Primera vez que se almacenó en caché
* AccessedTime: Tiempo cuando se usó la caché
* ModifiedTime: Última versión de la página web
* ExpiryTime: Tiempo cuando la caché expirará

#### Archivos

La información de la caché se puede encontrar en _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ y _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

La información dentro de estas carpetas es una **instantánea de lo que el usuario estaba viendo**. Las cachés tienen un tamaño de **250 MB** y las marcas de tiempo indican cuándo se visitó la página (primera vez, fecha de creación del NTFS, última vez, tiempo de modificación del NTFS).

### Cookies

Puedes usar la herramienta [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) para inspeccionar las cookies. Necesitas indicar la carpeta donde has extraído las cookies.

#### **Metadatos**

La información de metadatos sobre las cookies almacenadas:

* Nombre de la cookie en el sistema de archivos
* URL
* AccessCount: Número de veces que las cookies se han enviado al servidor
* CreationTime: Primera vez que se creó la cookie
* ModifiedTime: Última vez que se modificó la cookie
* AccessedTime: Última vez que se accedió a la cookie
* ExpiryTime: Tiempo de expiración de la cookie

#### Archivos

Los datos de las cookies se pueden encontrar en _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ y _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Las cookies de sesión residirán en la memoria y las cookies persistentes en el disco.

### Descargas

#### **Metadatos**

Revisando la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) puedes encontrar el contenedor con los metadatos de las descargas:

![](<../../../.gitbook/assets/image (445).png>)

Obteniendo la información de la columna "ResponseHeaders" puedes transformar de hex esa información y obtener la URL, el tipo de archivo y la ubicación del archivo descargado.

#### Archivos

Busca en la ruta _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Historial**

La herramienta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) se puede usar para leer el historial. Pero primero, necesitas indicar el navegador en opciones avanzadas y la ubicación de los archivos de historial extraídos.

#### **Metadatos**

* ModifiedTime: Primera vez que se encuentra una URL
* AccessedTime: Última vez
* AccessCount: Número de veces accedido

#### **Archivos**

Busca en _**%userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ y _**%userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs Escritas**

Esta información se puede encontrar dentro del registro NTDUSER.DAT en la ruta:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Almacena las últimas 50 URLs escritas por el usuario
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* Última vez que se escribió la URL

## Microsoft Edge

Para analizar los artefactos de Microsoft Edge, todas las **explicaciones sobre caché y ubicaciones de la sección anterior (IE 11) siguen siendo válidas** con la única diferencia de que la ubicación base, en este caso, es _**%userprofile%\Appdata\Local\Packages**_ (como se puede observar en las siguientes rutas):

* Ruta del Perfil: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC**_
* Historial, Cookies y Descargas: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Configuraciones, Marcadores y Lista de Lectura: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Caché: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Últimas sesiones activas: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Las bases de datos se pueden encontrar en `/Users/$User/Library/Safari`

* **History.db**: Las tablas `history_visits` _y_ `history_items` contienen información sobre el historial y marcas de tiempo.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: Contiene la información sobre los archivos descargados.
* **Bookmarks.plist**: URLs marcadas.
* **TopSites.plist**: Lista de los sitios web más visitados que el usuario navega.
* **Extensions.plist**: Para recuperar una lista antigua de extensiones del navegador Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: Dominios que tienen permiso para enviar notificaciones.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Pestañas que estaban abiertas la última vez que el usuario salió de Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Protección anti-phishing integrada en el navegador:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* La respuesta debe ser 1 para indicar que la configuración está activa

## Opera

Las bases de datos se pueden encontrar en `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

Opera **almacena el historial del navegador y los datos de descargas en el mismo formato exacto que Google Chrome**. Esto aplica tanto a los nombres de archivos como a los nombres de las tablas.

* **Protección anti-phishing integrada en el navegador:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud_protection_enabled** debe ser **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
```
