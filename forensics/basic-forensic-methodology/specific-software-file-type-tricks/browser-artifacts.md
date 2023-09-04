# Artefactos del Navegador

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefactos del Navegador <a href="#3def" id="3def"></a>

Cuando hablamos de artefactos del navegador, nos referimos al historial de navegación, marcadores, lista de archivos descargados, datos de caché, etc.

Estos artefactos son archivos almacenados en carpetas específicas del sistema operativo.

Cada navegador almacena sus archivos en un lugar diferente al de otros navegadores y todos tienen nombres diferentes, pero generalmente almacenan el mismo tipo de datos (artefactos).

Veamos los artefactos más comunes almacenados por los navegadores.

* **Historial de Navegación:** Contiene datos sobre el historial de navegación del usuario. Puede utilizarse para rastrear si el usuario ha visitado sitios maliciosos, por ejemplo.
* **Datos de Autocompletado:** Estos son los datos que el navegador sugiere en función de lo que más buscas. Puede utilizarse junto con el historial de navegación para obtener más información.
* **Marcadores:** Autoexplicativo.
* **Extensiones y Complementos:** Autoexplicativo.
* **Caché:** Al navegar por sitios web, el navegador crea todo tipo de datos en caché (imágenes, archivos JavaScript, etc.) por diversas razones. Por ejemplo, para acelerar el tiempo de carga de los sitios web. Estos archivos en caché pueden ser una gran fuente de datos durante una investigación forense.
* **Inicios de Sesión:** Autoexplicativo.
* **Favicons:** Son los pequeños iconos que se encuentran en las pestañas, URLs, marcadores, etc. Se pueden utilizar como otra fuente para obtener más información sobre el sitio web o los lugares que visitó el usuario.
* **Sesiones del Navegador:** Autoexplicativo.
* **Descargas:** Autoexplicativo.
* **Datos de Formularios:** Todo lo que se escribe en los formularios a menudo se almacena en el navegador, para que la próxima vez que el usuario ingrese algo en un formulario, el navegador pueda sugerir datos ingresados previamente.
* **Miniaturas:** Autoexplicativo.
* **Custom Dictionary.txt**: Palabras agregadas al diccionario por el usuario.

## Firefox

Firefox crea la carpeta de perfiles en \~/_**.mozilla/firefox/**_ (Linux), en **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro de esta carpeta, debería aparecer el archivo _**profiles.ini**_ con el nombre(s) del perfil(es) de usuario.\
Cada perfil tiene una variable "**Path**" con el nombre de la carpeta donde se almacenarán sus datos. La carpeta debe estar **presente en el mismo directorio donde se encuentra el archivo \_profiles.ini**\_\*\*. Si no lo está, probablemente fue eliminada.

Dentro de la carpeta **de cada perfil** (_\~/.mozilla/firefox/\<NombrePerfil>/_) deberías poder encontrar los siguientes archivos interesantes:

* _**places.sqlite**_ : Historial (moz\_\_places), marcadores (moz\_bookmarks) y descargas (moz\_\_annos). En Windows, la herramienta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) se puede utilizar para leer el historial dentro de _**places.sqlite**_.
* Consulta para volcar el historial: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Ten en cuenta que el tipo de enlace es un número que indica:
* 1: El usuario siguió un enlace
* 2: El usuario escribió la URL
* 3: El usuario utilizó un favorito
* 4: Cargado desde un Iframe
* 5: Accedido a través de una redirección HTTP 301
* 6: Accedido a través de una redirección HTTP 302
* 7: Archivo descargado
* 8: El usuario siguió un enlace dentro de un Iframe
* Consulta para volcar las descargas: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Copias de seguridad de marcadores
* _**formhistory.sqlite**_ : Datos de formularios web (como correos electrónicos)
* _**handlers.json**_ : Manejadores de protocolos (por ejemplo, qué aplicación va a manejar el protocolo _mailto://_)
* _**persdict.dat**_ : Palabras agregadas al diccionario
* _**addons.json**_ y \_**extensions.sqlite** \_ : Complementos y extensiones instalados
* _**cookies.sqlite**_ : Contiene **cookies**. En Windows, se puede utilizar [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) para inspeccionar este archivo.
*   _**cache2/entries**_ o _**startupCache**_ : Datos de caché (\~350MB). También se pueden utilizar técnicas como **data carving** para obtener los archivos guardados en la caché. Se puede utilizar [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) para ver los **archivos guardados en la caché**.

Información que se puede obtener:

* URL, recuento de descargas, nombre de archivo, tipo de contenido, tamaño del archivo, hora de la última modificación, hora de la última descarga, última modificación del servidor, respuesta del servidor
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Configuraciones y preferencias
* _**downloads.sqlite**_ : Base de datos antigua de descargas (ahora está dentro de places.sqlite)
* _**thumbnails/**_ : Miniaturas
* _**logins.json**_ : Nombres de usuario y contraseñas encriptados
* **Anti-phishing incorporado en el navegador:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Devolverá "safebrowsing.malware.enabled" y "phishing.enabled" como falso si la configuración de búsqueda segura ha sido desactivada
* _**key4.db**_ o _**key3.db**_ : ¿Clave maestra?

Para intentar descifrar la contraseña maestra, puedes usar [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Con el siguiente script y llamada, puedes especificar un archivo de contraseñas para realizar un ataque de fuerza bruta:

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
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome crea el perfil dentro del directorio del usuario _**\~/.config/google-chrome/**_ (Linux), en _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), o en \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
La mayoría de la información se guarda dentro de las carpetas _**Default/**_ o _**ChromeDefaultData/**_ en las rutas mencionadas anteriormente. Aquí puedes encontrar los siguientes archivos interesantes:

* _**History**_: URLs, descargas e incluso palabras clave buscadas. En Windows, puedes usar la herramienta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) para leer el historial. La columna "Transition Type" significa:
* Link: El usuario hizo clic en un enlace
* Typed: La URL fue escrita
* Auto Bookmark
* Auto Subframe: Agregar
* Start page: Página de inicio
* Form Submit: Se completó y envió un formulario
* Reloaded
* _**Cookies**_: Cookies. Puedes usar [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) para inspeccionar las cookies.
* _**Cache**_: Caché. En Windows, puedes usar la herramienta [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) para inspeccionar la caché.
* _**Bookmarks**_: Marcadores
* _**Web Data**_: Historial de formularios
* _**Favicons**_: Favicons
* _**Login Data**_: Información de inicio de sesión (nombres de usuario, contraseñas...)
* _**Current Session**_ y _**Current Tabs**_: Datos de la sesión actual y pestañas actuales
* _**Last Session**_ y _**Last Tabs**_: Estos archivos contienen los sitios que estaban activos en el navegador cuando se cerró Chrome por última vez.
* _**Extensions**_: Carpeta de extensiones y complementos
* **Thumbnails** : Miniaturas
* **Preferences**: Este archivo contiene una gran cantidad de información útil, como complementos, extensiones, sitios que utilizan geolocalización, ventanas emergentes, notificaciones, DNS prefetching, excepciones de certificados y mucho más. Si estás investigando si una configuración específica de Chrome estaba habilitada, es probable que encuentres esa configuración aquí.
* **Anti-phishing integrado en el navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Puedes buscar simplemente "safebrowsing" y buscar `{"enabled: true,"}` en el resultado para indicar que la protección contra phishing y malware está activada.

## **Recuperación de datos de la base de datos SQLite**

Como se puede observar en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas utilizando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer almacena **datos** y **metadatos** en ubicaciones diferentes. Los metadatos permitirán encontrar los datos.

Los **metadatos** se pueden encontrar en la carpeta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`, donde VX puede ser V01, V16 o V24.\
En la carpeta anterior, también puedes encontrar el archivo V01.log. En caso de que la **hora de modificación** de este archivo y el archivo WebcacheVX.data **sean diferentes**, es posible que debas ejecutar el comando `esentutl /r V01 /d` para **solucionar** posibles **incompatibilidades**.

Una vez **recuperado** este artefacto (es una base de datos ESE, photorec puede recuperarla con las opciones Base de datos de Exchange o EDB), puedes usar el programa [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abrirlo. Una vez **abierto**, ve a la tabla llamada "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dentro de esta tabla, puedes encontrar en qué otras tablas o contenedores se guarda cada parte de la información almacenada. A continuación, puedes encontrar las **ubicaciones de los datos** almacenados por los navegadores y los **metadatos** que se encuentran dentro.

**Ten en cuenta que esta tabla indica metadatos de la caché para otras herramientas de Microsoft también (por ejemplo, Skype)**

### Caché

Puedes usar la herramienta [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) para inspeccionar la caché. Debes indicar la carpeta donde has extraído los datos de la caché.

#### Metadatos

La información de metadatos sobre la caché almacena:

* Nombre de archivo en el disco
* SecureDIrectory: Ubicación del archivo dentro de los directorios de caché
* AccessCount: Número de veces que se guardó en la caché
* URL: El origen de la URL
* CreationTime: Primera vez que se almacenó en la caché
* AccessedTime: Hora en que se utilizó la caché
* ModifiedTime: Última versión de la página web
* ExpiryTime: Hora en que caducará la caché

#### Archivos

La información de la caché se puede encontrar en _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ y _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

La información dentro de estas carpetas es una **captura de lo que el usuario estaba viendo**. Las cachés tienen un tamaño de **250 MB** y las marcas de tiempo indican cuándo se visitó la página (primera vez, fecha de creación de NTFS, última vez, hora de modificación de NTFS).

### Cookies

Puedes usar la herramienta [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) para inspeccionar las cookies. Debes indicar la carpeta donde has extraído las cookies.

#### Metadatos

La información de metadatos sobre las cookies almacenadas:

* Nombre de la cookie en el sistema de archivos
* URL
* AccessCount: Número de veces que las cookies se han enviado al servidor
* CreationTime: Primera vez que se creó la cookie
* ModifiedTime: Última vez que se modificó la cookie
* AccessedTime: Última vez que se accedió a la cookie
* ExpiryTime: Hora de vencimiento de la cookie

#### Archivos

Los datos de las cookies se pueden encontrar en _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ y _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Las cookies de sesión residirán en la memoria y las cookies persistentes en el disco.
### Descargas

#### **Metadatos**

Al verificar la herramienta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), puedes encontrar el contenedor con los metadatos de las descargas:

![](<../../../.gitbook/assets/image (445).png>)

Al obtener la información de la columna "ResponseHeaders", puedes transformar esa información de hexadecimal y obtener la URL, el tipo de archivo y la ubicación del archivo descargado.

#### Archivos

Busca en la ruta _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Historial**

La herramienta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) se puede utilizar para leer el historial. Pero primero, debes indicar el navegador en las opciones avanzadas y la ubicación de los archivos de historial extraídos.

#### **Metadatos**

* ModifiedTime: Primera vez que se encuentra una URL
* AccessedTime: Última vez
* AccessCount: Número de veces que se ha accedido

#### **Archivos**

Busca en _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ y _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs escritas**

Esta información se puede encontrar dentro del registro NTDUSER.DAT en la ruta:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Almacena las últimas 50 URLs escritas por el usuario
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* última vez que se escribió la URL

## Microsoft Edge

Para analizar los artefactos de Microsoft Edge, todas las **explicaciones sobre la caché y las ubicaciones de la sección anterior (IE 11) siguen siendo válidas**, con la única diferencia de que la ubicación base, en este caso, es _**%userprofile%\Appdata\Local\Packages**_ (como se puede observar en las siguientes rutas):

* Ruta del perfil: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* Historial, cookies y descargas: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Configuración, marcadores y lista de lectura: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Caché: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Sesiones activas recientes: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Las bases de datos se pueden encontrar en `/Users/$User/Library/Safari`

* **History.db**: Las tablas `history_visits` _y_ `history_items` contienen información sobre el historial y las marcas de tiempo.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: Contiene información sobre los archivos descargados.
* **Book-marks.plist**: URLs marcadas como favoritas.
* **TopSites.plist**: Lista de los sitios web más visitados por el usuario.
* **Extensions.plist**: Para recuperar una lista antigua de extensiones del navegador Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: Dominios permitidos para enviar notificaciones.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Pestañas que se abrieron la última vez que el usuario salió de Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Anti-phishing integrado en el navegador:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* La respuesta debería ser 1 para indicar que la configuración está activa

## Opera

Las bases de datos se pueden encontrar en `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

Opera **almacena el historial del navegador y los datos de descarga en el mismo formato que Google Chrome**. Esto se aplica tanto a los nombres de archivo como a los nombres de tabla.

* **Anti-phishing integrado en el navegador:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled** debería ser **true**

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
