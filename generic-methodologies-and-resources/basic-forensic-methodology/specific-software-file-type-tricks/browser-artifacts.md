# Artefactos del Navegador

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefactos de Navegadores <a href="#id-3def" id="id-3def"></a>

Los artefactos del navegador incluyen varios tipos de datos almacenados por los navegadores web, como historial de navegación, marcadores y datos de caché. Estos artefactos se guardan en carpetas específicas dentro del sistema operativo, difiriendo en ubicación y nombre entre navegadores, pero generalmente almacenando tipos de datos similares.

Aquí tienes un resumen de los artefactos de navegador más comunes:

* **Historial de Navegación**: Registra las visitas del usuario a sitios web, útil para identificar visitas a sitios maliciosos.
* **Datos de Autocompletar**: Sugerencias basadas en búsquedas frecuentes, ofreciendo información cuando se combina con el historial de navegación.
* **Marcadores**: Sitios guardados por el usuario para un acceso rápido.
* **Extensiones y Complementos**: Extensiones del navegador o complementos instalados por el usuario.
* **Caché**: Almacena contenido web (por ejemplo, imágenes, archivos JavaScript) para mejorar los tiempos de carga del sitio web, valioso para análisis forense.
* **Inicios de Sesión**: Credenciales de inicio de sesión almacenadas.
* **Favicons**: Iconos asociados con sitios web, que aparecen en pestañas y marcadores, útiles para obtener información adicional sobre las visitas del usuario.
* **Sesiones del Navegador**: Datos relacionados con las sesiones del navegador abiertas.
* **Descargas**: Registros de archivos descargados a través del navegador.
* **Datos de Formularios**: Información introducida en formularios web, guardada para sugerencias de autocompletar futuras.
* **Miniaturas**: Imágenes de vista previa de sitios web.
* **Diccionario Personalizado.txt**: Palabras añadidas por el usuario al diccionario del navegador.

## Firefox

Firefox organiza los datos del usuario dentro de perfiles, almacenados en ubicaciones específicas según el sistema operativo:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un archivo `profiles.ini` dentro de estos directorios lista los perfiles de usuario. Los datos de cada perfil se almacenan en una carpeta nombrada en la variable `Path` dentro de `profiles.ini`, ubicada en el mismo directorio que `profiles.ini` en sí. Si falta la carpeta de un perfil, puede haber sido eliminada.

Dentro de cada carpeta de perfil, puedes encontrar varios archivos importantes:

* **places.sqlite**: Almacena historial, marcadores y descargas. Herramientas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) en Windows pueden acceder a los datos del historial.
* Utiliza consultas SQL específicas para extraer información de historial y descargas.
* **bookmarkbackups**: Contiene copias de seguridad de marcadores.
* **formhistory.sqlite**: Almacena datos de formularios web.
* **handlers.json**: Gestiona los manejadores de protocolo.
* **persdict.dat**: Palabras del diccionario personalizado.
* **addons.json** y **extensions.sqlite**: Información sobre extensiones y complementos instalados.
* **cookies.sqlite**: Almacenamiento de cookies, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible para inspección en Windows.
* **cache2/entries** o **startupCache**: Datos de caché, accesibles a través de herramientas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Almacena favicons.
* **prefs.js**: Ajustes y preferencias del usuario.
* **downloads.sqlite**: Base de datos de descargas antiguas, ahora integrada en places.sqlite.
* **thumbnails**: Miniaturas de sitios web.
* **logins.json**: Información de inicio de sesión encriptada.
* **key4.db** o **key3.db**: Almacena claves de cifrado para asegurar información sensible.

Además, verificar la configuración de antiphishing del navegador se puede hacer buscando entradas `browser.safebrowsing` en `prefs.js`, indicando si las funciones de navegación segura están habilitadas o deshabilitadas.

Para intentar descifrar la contraseña maestra, puedes usar [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Con el siguiente script y llamada puedes especificar un archivo de contraseña para fuerza bruta:

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

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chrome almacena perfiles de usuario en ubicaciones específicas según el sistema operativo:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dentro de estos directorios, la mayoría de los datos de usuario se pueden encontrar en las carpetas **Default/** o **ChromeDefaultData/**. Los siguientes archivos contienen datos significativos:

* **Historial**: Contiene URLs, descargas y palabras clave de búsqueda. En Windows, se puede utilizar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) para leer el historial. La columna "Tipo de transición" tiene varios significados, incluidos clics de usuario en enlaces, URLs escritas, envíos de formularios y recargas de página.
* **Cookies**: Almacena cookies. Para inspeccionarlas, está disponible [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html).
* **Caché**: Contiene datos en caché. Para inspeccionarlos, los usuarios de Windows pueden utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
* **Marcadores**: Marcadores del usuario.
* **Datos web**: Contiene historial de formularios.
* **Favicons**: Almacena favicons de sitios web.
* **Datos de inicio de sesión**: Incluye credenciales de inicio de sesión como nombres de usuario y contraseñas.
* **Sesión actual**/**Pestañas actuales**: Datos sobre la sesión de navegación actual y las pestañas abiertas.
* **Última sesión**/**Últimas pestañas**: Información sobre los sitios activos durante la última sesión antes de que se cerrara Chrome.
* **Extensiones**: Directorios para extensiones y complementos del navegador.
* **Miniaturas**: Almacena miniaturas de sitios web.
* **Preferencias**: Un archivo rico en información, que incluye configuraciones para complementos, extensiones, ventanas emergentes, notificaciones y más.
* **Antiphishing integrado en el navegador**: Para verificar si la protección contra phishing y malware está habilitada, ejecuta `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Busca `{"enabled: true,"}` en la salida.

## **Recuperación de datos de bases de datos SQLite**

Como se puede observar en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas utilizando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestiona sus datos y metadatos en varias ubicaciones, lo que ayuda a separar la información almacenada y sus detalles correspondientes para facilitar el acceso y la gestión.

### Almacenamiento de metadatos

Los metadatos de Internet Explorer se almacenan en `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (siendo VX V01, V16 o V24). Además, el archivo `V01.log` puede mostrar discrepancias en la hora de modificación con `WebcacheVX.data`, lo que indica la necesidad de reparación utilizando `esentutl /r V01 /d`. Estos metadatos, alojados en una base de datos ESE, pueden recuperarse e inspeccionarse utilizando herramientas como photorec y [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), respectivamente. Dentro de la tabla **Containers**, se puede discernir las tablas o contenedores específicos donde se almacena cada segmento de datos, incluidos detalles de caché para otras herramientas de Microsoft como Skype.

### Inspección de caché

La herramienta [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) permite la inspección de la caché, requiriendo la ubicación de la carpeta de extracción de datos de caché. Los metadatos de la caché incluyen nombre de archivo, directorio, recuento de accesos, origen de URL y marcas de tiempo que indican la creación de la caché, acceso, modificación y tiempos de caducidad.

### Gestión de cookies

Las cookies se pueden explorar utilizando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadatos que abarcan nombres, URLs, recuentos de accesos y varios detalles relacionados con el tiempo. Las cookies persistentes se almacenan en `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mientras que las cookies de sesión residen en la memoria.

### Detalles de descargas

Los metadatos de descargas son accesibles a través de [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), con contenedores específicos que contienen datos como URL, tipo de archivo y ubicación de descarga. Los archivos físicos se pueden encontrar en `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historial de navegación

Para revisar el historial de navegación, se puede utilizar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html), que requiere la ubicación de los archivos de historial extraídos y la configuración para Internet Explorer. Los metadatos aquí incluyen tiempos de modificación y acceso, junto con recuentos de acceso. Los archivos de historial se encuentran en `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs escritas

Las URLs escritas y sus tiempos de uso se almacenan en el registro en `NTUSER.DAT` en `Software\Microsoft\InternetExplorer\TypedURLs` y `Software\Microsoft\InternetExplorer\TypedURLsTime`, rastreando las últimas 50 URLs ingresadas por el usuario y sus últimos tiempos de entrada.

## Microsoft Edge

Microsoft Edge almacena datos de usuario en `%userprofile%\Appdata\Local\Packages`. Las rutas para varios tipos de datos son:

* **Ruta del perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **Historial, Cookies y Descargas**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Configuraciones, Marcadores y Lista de lectura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Caché**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Últimas sesiones activas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Los datos de Safari se almacenan en `/Users/$User/Library/Safari`. Los archivos clave incluyen:

* **History.db**: Contiene tablas `history_visits` y `history_items` con URLs y marcas de tiempo de visita. Usa `sqlite3` para consultar.
* **Downloads.plist**: Información sobre archivos descargados.
* **Bookmarks.plist**: Almacena URLs marcadas.
* **TopSites.plist**: Sitios más visitados con frecuencia.
* **Extensions.plist**: Lista de extensiones del navegador Safari. Usa `plutil` o `pluginkit` para recuperar.
* **UserNotificationPermissions.plist**: Dominios permitidos para enviar notificaciones. Usa `plutil` para analizar.
* **LastSession.plist**: Pestañas de la última sesión. Usa `plutil` para analizar.
* **Antiphishing integrado en el navegador**: Verifica usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una respuesta de 1 indica que la función está activa.

## Opera

Los datos de Opera residen en `/Users/$USER/Library/Application Support/com.operasoftware.Opera` y comparten el formato de Chrome para historial y descargas.

* **Antiphishing integrado en el navegador**: Verifica si `fraud_protection_enabled` en el archivo de Preferencias está configurado en `true` usando `grep`.

Estas rutas y comandos son cruciales para acceder y comprender los datos de navegación almacenados por diferentes navegadores web.

## Referencias

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Libro: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
