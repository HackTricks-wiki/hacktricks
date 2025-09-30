# Artefactos del Navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos del navegador <a href="#id-3def" id="id-3def"></a>

Los artefactos del navegador incluyen varios tipos de datos almacenados por los navegadores web, como historial de navegación, marcadores y datos de caché. Estos artefactos se guardan en carpetas específicas dentro del sistema operativo, cambiando de ubicación y nombre según el navegador, aunque en general contienen tipos de datos similares.

Aquí hay un resumen de los artefactos de navegador más comunes:

- **Navigation History**: Registra las visitas del usuario a sitios web, útil para identificar visitas a sitios maliciosos.
- **Autocomplete Data**: Sugerencias basadas en búsquedas frecuentes, que ofrecen información cuando se combinan con el historial de navegación.
- **Bookmarks**: Sitios guardados por el usuario para acceso rápido.
- **Extensions and Add-ons**: Extensiones o complementos instalados por el usuario.
- **Cache**: Almacena contenido web (por ejemplo, imágenes, archivos JavaScript) para mejorar los tiempos de carga del sitio, valioso para análisis forense.
- **Logins**: Credenciales de inicio de sesión almacenadas.
- **Favicons**: Iconos asociados a sitios web, que aparecen en pestañas y marcadores, útiles para información adicional sobre visitas del usuario.
- **Browser Sessions**: Datos relacionados con sesiones de navegador abiertas.
- **Downloads**: Registros de archivos descargados a través del navegador.
- **Form Data**: Información introducida en formularios web, guardada para futuras sugerencias de autocompletar.
- **Thumbnails**: Imágenes en miniatura de sitios web.
- **Custom Dictionary.txt**: Palabras añadidas por el usuario al diccionario del navegador.

## Firefox

Firefox organiza los datos de usuario dentro de perfiles, almacenados en ubicaciones específicas según el sistema operativo:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un archivo `profiles.ini` dentro de estos directorios lista los perfiles de usuario. Los datos de cada perfil se almacenan en una carpeta cuyo nombre está en la variable `Path` dentro de `profiles.ini`, ubicada en el mismo directorio que `profiles.ini`. Si falta la carpeta de un perfil, puede haber sido eliminada.

Dentro de cada carpeta de perfil, puedes encontrar varios archivos importantes:

- **places.sqlite**: Almacena historial, marcadores y descargas. Tools like [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) on Windows can access the history data.
- Usa consultas SQL específicas para extraer información de historial y descargas.
- **bookmarkbackups**: Contiene copias de seguridad de marcadores.
- **formhistory.sqlite**: Almacena datos de formularios web.
- **handlers.json**: Gestiona los manejadores de protocolo.
- **persdict.dat**: Palabras del diccionario personalizado.
- **addons.json** and **extensions.sqlite**: Información sobre add-ons y extensiones instaladas.
- **cookies.sqlite**: Almacenamiento de cookies, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible para inspección en Windows.
- **cache2/entries** or **startupCache**: Datos de caché, accesibles mediante herramientas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Almacena favicons.
- **prefs.js**: Configuraciones y preferencias del usuario.
- **downloads.sqlite**: Base de datos de descargas antigua, ahora integrada en places.sqlite.
- **thumbnails**: Miniaturas de sitios web.
- **logins.json**: Información de inicio de sesión encriptada.
- **key4.db** or **key3.db**: Almacena claves de encriptación para proteger información sensible.

Adicionalmente, se puede comprobar la configuración anti-phishing del navegador buscando entradas `browser.safebrowsing` en `prefs.js`, lo que indica si las funciones de safe browsing están habilitadas o deshabilitadas.

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con el siguiente script y la llamada, puedes especificar un archivo de contraseñas para realizar un ataque de fuerza bruta:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome almacena los perfiles de usuario en ubicaciones específicas según el sistema operativo:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dentro de estos directorios, la mayoría de los datos de usuario se encuentran en las carpetas **Default/** o **ChromeDefaultData/**. Los siguientes archivos contienen datos importantes:

- **History**: Contiene URLs, descargas y palabras clave de búsqueda. En Windows, se puede usar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para leer el historial. La columna "Transition Type" tiene varios significados, incluyendo clics del usuario en enlaces, URLs tecleadas, envíos de formularios y recargas de página.
- **Cookies**: Almacena cookies. Para inspección, está disponible [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene datos en caché. Para inspeccionarlo, los usuarios de Windows pueden utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Las aplicaciones de escritorio basadas en Electron (p. ej., Discord) también usan Chromium Simple Cache y dejan artefactos ricos en disco. Ver:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Marcadores del usuario.
- **Web Data**: Contiene el historial de formularios.
- **Favicons**: Almacena los favicons de los sitios web.
- **Login Data**: Incluye credenciales de inicio de sesión como nombres de usuario y contraseñas.
- **Current Session**/**Current Tabs**: Datos sobre la sesión de navegación actual y las pestañas abiertas.
- **Last Session**/**Last Tabs**: Información sobre los sitios activos durante la última sesión antes de que se cerrara Chrome.
- **Extensions**: Directorios para extensiones y addons del navegador.
- **Thumbnails**: Almacena miniaturas de sitios web.
- **Preferences**: Un archivo con mucha información, incluyendo configuraciones de plugins, extensiones, pop-ups, notificaciones y más.
- **Browser’s built-in anti-phishing**: Para comprobar si la protección anti-phishing y contra malware está habilitada, ejecuta `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Busca `{"enabled: true,"}` en la salida.

## **SQLite DB Data Recovery**

Como puede observarse en las secciones anteriores, tanto Chrome como Firefox usan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas usando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestiona sus datos y metadatos en varias ubicaciones, lo que ayuda a separar la información almacenada y sus detalles correspondientes para un acceso y gestión más sencilla.

### Almacenamiento de metadatos

Los metadatos de Internet Explorer se almacenan en `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (con VX siendo V01, V16, o V24). Junto a esto, el archivo `V01.log` puede mostrar discrepancias en los tiempos de modificación con `WebcacheVX.data`, lo que indica la necesidad de una reparación usando `esentutl /r V01 /d`. Estos metadatos, alojados en una base de datos ESE, pueden recuperarse e inspeccionarse usando herramientas como photorec y [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. Dentro de la tabla **Containers**, se pueden identificar las tablas o contenedores específicos donde se almacena cada segmento de datos, incluyendo detalles de caché para otras herramientas de Microsoft como Skype.

### Inspección de la caché

La herramienta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspeccionar la caché, requiriendo la ubicación de la carpeta de extracción de datos de caché. Los metadatos de la caché incluyen nombre de archivo, directorio, contador de accesos, URL de origen y marcas de tiempo que indican la creación, acceso, modificación y expiración del caché.

### Gestión de cookies

Las cookies pueden explorarse usando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadatos que abarcan nombres, URLs, contadores de acceso y varios detalles relacionados con tiempos. Las cookies persistentes se almacenan en `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mientras que las cookies de sesión residen en memoria.

### Detalles de descargas

Los metadatos de descargas son accesibles vía [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con contenedores específicos que contienen datos como URL, tipo de archivo y ubicación de descarga. Los archivos físicos pueden encontrarse bajo `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historial de navegación

Para revisar el historial de navegación, se puede usar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), requiriendo la ubicación de los archivos de historial extraídos y la configuración para Internet Explorer. Los metadatos aquí incluyen tiempos de modificación y acceso, junto con contadores de acceso. Los archivos de historial se ubican en `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs tecleadas

Las URLs tecleadas y sus tiempos de uso se almacenan dentro del registro en `NTUSER.DAT` en `Software\Microsoft\InternetExplorer\TypedURLs` y `Software\Microsoft\InternetExplorer\TypedURLsTime`, rastreando las últimas 50 URLs introducidas por el usuario y sus últimos tiempos de entrada.

## Microsoft Edge

Microsoft Edge almacena datos de usuario en `%userprofile%\Appdata\Local\Packages`. Las rutas para varios tipos de datos son:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Los datos de Safari se almacenan en `/Users/$User/Library/Safari`. Archivos clave incluyen:

- **History.db**: Contiene las tablas `history_visits` y `history_items` con URLs y marcas de tiempo de visitas. Usa `sqlite3` para consultar.
- **Downloads.plist**: Información sobre archivos descargados.
- **Bookmarks.plist**: Almacena URLs marcadas como favoritos.
- **TopSites.plist**: Sitios más visitados.
- **Extensions.plist**: Lista de extensiones del navegador Safari. Usa `plutil` o `pluginkit` para recuperar.
- **UserNotificationPermissions.plist**: Dominios permitidos para enviar notificaciones push. Usa `plutil` para parsear.
- **LastSession.plist**: Pestañas de la última sesión. Usa `plutil` para parsear.
- **Browser’s built-in anti-phishing**: Compruébalo usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una respuesta de 1 indica que la función está activa.

## Opera

Los datos de Opera residen en `/Users/$USER/Library/Application Support/com.operasoftware.Opera` y comparten el formato de Chrome para historial y descargas.

- **Browser’s built-in anti-phishing**: Verifícalo comprobando si `fraud_protection_enabled` en el archivo Preferences está establecido en `true` usando `grep`.

Estas rutas y comandos son cruciales para acceder y entender los datos de navegación almacenados por los diferentes navegadores web.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Libro: OS X Incident Response: Scripting and Analysis By Jaron Bradley página 123**


{{#include ../../../banners/hacktricks-training.md}}
