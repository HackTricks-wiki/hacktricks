# Artefactos del navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos de los navegadores <a href="#id-3def" id="id-3def"></a>

Los artefactos del navegador incluyen varios tipos de datos almacenados por los navegadores web, como el historial de navegación, los marcadores y los datos de caché. Estos artefactos se conservan en carpetas específicas dentro del sistema operativo, cuya ubicación y nombre varían según el navegador, aunque generalmente almacenan tipos de datos similares.

Este es un resumen de los artefactos del navegador más comunes:

- **Historial de navegación**: Registra las visitas del usuario a sitios web y resulta útil para identificar visitas a sitios maliciosos.
- **Datos de autocompletado**: Sugerencias basadas en búsquedas frecuentes, que ofrecen información útil al combinarlas con el historial de navegación.
- **Marcadores**: Sitios guardados por el usuario para acceder rápidamente a ellos.
- **Extensiones y complementos**: Extensiones o complementos del navegador instalados por el usuario.
- **Caché**: Almacena contenido web (por ejemplo, imágenes y archivos JavaScript) para mejorar los tiempos de carga de los sitios web, y resulta valiosa para el análisis forense.
- **Logins**: Credenciales de inicio de sesión almacenadas.
- **Favicons**: Iconos asociados a sitios web que aparecen en pestañas y marcadores, útiles para obtener información adicional sobre las visitas del usuario.
- **Sesiones del navegador**: Datos relacionados con las sesiones abiertas del navegador.
- **Descargas**: Registros de archivos descargados mediante el navegador.
- **Datos de formularios**: Información introducida en formularios web y guardada para futuras sugerencias de autocompletado.
- **Miniaturas**: Imágenes de vista previa de sitios web.
- **Custom Dictionary.txt**: Palabras añadidas por el usuario al diccionario del navegador.

## Firefox

Firefox organiza los datos del usuario dentro de perfiles, almacenados en ubicaciones específicas según el sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un archivo `profiles.ini` dentro de estos directorios contiene una lista de los perfiles de usuario. Los datos de cada perfil se almacenan en una carpeta cuyo nombre se encuentra en la variable `Path` dentro de `profiles.ini`, ubicada en el mismo directorio que el propio archivo `profiles.ini`. Si falta la carpeta de un perfil, es posible que se haya eliminado.

Dentro de cada carpeta de perfil se pueden encontrar varios archivos importantes:<sup>[[1]](#references)</sup>

- **places.sqlite**: Almacena el historial, los marcadores y las descargas. Herramientas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) en Windows pueden acceder a los datos del historial.
- Usa consultas SQL específicas para extraer información del historial y de las descargas.
- **bookmarkbackups**: Contiene copias de seguridad de los marcadores.
- **formhistory.sqlite**: Almacena los datos de los formularios web.
- **handlers.json**: Gestiona los controladores de protocolos.
- **persdict.dat**: Palabras del diccionario personalizado.
- **addons.json** y **extensions.sqlite**: Información sobre los complementos y extensiones instalados.
- **cookies.sqlite**: Almacenamiento de cookies; en Windows se puede usar [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) para inspeccionarlo.
- **cache2/entries** o **startupCache**: Datos de caché, accesibles mediante herramientas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Almacena los favicons.
- **prefs.js**: Configuraciones y preferencias del usuario.
- **downloads.sqlite**: Base de datos de descargas antigua, ahora integrada en places.sqlite.
- **thumbnails**: Miniaturas de sitios web.
- **logins.json**: Información de inicio de sesión cifrada.
- **key4.db** o **key3.db**: Almacena las claves de cifrado utilizadas para proteger información confidencial.

Además, se pueden comprobar las configuraciones anti-phishing del navegador buscando entradas `browser.safebrowsing` en `prefs.js`, que indican si las funciones de navegación segura están habilitadas o deshabilitadas.<sup>[[2]](#references)</sup>

Para intentar descifrar la contraseña maestra, puedes usar [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con el siguiente script y llamada puedes especificar un archivo de contraseñas para realizar brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artefactos de navegadores - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome almacena los perfiles de usuario en ubicaciones específicas según el sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dentro de estos directorios, la mayoría de los datos de usuario se encuentran en las carpetas **Default/** o **ChromeDefaultData/**. Los siguientes archivos contienen datos importantes:<sup>[[1]](#references)</sup>

- **History**: Contiene URL, descargas y palabras clave de búsqueda. En Windows, se puede utilizar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para leer el historial. La columna "Transition Type" tiene varios significados, incluidos los clics del usuario en enlaces, las URL escritas, los envíos de formularios y las recargas de páginas.
- **Cookies**: Almacena cookies. Para su inspección, está disponible [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene datos almacenados en caché. Para inspeccionarlos, los usuarios de Windows pueden utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Las aplicaciones de escritorio basadas en Electron (por ejemplo, Discord) también utilizan Chromium Simple Cache y dejan abundantes artefactos en disco. Consulta:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Marcadores del usuario.
- **Web Data**: Contiene el historial de formularios.
- **Favicons**: Almacena los favicons de los sitios web.
- **Login Data**: Incluye credenciales de inicio de sesión, como nombres de usuario y contraseñas.
- **Current Session**/**Current Tabs**: Datos sobre la sesión de navegación actual y las pestañas abiertas.
- **Last Session**/**Last Tabs**: Información sobre los sitios activos durante la última sesión antes de cerrar Chrome.
- **Extensions**: Directorios de extensiones y addons del navegador.
- **Thumbnails**: Almacena miniaturas de sitios web.
- **Preferences**: Un archivo con abundante información, incluidos ajustes de plugins, extensiones, ventanas emergentes, notificaciones y más.
- **anti-phishing integrado del navegador**: Para comprobar si la protección contra anti-phishing y malware está habilitada, ejecuta `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Busca `{"enabled: true,"}` en la salida.<sup>[[2]](#references)</sup>

## **Recuperación de datos de DB SQLite**

Como se puede observar en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas utilizando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestiona sus datos y metadatos en varias ubicaciones, lo que ayuda a separar la información almacenada de sus detalles correspondientes para facilitar el acceso y la gestión.

### Almacenamiento de metadatos

Los metadatos de Internet Explorer se almacenan en `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (donde VX puede ser V01, V16 o V24). Además, el archivo `V01.log` podría mostrar discrepancias en la hora de modificación con respecto a `WebcacheVX.data`, lo que indica la necesidad de repararlo mediante `esentutl /r V01 /d`. Estos metadatos, almacenados en una base de datos ESE, pueden recuperarse e inspeccionarse utilizando herramientas como photorec y [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. Dentro de la tabla **Containers**, se pueden identificar las tablas o contenedores específicos donde se almacena cada segmento de datos, incluidos los detalles de caché de otras herramientas de Microsoft, como Skype.

### Inspección de la caché

La herramienta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspeccionar la caché y requiere la ubicación de la carpeta donde se extraerán los datos de caché. Los metadatos de la caché incluyen el nombre del archivo, el directorio, el número de accesos, el origen de la URL y las marcas de tiempo que indican las horas de creación, acceso, modificación y expiración de la caché.

### Gestión de cookies

Las cookies se pueden explorar mediante [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), cuyos metadatos incluyen nombres, URL, números de accesos y varios detalles relacionados con el tiempo. Las cookies persistentes se almacenan en `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mientras que las cookies de sesión residen en la memoria.

### Detalles de las descargas

Los metadatos de las descargas son accesibles mediante [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), cuyos contenedores específicos almacenan datos como la URL, el tipo de archivo y la ubicación de descarga. Los archivos físicos se encuentran en `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historial de navegación

Para revisar el historial de navegación, se puede utilizar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), que requiere la ubicación de los archivos de historial extraídos y la configuración de Internet Explorer. Estos metadatos incluyen las horas de modificación y acceso, además del número de accesos. Los archivos del historial se encuentran en `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL escritas

Las URL escritas y sus tiempos de uso se almacenan en el registro, dentro de `NTUSER.DAT`, en `Software\Microsoft\InternetExplorer\TypedURLs` y `Software\Microsoft\InternetExplorer\TypedURLsTime`. Estos datos registran las últimas 50 URL introducidas por el usuario y las horas en que se introdujeron por última vez.

## Microsoft Edge

Microsoft Edge almacena los datos de usuario en `%userprofile%\Appdata\Local\Packages`. Las rutas para los distintos tipos de datos son:<sup>[[1]](#references)</sup>

- **Ruta del perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historial, cookies y descargas**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ajustes, marcadores y lista de lectura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Caché**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Últimas sesiones activas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Los datos de Safari se almacenan en `/Users/$User/Library/Safari`. Entre los archivos importantes se incluyen:<sup>[[3]](#references)</sup>

- **History.db**: Contiene las tablas `history_visits` y `history_items`, con las URL y las marcas de tiempo de las visitas. Utiliza `sqlite3` para realizar consultas.
- **Downloads.plist**: Información sobre los archivos descargados.
- **Bookmarks.plist**: Almacena las URL guardadas en marcadores.
- **TopSites.plist**: Sitios visitados con mayor frecuencia.
- **Extensions.plist**: Lista de extensiones del navegador Safari. Utiliza `plutil` o `pluginkit` para recuperarla.
- **UserNotificationPermissions.plist**: Dominios autorizados para enviar notificaciones push. Utiliza `plutil` para analizarlo.
- **LastSession.plist**: Pestañas de la última sesión. Utiliza `plutil` para analizarlo.
- **anti-phishing integrado del navegador**: Compruébalo mediante `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una respuesta de 1 indica que la función está activa.<sup>[[2]](#references)</sup>

## Opera

Los datos de Opera se encuentran en `/Users/$USER/Library/Application Support/com.operasoftware.Opera` y utilizan el mismo formato que Chrome para el historial y las descargas.

- **anti-phishing integrado del navegador**: Verifica si `fraud_protection_enabled` en el archivo Preferences está establecido en `true` utilizando `grep`.<sup>[[2]](#references)</sup>

Estas rutas y comandos son fundamentales para acceder a los datos de navegación almacenados por los distintos navegadores web y comprenderlos.

## Referencias

- [1] [Análisis forense de navegadores web: guía para realizar análisis forenses de navegadores web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Respuesta ante incidentes en macOS | Parte 3: Manipulación del sistema](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Respuesta ante incidentes en OS X: scripting y análisis, por Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
