# Artefactos del navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos del navegador <a href="#id-3def" id="id-3def"></a>

Los artefactos del navegador incluyen varios tipos de datos almacenados por los navegadores web, como el historial de navegación, los marcadores y los datos de caché. Estos artefactos se guardan en carpetas específicas del sistema operativo, cuya ubicación y nombre varían según el navegador, aunque generalmente almacenan tipos de datos similares.

Este es un resumen de los artefactos del navegador más comunes:

- **Historial de navegación**: Registra las visitas del usuario a sitios web; resulta útil para identificar visitas a sitios maliciosos.
- **Datos de autocompletado**: Sugerencias basadas en búsquedas frecuentes, que ofrecen información útil al combinarlas con el historial de navegación.
- **Marcadores**: Sitios guardados por el usuario para acceder a ellos rápidamente.
- **Extensiones y complementos**: Extensiones o complementos del navegador instalados por el usuario.
- **Caché**: Almacena contenido web (p. ej., imágenes y archivos JavaScript) para mejorar los tiempos de carga de los sitios web; es valioso para el análisis forense.
- **Inicios de sesión**: Credenciales de inicio de sesión almacenadas.
- **Favicons**: Iconos asociados a sitios web que aparecen en pestañas y marcadores; son útiles para obtener información adicional sobre las visitas del usuario.
- **Sesiones del navegador**: Datos relacionados con las sesiones abiertas del navegador.
- **Descargas**: Registros de los archivos descargados mediante el navegador.
- **Datos de formularios**: Información introducida en formularios web y guardada para sugerencias de autocompletado futuras.
- **Miniaturas**: Imágenes de vista previa de sitios web.
- **Custom Dictionary.txt**: Palabras añadidas por el usuario al diccionario del navegador.

## Firefox

Firefox organiza los datos del usuario en perfiles, almacenados en ubicaciones específicas según el sistema operativo:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un archivo `profiles.ini` dentro de estos directorios enumera los perfiles de usuario. Los datos de cada perfil se almacenan en una carpeta cuyo nombre aparece en la variable `Path` de `profiles.ini`, ubicado en el mismo directorio que el propio `profiles.ini`. Si falta la carpeta de un perfil, es posible que se haya eliminado.

Dentro de cada carpeta de perfil, puedes encontrar varios archivos importantes:<sup>[[1]](#references)</sup>

- **places.sqlite**: Almacena el historial, los marcadores y las descargas. Herramientas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) en Windows pueden acceder a los datos del historial.
  - Usa consultas SQL específicas para extraer información del historial y las descargas.
- **bookmarkbackups**: Contiene copias de seguridad de los marcadores.
- **formhistory.sqlite**: Almacena datos de formularios web.
- **handlers.json**: Administra los controladores de protocolos.
- **persdict.dat**: Palabras del diccionario personalizado.
- **addons.json** y **extensions.sqlite**: Información sobre los complementos y las extensiones instalados.
- **cookies.sqlite**: Almacena cookies; puedes inspeccionarlas en Windows con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** o **startupCache**: Datos de caché, accesibles con herramientas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Almacena favicons.
- **prefs.js**: Configuración y preferencias del usuario.
- **downloads.sqlite**: Base de datos de descargas antigua, ahora integrada en places.sqlite.
- **thumbnails**: Miniaturas de sitios web.
- **logins.json**: Información de inicio de sesión cifrada.
- **key4.db** o **key3.db**: Almacena las claves de cifrado que protegen la información confidencial.

Además, puedes comprobar la configuración anti-phishing del navegador buscando entradas `browser.safebrowsing` en `prefs.js`, que indican si las funciones de navegación segura están activadas o desactivadas.<sup>[[2]](#references)</sup>

Para descifrar los inicios de sesión guardados de un perfil accesible, debes proporcionar la [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), si está configurada, o recuperarla por separado; el perfil no revela esa contraseña. Confirma que cualquier inicio de sesión recuperado autentica correctamente en su cuenta web. El acceso root de Unix requiere una prueba independiente de que la credencial también es aceptada por la autenticación Unix para root. Puedes revisar los inicios de sesión guardados con [firefox_decrypt](https://github.com/unode/firefox_decrypt). El siguiente ejemplo prueba posibles Firefox Primary Passwords de un archivo de contraseñas:

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

En estos directorios, la mayoría de los datos de usuario se encuentran en las carpetas **Default/** o **ChromeDefaultData/**. Los siguientes archivos contienen datos importantes:<sup>[[1]](#references)</sup>

- **History**: Contiene URL, descargas y palabras clave de búsqueda. En Windows, se puede usar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para leer el historial. La columna "Transition Type" tiene varios significados, como clics del usuario en enlaces, URL escritas, envíos de formularios y recargas de páginas.
- **Cookies**: Almacena cookies. Para inspeccionarlas, está disponible [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene datos en caché. Para inspeccionarlos, los usuarios de Windows pueden utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Las aplicaciones de escritorio basadas en Electron (por ejemplo, Discord) también usan Chromium Simple Cache y dejan abundantes artefactos en el disco. Consulta:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Marcadores del usuario.
- **Web Data**: Contiene el historial de formularios.
- **Favicons**: Almacena los favicons de los sitios web.
- **Login Data**: Incluye credenciales de inicio de sesión, como nombres de usuario y contraseñas.
- **Current Session**/**Current Tabs**: Datos sobre la sesión de navegación actual y las pestañas abiertas.
- **Last Session**/**Last Tabs**: Información sobre los sitios activos durante la última sesión antes de cerrar Chrome.
- **Extensions**: Directorios de extensiones y complementos del navegador.
- **Thumbnails**: Almacena miniaturas de sitios web.
- **Preferences**: Archivo con abundante información, incluida la configuración de plugins, extensiones, ventanas emergentes, notificaciones y más.
- **Protección integrada contra phishing del navegador**: Para comprobar si la protección contra phishing y malware está habilitada, ejecuta `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Busca `{"enabled: true,"}` en la salida.<sup>[[2]](#references)</sup>

El directorio `Local Extension Settings/<extension-id>/` de un perfil de Chromium puede contener datos locales de extensiones, incluido material de claves de gestores de contraseñas. Por ejemplo, [Passbolt indica que su clave privada cifrada se almacena en el almacenamiento local de la extensión del navegador](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), y su [ID de extensión de Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) permite identificar el directorio correspondiente. La mera presencia del directorio no demuestra que contenga una clave ni desbloquea una bóveda: el usuario debe tener acceso a los datos del perfil, una clave privada utilizable y una frase de contraseña, además de una ruta de recuperación/autenticación autorizada al servidor. Si un elemento de la bóveda contiene una contraseña de una cuenta del sistema operativo, se debe verificar por separado la reutilización de esa contraseña. La enumeración rutinaria debe informar únicamente de la ruta de almacenamiento, sin volcar sus archivos LevelDB ni los valores secretos.

## **Recuperación de datos de bases de datos SQLite**

Como se observa en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas con la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestiona sus datos y metadatos en varias ubicaciones, lo que ayuda a separar la información almacenada de sus detalles correspondientes para facilitar el acceso y la gestión.

### Almacenamiento de metadatos

Los metadatos de Internet Explorer se almacenan en `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (donde VX puede ser V01, V16 o V24). El archivo `V01.log` asociado puede mostrar discrepancias en la hora de modificación con respecto a `WebcacheVX.data`, lo que indica que podría ser necesario repararlo con `esentutl /r V01 /d`. Estos metadatos, almacenados en una base de datos ESE, pueden recuperarse e inspeccionarse con herramientas como photorec y [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. En la tabla **Containers**, se pueden identificar las tablas o contenedores específicos donde se almacena cada segmento de datos, incluidos los detalles de caché de otras herramientas de Microsoft, como Skype.

### Inspección de la caché

La herramienta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspeccionar la caché y requiere la ubicación de la carpeta donde se extrajeron los datos de caché. Los metadatos de la caché incluyen el nombre de archivo, el directorio, el número de accesos, el origen de la URL y las marcas de tiempo de creación, acceso, modificación y expiración de la caché.

### Gestión de cookies

Las cookies se pueden explorar con [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Los metadatos incluyen nombres, URL, número de accesos y diversos datos de tiempo. Las cookies persistentes se almacenan en `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mientras que las cookies de sesión residen en la memoria.

### Detalles de descargas

Se puede acceder a los metadatos de las descargas mediante [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); algunos contenedores contienen datos como la URL, el tipo de archivo y la ubicación de descarga. Los archivos físicos se encuentran en `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historial de navegación

Para revisar el historial de navegación, se puede usar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html); se necesita la ubicación de los archivos de historial extraídos y configurar Internet Explorer. Los metadatos incluyen las horas de modificación y acceso, además del número de accesos. Los archivos de historial se encuentran en `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL escritas

Las URL escritas y las horas en que se usaron se almacenan en el registro, dentro de `NTUSER.DAT`, en `Software\Microsoft\InternetExplorer\TypedURLs` y `Software\Microsoft\InternetExplorer\TypedURLsTime`. Allí se registran las últimas 50 URL introducidas por el usuario y las horas en que se escribieron por última vez.

## Microsoft Edge

Microsoft Edge almacena los datos de usuario en `%userprofile%\Appdata\Local\Packages`. Las rutas de los distintos tipos de datos son:<sup>[[1]](#references)</sup>

- **Ruta del perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historial, cookies y descargas**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Configuración, marcadores y lista de lectura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Caché**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Últimas sesiones activas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Los datos de Safari se almacenan en `/Users/$User/Library/Safari`. Entre los archivos principales se incluyen:<sup>[[3]](#references)</sup>

- **History.db**: Contiene las tablas `history_visits` y `history_items`, con las URL y las marcas de tiempo de las visitas. Usa `sqlite3` para consultarlas.
- **Downloads.plist**: Información sobre los archivos descargados.
- **Bookmarks.plist**: Almacena las URL guardadas en marcadores.
- **TopSites.plist**: Sitios visitados con mayor frecuencia.
- **Extensions.plist**: Lista de extensiones del navegador Safari. Usa `plutil` o `pluginkit` para obtenerla.
- **UserNotificationPermissions.plist**: Dominios autorizados para enviar notificaciones push. Usa `plutil` para analizarlo.
- **LastSession.plist**: Pestañas de la última sesión. Usa `plutil` para analizarlo.
- **Protección integrada contra phishing del navegador**: Compruébala con `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una respuesta de 1 indica que la función está activa.<sup>[[2]](#references)</sup>

## Opera

Los datos de Opera se encuentran en `/Users/$USER/Library/Application Support/com.operasoftware.Opera` y usan el mismo formato que Chrome para el historial y las descargas.

- **Protección integrada contra phishing del navegador**: Comprueba con `grep` si `fraud_protection_enabled` está configurado como `true` en el archivo Preferences.<sup>[[2]](#references)</sup>

Estas rutas y comandos son fundamentales para acceder a los datos de navegación almacenados por distintos navegadores web y comprenderlos.

## References

- [1] [Informática forense de navegadores web: guía para realizar análisis forenses de navegadores web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Respuesta a incidentes en macOS | Parte 3: Manipulación del sistema](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Respuesta a incidentes en OS X: scripting y análisis, por Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
