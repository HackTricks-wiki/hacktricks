# Artefactos del Navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefactos del Navegador <a href="#id-3def" id="id-3def"></a>

Los artefactos del navegador incluyen varios tipos de datos almacenados por los navegadores web, como el historial de navegación, marcadores y datos de caché. Estos artefactos se mantienen en carpetas específicas dentro del sistema operativo, variando en ubicación y nombre entre navegadores, pero generalmente almacenando tipos de datos similares.

Aquí hay un resumen de los artefactos de navegador más comunes:

- **Historial de Navegación**: Registra las visitas del usuario a sitios web, útil para identificar visitas a sitios maliciosos.
- **Datos de Autocompletar**: Sugerencias basadas en búsquedas frecuentes, ofreciendo información cuando se combinan con el historial de navegación.
- **Marcadores**: Sitios guardados por el usuario para acceso rápido.
- **Extensiones y Complementos**: Extensiones del navegador o complementos instalados por el usuario.
- **Caché**: Almacena contenido web (por ejemplo, imágenes, archivos JavaScript) para mejorar los tiempos de carga de los sitios web, valioso para el análisis forense.
- **Inicios de Sesión**: Credenciales de inicio de sesión almacenadas.
- **Favicons**: Iconos asociados con sitios web, que aparecen en pestañas y marcadores, útiles para información adicional sobre las visitas del usuario.
- **Sesiones del Navegador**: Datos relacionados con las sesiones abiertas del navegador.
- **Descargas**: Registros de archivos descargados a través del navegador.
- **Datos de Formularios**: Información ingresada en formularios web, guardada para futuras sugerencias de autocompletar.
- **Miniaturas**: Imágenes de vista previa de sitios web.
- **Custom Dictionary.txt**: Palabras añadidas por el usuario al diccionario del navegador.

## Firefox

Firefox organiza los datos del usuario dentro de perfiles, almacenados en ubicaciones específicas según el sistema operativo:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un archivo `profiles.ini` dentro de estos directorios lista los perfiles de usuario. Los datos de cada perfil se almacenan en una carpeta nombrada en la variable `Path` dentro de `profiles.ini`, ubicada en el mismo directorio que `profiles.ini` mismo. Si falta la carpeta de un perfil, puede haber sido eliminada.

Dentro de cada carpeta de perfil, puedes encontrar varios archivos importantes:

- **places.sqlite**: Almacena historial, marcadores y descargas. Herramientas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) en Windows pueden acceder a los datos del historial.
- Usa consultas SQL específicas para extraer información de historial y descargas.
- **bookmarkbackups**: Contiene copias de seguridad de marcadores.
- **formhistory.sqlite**: Almacena datos de formularios web.
- **handlers.json**: Gestiona los controladores de protocolo.
- **persdict.dat**: Palabras del diccionario personalizado.
- **addons.json** y **extensions.sqlite**: Información sobre complementos y extensiones instalados.
- **cookies.sqlite**: Almacenamiento de cookies, con [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible para inspección en Windows.
- **cache2/entries** o **startupCache**: Datos de caché, accesibles a través de herramientas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Almacena favicons.
- **prefs.js**: Configuraciones y preferencias del usuario.
- **downloads.sqlite**: Base de datos de descargas antiguas, ahora integrada en places.sqlite.
- **thumbnails**: Miniaturas de sitios web.
- **logins.json**: Información de inicio de sesión encriptada.
- **key4.db** o **key3.db**: Almacena claves de encriptación para asegurar información sensible.

Además, verificar la configuración de anti-phishing del navegador se puede hacer buscando entradas `browser.safebrowsing` en `prefs.js`, indicando si las funciones de navegación segura están habilitadas o deshabilitadas.

Para intentar descifrar la contraseña maestra, puedes usar [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Con el siguiente script y llamada puedes especificar un archivo de contraseña para hacer fuerza bruta:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (417).png>)

## Google Chrome

Google Chrome almacena perfiles de usuario en ubicaciones específicas según el sistema operativo:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dentro de estos directorios, la mayoría de los datos del usuario se pueden encontrar en las carpetas **Default/** o **ChromeDefaultData/**. Los siguientes archivos contienen datos significativos:

- **History**: Contiene URLs, descargas y palabras clave de búsqueda. En Windows, se puede usar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para leer el historial. La columna "Transition Type" tiene varios significados, incluidos clics del usuario en enlaces, URLs escritas, envíos de formularios y recargas de página.
- **Cookies**: Almacena cookies. Para inspección, está disponible [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Contiene datos en caché. Para inspeccionar, los usuarios de Windows pueden utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks**: Marcadores del usuario.
- **Web Data**: Contiene el historial de formularios.
- **Favicons**: Almacena favicons de sitios web.
- **Login Data**: Incluye credenciales de inicio de sesión como nombres de usuario y contraseñas.
- **Current Session**/**Current Tabs**: Datos sobre la sesión de navegación actual y las pestañas abiertas.
- **Last Session**/**Last Tabs**: Información sobre los sitios activos durante la última sesión antes de que se cerrara Chrome.
- **Extensions**: Directorios para extensiones y complementos del navegador.
- **Thumbnails**: Almacena miniaturas de sitios web.
- **Preferences**: Un archivo rico en información, que incluye configuraciones para complementos, extensiones, ventanas emergentes, notificaciones y más.
- **Browser’s built-in anti-phishing**: Para verificar si la protección contra phishing y malware está habilitada, ejecute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Busque `{"enabled: true,"}` en la salida.

## **Recuperación de Datos de SQLite DB**

Como se puede observar en las secciones anteriores, tanto Chrome como Firefox utilizan bases de datos **SQLite** para almacenar los datos. Es posible **recuperar entradas eliminadas utilizando la herramienta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **o** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gestiona sus datos y metadatos en varias ubicaciones, ayudando a separar la información almacenada y sus detalles correspondientes para un fácil acceso y gestión.

### Almacenamiento de Metadatos

Los metadatos para Internet Explorer se almacenan en `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (siendo VX V01, V16 o V24). Acompañando esto, el archivo `V01.log` puede mostrar discrepancias en el tiempo de modificación con `WebcacheVX.data`, indicando la necesidad de reparación utilizando `esentutl /r V01 /d`. Estos metadatos, alojados en una base de datos ESE, pueden ser recuperados e inspeccionados utilizando herramientas como photorec y [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. Dentro de la tabla **Containers**, se puede discernir las tablas o contenedores específicos donde se almacena cada segmento de datos, incluidos los detalles de caché para otras herramientas de Microsoft como Skype.

### Inspección de Caché

La herramienta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite la inspección de caché, requiriendo la ubicación de la carpeta de extracción de datos de caché. Los metadatos de caché incluyen nombre de archivo, directorio, conteo de accesos, origen de URL y marcas de tiempo que indican la creación, acceso, modificación y tiempos de expiración de la caché.

### Gestión de Cookies

Las cookies se pueden explorar utilizando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), con metadatos que abarcan nombres, URLs, conteos de acceso y varios detalles relacionados con el tiempo. Las cookies persistentes se almacenan en `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, mientras que las cookies de sesión residen en memoria.

### Detalles de Descargas

Los metadatos de descargas son accesibles a través de [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), con contenedores específicos que contienen datos como URL, tipo de archivo y ubicación de descarga. Los archivos físicos se pueden encontrar en `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historial de Navegación

Para revisar el historial de navegación, se puede usar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), requiriendo la ubicación de los archivos de historial extraídos y la configuración para Internet Explorer. Los metadatos aquí incluyen tiempos de modificación y acceso, junto con conteos de acceso. Los archivos de historial se encuentran en `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs Escritas

Las URLs escritas y sus tiempos de uso se almacenan en el registro bajo `NTUSER.DAT` en `Software\Microsoft\InternetExplorer\TypedURLs` y `Software\Microsoft\InternetExplorer\TypedURLsTime`, rastreando las últimas 50 URLs ingresadas por el usuario y sus últimos tiempos de entrada.

## Microsoft Edge

Microsoft Edge almacena datos de usuario en `%userprofile%\Appdata\Local\Packages`. Las rutas para varios tipos de datos son:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Los datos de Safari se almacenan en `/Users/$User/Library/Safari`. Los archivos clave incluyen:

- **History.db**: Contiene tablas `history_visits` y `history_items` con URLs y marcas de tiempo de visitas. Use `sqlite3` para consultar.
- **Downloads.plist**: Información sobre archivos descargados.
- **Bookmarks.plist**: Almacena URLs marcadas.
- **TopSites.plist**: Sitios más visitados.
- **Extensions.plist**: Lista de extensiones del navegador Safari. Use `plutil` o `pluginkit` para recuperar.
- **UserNotificationPermissions.plist**: Dominios permitidos para enviar notificaciones. Use `plutil` para analizar.
- **LastSession.plist**: Pestañas de la última sesión. Use `plutil` para analizar.
- **Browser’s built-in anti-phishing**: Verifique usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Una respuesta de 1 indica que la función está activa.

## Opera

Los datos de Opera residen en `/Users/$USER/Library/Application Support/com.operasoftware.Opera` y comparte el formato de Chrome para el historial y las descargas.

- **Browser’s built-in anti-phishing**: Verifique comprobando si `fraud_protection_enabled` en el archivo de Preferencias está configurado como `true` usando `grep`.

Estas rutas y comandos son cruciales para acceder y comprender los datos de navegación almacenados por diferentes navegadores web.

## Referencias

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
