<details>

<summary><strong>Aprende hacking en AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares de robo**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

---

# Verificar posibles acciones dentro de la aplicación GUI

Los **Diálogos comunes** son esas opciones de **guardar un archivo**, **abrir un archivo**, seleccionar una fuente, un color... La mayoría de ellos **ofrecerán una funcionalidad completa de Explorador**. Esto significa que podrás acceder a funcionalidades de Explorador si puedes acceder a estas opciones:

* Cerrar/Cerrar como
* Abrir/Abrir con
* Imprimir
* Exportar/Importar
* Buscar
* Escanear

Deberías verificar si puedes:

* Modificar o crear nuevos archivos
* Crear enlaces simbólicos
* Acceder a áreas restringidas
* Ejecutar otras aplicaciones

## Ejecución de comandos

Tal vez **usando la opción `Abrir con`** puedas abrir/ejecutar algún tipo de shell.

### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que se pueden usar para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Saltando restricciones de ruta

* **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
* **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Enlaces simbólicos**
* **Accesos directos**: CTRL+N (abrir nueva sesión), CTRL+R (Ejecutar comandos), CTRL+SHIFT+ESC (Administrador de tareas),  Windows+E (abrir explorador), CTRL-B, CTRL-I (Favoritos), CTRL-H (Historial), CTRL-L, CTRL-O (Diálogo de Archivo/Abrir), CTRL-P (Diálogo de Imprimir), CTRL-S (Guardar como)
* Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **URIs de shell**: _shell:Herramientas Administrativas, shell:Bibliotecas de Documentos, shell:Bibliotecas, shell:Perfiles de Usuario, shell:Personal, shell:Carpeta de Inicio de Búsqueda, shell:Sistemas shell:Red, shell:Enviar a, shell:Perfiles de Usuarios, shell:Herramientas Administrativas Comunes, shell:Carpeta de Mi PC, shell:Carpeta de Internet_
* **Rutas UNC**: Rutas para conectarse a carpetas compartidas. Deberías intentar conectarte al C$ de la máquina local ("\\\127.0.0.1\c$\Windows\System32")
* **Más rutas UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Descarga tus binarios

Consola: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorador: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor de registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Accediendo al sistema de archivos desde el navegador

| RUTA                | RUTA              | RUTA               | RUTA                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Accesos directos

* Teclas de acceso rápido – Presiona SHIFT 5 veces
* Teclas del ratón – SHIFT+ALT+NUMLOCK
* Alto contraste – SHIFT+ALT+PRINTSCN
* Teclas de alternancia – Mantén presionado NUMLOCK durante 5 segundos
* Teclas de filtro – Mantén presionado el botón derecho SHIFT durante 12 segundos
* WINDOWS+F1 – Búsqueda de Windows
* WINDOWS+D – Mostrar escritorio
* WINDOWS+E – Abrir Explorador de Windows
* WINDOWS+R – Ejecutar
* WINDOWS+U – Centro de accesibilidad
* WINDOWS+F – Búsqueda
* SHIFT+F10 – Menú contextual
* CTRL+SHIFT+ESC – Administrador de tareas
* CTRL+ALT+DEL – Pantalla de inicio en versiones más nuevas de Windows
* F1 – Ayuda F3 – Búsqueda
* F6 – Barra de direcciones
* F11 – Alternar pantalla completa dentro de Internet Explorer
* CTRL+H – Historial de Internet Explorer
* CTRL+T – Internet Explorer – Nueva pestaña
* CTRL+N – Internet Explorer – Nueva página
* CTRL+O – Abrir archivo
* CTRL+S – Guardar CTRL+N – Nueva RDP / Citrix
## Deslizamientos

* Deslice desde el lado izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizando la aplicación KIOSK y accediendo directamente a todo el sistema operativo;
* Deslice desde el lado derecho hacia la izquierda para abrir el Centro de Acción, minimizando la aplicación KIOSK y accediendo directamente a todo el sistema operativo;
* Deslice desde el borde superior para hacer visible la barra de título de una aplicación abierta en modo de pantalla completa;
* Deslice hacia arriba desde la parte inferior para mostrar la barra de tareas en una aplicación de pantalla completa.

## Trucos de Internet Explorer

### 'Barra de herramientas de imagen'

Es una barra de herramientas que aparece en la parte superior izquierda de la imagen cuando se hace clic en ella. Podrá Guardar, Imprimir, Enviar por correo electrónico, Abrir "Mis imágenes" en el Explorador. El Kiosk debe estar utilizando Internet Explorer.

### Protocolo Shell

Escriba estas URL para obtener una vista de Explorador:

* `shell:Herramientas Administrativas`
* `shell:BibliotecaDocumentos`
* `shell:Bibliotecas`
* `shell:PerfilesUsuarios`
* `shell:Personal`
* `shell:CarpetaInicioBusqueda`
* `shell:CarpetaSitiosRed`
* `shell:EnviarA`
* `shell:PerfilesUsuarios`
* `shell:HerramientasAdministrativasComunes`
* `shell:MiPC`
* `shell:CarpetaInternet`
* `Shell:Perfil`
* `Shell:ArchivosPrograma`
* `Shell:Sistema`
* `Shell:CarpetaPanelControl`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel de Control
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mi PC
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mis sitios de red
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Mostrar extensiones de archivo

Consulte esta página para obtener más información: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Trucos de navegadores

Hacer copias de seguridad de versiones iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crear un cuadro de diálogo común utilizando JavaScript y acceder al explorador de archivos: `document.write('<input/type=file>')`
Fuente: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestos y botones

* Deslice hacia arriba con cuatro (o cinco) dedos / Toque dos veces el botón de inicio: Para ver la vista de multitarea y cambiar de aplicación

* Deslice de un lado a otro con cuatro o cinco dedos: Para cambiar a la siguiente/anterior aplicación

* Pellizcar la pantalla con cinco dedos / Toque el botón de inicio / Deslice hacia arriba con 1 dedo desde la parte inferior de la pantalla en un movimiento rápido hacia arriba: Para acceder a Inicio

* Deslice un dedo desde la parte inferior de la pantalla solo 1-2 pulgadas (lento): Aparecerá el dock

* Deslice hacia abajo desde la parte superior de la pantalla con 1 dedo: Para ver sus notificaciones

* Deslice hacia abajo con 1 dedo en la esquina superior derecha de la pantalla: Para ver el centro de control del iPad Pro

* Deslice 1 dedo desde el lado izquierdo de la pantalla 1-2 pulgadas: Para ver la vista de Hoy

* Deslice rápidamente 1 dedo desde el centro de la pantalla hacia la derecha o izquierda: Para cambiar a la siguiente/anterior aplicación

* Mantenga presionado el botón de Encendido/Apagado/Suspensión en la esquina superior derecha del iPad + Mueva el deslizador de Apagar todo el camino hacia la derecha: Para apagar

* Presione el botón de Encendido/Apagado/Suspensión en la esquina superior derecha del iPad y el botón de Inicio durante unos segundos: Para forzar un apagado completo

* Presione el botón de Encendido/Apagado/Suspensión en la esquina superior derecha del iPad y el botón de Inicio rápidamente: Para tomar una captura de pantalla que aparecerá en la esquina inferior izquierda de la pantalla. Presione ambos botones al mismo tiempo brevemente, ya que si los mantiene presionados durante unos segundos se realizará un apagado completo.

## Accesos directos

Debe tener un teclado para iPad o un adaptador de teclado USB. Aquí se mostrarán solo los accesos directos que podrían ayudar a escapar de la aplicación.

| Tecla | Nombre         |
| --- | ------------ |
| ⌘   | Comando      |
| ⌥   | Opción (Alt) |
| ⇧   | Mayúsculas        |
| ↩   | Retorno       |
| ⇥   | Tabulador          |
| ^   | Control      |
| ←   | Flecha izquierda   |
| →   | Flecha derecha  |
| ↑   | Flecha arriba     |
| ↓   | Flecha abajo   |

### Accesos directos del sistema

Estos accesos directos son para la configuración visual y de sonido, dependiendo del uso del iPad.

| Acceso directo | Acción                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Disminuir brillo de la pantalla                                                                    |
| F2       | Aumentar brillo de la pantalla                                                                |
| F7       | Retroceder una canción                                                                  |
| F8       | Reproducir/pausar                                                                     |
| F9       | Saltar canción                                                                      |
| F10      | Silenciar                                                                           |
| F11      | Disminuir volumen                                                                |
| F12      | Aumentar volumen                                                                |
| ⌘ Espacio  | Mostrar una lista de idiomas disponibles; para elegir uno, toque nuevamente la barra espaciadora. |

### Navegación en iPad

| Acceso directo                                           | Acción                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir a Inicio                                              |
| ⌘⇧H (Comando-Mayúsculas-H)                              | Ir a Inicio                                              |
| ⌘ (Espacio)                                          | Abrir Spotlight                                          |
| ⌘⇥ (Comando-Tabulador)                                   | Listar las últimas diez aplicaciones utilizadas                                 |
| ⌘\~                                                | Ir a la última aplicación                                       |
| ⌘⇧3 (Comando-Mayúsculas-3)                              | Captura de pantalla (aparece en la esquina inferior izquierda para guardarla o actuar sobre ella) |
| ⌘⇧4                                                | Captura de pantalla y ábrala en el editor                    |
| Mantener presionado ⌘                                   | Lista de accesos directos disponibles para la aplicación                 |
| ⌘⌥D (Comando-Opción/Alt-D)                         | Muestra el dock                                      |
| ^⌥H (Control-Opción-H)                             | Botón de inicio                                             |
| ^⌥H H (Control-Opción-H-H)                         | Mostrar barra de multitarea                                      |
| ^⌥I (Control-Opción-i)                             | Selector de elementos                                            |
| Escape                                             | Botón de retroceso                                             |
| → (Flecha derecha)                                    | Siguiente elemento                                               |
| ← (Flecha izquierda)                                     | Elemento anterior                                           |
| ↑↓ (Flecha arriba, Flecha abajo)                          | Tocar simultáneamente el elemento seleccionado                        |
| ⌥ ↓ (Opción-Flecha abajo)                            | Desplazarse hacia abajo                                             |
| ⌥↑ (Opción-Flecha arriba)                               | Desplazarse hacia arriba                                               |
| ⌥← o ⌥→ (Opción-Flecha izquierda o Opción-Flecha derecha) | Desplazarse hacia la izquierda o derecha                                    |
| ^⌥S (Control-Opción-S)                             | Activar o desactivar el habla de VoiceOver                         |
| ⌘⇧⇥ (Comando-Mayúsculas-Tabulador)                            | Cambiar a la aplicación anterior                              |
| ⌘⇥ (Comando-Tabulador)                                   | Volver a la aplicación original                         |
| ←+→, luego Opción + ← o Opción+→                   | Navegar a través del Dock                                   |
### Atajos de Safari

| Atajo                   | Acción                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)          | Abrir ubicación                                  |
| ⌘T                      | Abrir una nueva pestaña                          |
| ⌘W                      | Cerrar la pestaña actual                         |
| ⌘R                      | Actualizar la pestaña actual                    |
| ⌘.                      | Detener la carga de la pestaña actual            |
| ^⇥                      | Cambiar a la siguiente pestaña                   |
| ^⇧⇥ (Control-Mayús-Tab) | Moverse a la pestaña anterior                    |
| ⌘L                      | Seleccionar el campo de entrada de texto/URL para modificarlo |
| ⌘⇧T (Comando-Mayús-T)   | Abrir la última pestaña cerrada (se puede usar varias veces) |
| ⌘\[                     | Retroceder una página en tu historial de navegación |
| ⌘]                      | Avanzar una página en tu historial de navegación |
| ⌘⇧R                     | Activar el Modo Lector                            |

### Atajos de Correo

| Atajo                     | Acción                       |
| ------------------------- | ---------------------------- |
| ⌘L                        | Abrir ubicación              |
| ⌘T                        | Abrir una nueva pestaña      |
| ⌘W                        | Cerrar la pestaña actual     |
| ⌘R                        | Actualizar la pestaña actual |
| ⌘.                        | Detener la carga de la pestaña actual |
| ⌘⌥F (Comando-Opción/Alt-F) | Buscar en tu buzón de correo  |

# Referencias

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares de robo**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
