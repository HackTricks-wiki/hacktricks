<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Revisa posibles acciones dentro de la aplicación GUI

**Cuadros de diálogo comunes** son aquellas opciones de **guardar un archivo**, **abrir un archivo**, seleccionar una fuente, un color... La mayoría ofrecerán **funcionalidad completa de Explorer**. Esto significa que podrás acceder a funcionalidades de Explorer si puedes acceder a estas opciones:

* Cerrar/Guardar como
* Abrir/Abrir con
* Imprimir
* Exportar/Importar
* Buscar
* Escanear

Deberías verificar si puedes:

* Modificar o crear nuevos archivos
* Crear enlaces simbólicos
* Obtener acceso a áreas restringidas
* Ejecutar otras aplicaciones

## Ejecución de comandos

Quizás **usando la opción** _**Abrir con**_ puedas abrir/ejecutar algún tipo de shell.

### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que pueden ser usados para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Eludir restricciones de ruta

* **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
* **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Enlaces simbólicos**
* **Atajos**: CTRL+N (abrir nueva sesión), CTRL+R (Ejecutar comandos), CTRL+SHIFT+ESC (Administrador de tareas),  Windows+E (abrir explorador), CTRL-B, CTRL-I (Favoritos), CTRL-H (Historial), CTRL-L, CTRL-O (Diálogo de archivo/abrir), CTRL-P (Diálogo de imprimir), CTRL-S (Guardar como)
* Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
* **URIs de Shell**: _shell:Herramientas administrativas, shell:Biblioteca de documentos, shell:Bibliotecas, shell:Perfiles de usuario, shell:Personal, shell:Carpeta de búsqueda, shell:Carpeta de lugares de red, shell:Enviar a, shell:Perfiles de usuario, shell:Herramientas administrativas comunes, shell:Carpeta de mi PC, shell:Carpeta de Internet_
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

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## Atajos

* Teclas adhesivas – Presiona SHIFT 5 veces
* Teclas del ratón – SHIFT+ALT+NUMLOCK
* Alto contraste – SHIFT+ALT+PRINTSCN
* Teclas de alternancia – Mantén presionado NUMLOCK durante 5 segundos
* Teclas de filtro – Mantén presionada la tecla SHIFT derecha durante 12 segundos
* WINDOWS+F1 – Búsqueda de Windows
* WINDOWS+D – Mostrar escritorio
* WINDOWS+E – Lanzar Explorador de Windows
* WINDOWS+R – Ejecutar
* WINDOWS+U – Centro de accesibilidad
* WINDOWS+F – Buscar
* SHIFT+F10 – Menú contextual
* CTRL+SHIFT+ESC – Administrador de tareas
* CTRL+ALT+DEL – Pantalla de inicio en versiones más nuevas de Windows
* F1 – Ayuda F3 – Buscar
* F6 – Barra de direcciones
* F11 – Alternar pantalla completa en Internet Explorer
* CTRL+H – Historial de Internet Explorer
* CTRL+T – Internet Explorer – Nueva pestaña
* CTRL+N – Internet Explorer – Nueva página
* CTRL+O – Abrir archivo
* CTRL+S – Guardar CTRL+N – Nuevo RDP / Citrix

## Deslizamientos

* Desliza desde el lado izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizando la aplicación KIOSK y accediendo al sistema operativo completo directamente;
* Desliza desde el lado derecho hacia la izquierda para abrir el Centro de acción, minimizando la aplicación KIOSK y accediendo al sistema operativo completo directamente;
* Desliza desde el borde superior para hacer visible la barra de título de una aplicación abierta en modo de pantalla completa;
* Desliza hacia arriba desde la parte inferior para mostrar la barra de tareas en una aplicación de pantalla completa.

## Trucos de Internet Explorer

### 'Barra de herramientas de imagen'

Es una barra de herramientas que aparece en la parte superior izquierda de la imagen cuando se hace clic. Podrás Guardar, Imprimir, Mailto, Abrir "Mis imágenes" en Explorer. El Kiosco debe estar utilizando Internet Explorer.

### Protocolo Shell

Escribe estas URLs para obtener una vista de Explorer:

* `shell:Herramientas administrativas`
* `shell:Biblioteca de documentos`
* `shell:Bibliotecas`
* `shell:Perfiles de usuario`
* `shell:Personal`
* `shell:Carpeta de búsqueda`
* `shell:Carpeta de lugares de red`
* `shell:Enviar a`
* `shell:Perfiles de usuario`
* `shell:Herramientas administrativas comunes`
* `shell:Carpeta de mi PC`
* `shell:Carpeta de Internet`
* `Shell:Perfil`
* `Shell:ProgramFiles`
* `Shell:Sistema`
* `Shell:Carpeta de control`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel de control
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mi PC
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mis lugares de red
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# Trucos de navegadores

Versiones de respaldo de iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crea un cuadro de diálogo común usando JavaScript y accede al explorador de archivos: `document.write('<input/type=file>')`
Fuente: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestos y botones

### Deslizar hacia arriba con cuatro (o cinco) dedos / Tocar dos veces el botón de inicio

Para ver la vista de multitarea y cambiar de aplicación

### Deslizar de un lado a otro con cuatro o cinco dedos

Para cambiar a la siguiente/última aplicación

### Pellizcar la pantalla con cinco dedos / Tocar el botón de inicio / Deslizar hacia arriba con 1 dedo desde la parte inferior de la pantalla en un movimiento rápido hacia arriba

Para acceder al inicio

### Deslizar 1 dedo desde la parte inferior de la pantalla solo 1-2 pulgadas (lento)

Aparecerá el dock

### Deslizar hacia abajo desde la parte superior de la pantalla con 1 dedo

Para ver tus notificaciones

### Deslizar hacia abajo con 1 dedo desde la esquina superior derecha de la pantalla

Para ver el centro de control del iPad Pro

### Deslizar 1 dedo desde el lado izquierdo de la pantalla 1-2 pulgadas

Para ver la vista de Hoy

### Deslizar rápido 1 dedo desde el centro de la pantalla hacia la derecha o izquierda

Para cambiar a la siguiente/última aplicación

### Mantener presionado el botón de Encendido/**Apagado**/Suspensión en la esquina superior derecha del **iPad +** Mover el deslizador de **apagar** completamente hacia la derecha,

Para apagar

### Presionar el botón de Encendido/**Apagado**/Suspensión en la esquina superior derecha del **iPad y el botón de inicio durante unos segundos**

Para forzar un apagado duro

### Presionar rápidamente el botón de Encendido/**Apagado**/Suspensión en la esquina superior derecha del **iPad y el botón de inicio**

Para tomar una captura de pantalla que aparecerá en la esquina inferior izquierda de la pantalla. Presiona ambos botones al mismo tiempo muy brevemente ya que si los mantienes presionados unos segundos se realizará un apagado duro.

## Atajos

Deberías tener un teclado para iPad o un adaptador de teclado USB. Aquí solo se mostrarán los atajos que podrían ayudar a escapar de la aplicación.

| Tecla | Nombre        |
| ----- | ------------- |
| ⌘     | Comando       |
| ⌥     | Opción (Alt)  |
| ⇧     | Mayúsculas    |
| ↩     | Retorno       |
| ⇥     | Tabulación    |
| ^     | Control       |
| ←     | Flecha izquierda |
| →     | Flecha derecha   |
| ↑     | Flecha arriba    |
| ↓     | Flecha abajo     |

### Atajos del sistema

Estos atajos son para los ajustes visuales y de sonido, dependiendo del uso del iPad.

| Atajo     | Acción                                                                         |
| --------- | ------------------------------------------------------------------------------ |
| F1        | Oscurecer pantalla                                                             |
| F2        | Aclarar pantalla                                                               |
| F7        | Retroceder una canción                                                         |
| F8        | Reproducir/pausar                                                              |
| F9        | Saltar canción                                                                 |
| F10       | Silenciar                                                                      |
| F11       | Disminuir volumen                                                              |
| F12       | Aumentar volumen                                                               |
| ⌘ Espacio | Mostrar una lista de idiomas disponibles; para elegir uno, toca el espacio de nuevo. |

### Navegación en iPad

| Atajo                                              | Acción                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir a Inicio                                             |
| ⌘⇧H (Comando-Mayúsculas-H)                         | Ir a Inicio                                             |
| ⌘ (Espacio)                                        | Abrir Spotlight                                         |
| ⌘⇥ (Comando-Tabulación)                            | Listar las últimas diez aplicaciones usadas             |
| ⌘\~                                                | Ir a la última aplicación                               |
| ⌘⇧3 (Comando-Mayúsculas-3)                         | Captura de pantalla (se muestra en la esquina inferior izquierda para guardar o actuar sobre ella) |
| ⌘⇧4                                                | Captura de pantalla y abrir en el editor                |
| Mantener presionado ⌘                              | Lista de atajos disponibles para la aplicación          |
| ⌘⌥D (Comando-Opción/Alt-D)                         | Mostrar el dock                                         |
| ^⌥H (Control-Opción-H)                             | Botón de inicio                                         |
| ^⌥H H (Control-Opción-H-H)                         | Mostrar barra de multitarea                             |
| ^⌥I (Control-Opción-i)                             | Selector de elementos                                   |
| Escape                                             | Botón de retroceso                                      |
| → (Flecha derecha)                                 | Siguiente elemento                                      |
| ← (Flecha izquierda)                               | Elemento anterior                                       |
| ↑↓ (Flecha arriba, Flecha abajo)                   | Tocar simultáneamente el elemento seleccionado          |
| ⌥ ↓ (Opción-Flecha abajo)                          | Desplazarse hacia abajo                                 |
| ⌥↑ (Opción-Flecha arriba)                          | Desplazarse hacia arriba                                |
| ⌥← o ⌥→ (Opción-Flecha izquierda o Opción-Flecha derecha) | Desplazarse hacia la izquierda o derecha              |
| ^⌥S (Control-Opción-S)                             | Activar o desactivar el habla de VoiceOver              |
| ⌘⇧⇥ (Comando-Mayúsculas-Tabulación)                | Cambiar a la aplicación anterior                        |
| ⌘⇥ (Comando-Tabulación)                            | Cambiar de nuevo a la aplicación original               |
| ←+→, luego Opción + ← o Opción+→                   | Navegar por el Dock                                     |

### Atajos de Safari

| Atajo                  | Acción                                           |
| ---------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)         | Abrir ubicación                                  |
| ⌘T                     | Abrir una nueva pestaña                          |
| ⌘W                     | Cerrar la pestaña actual                         |
| ⌘R                     | Refrescar la pestaña actual                      |
| ⌘.                     | Detener la carga de la pestaña actual            |
| ^⇥                     | Cambiar a la siguiente pestaña                   |
| ^⇧⇥ (Control-Mayúsculas-Tabulación) | Moverse a la pestaña anterior               |
| ⌘L                     | Seleccionar el campo de texto/URL para modificarlo |
| ⌘⇧T (Comando-Mayúsculas-T) | Abrir la última pestaña cerrada (puede usarse varias veces) |
| ⌘\[                    | Retroceder una página en el historial de navegación |
| ⌘]                     | Avanzar una página en el historial de navegación |
| ⌘⇧R                    | Activar el modo Lector
