# Escapando de KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Comprobar el dispositivo físico

| Componente    | Acción                                                             |
| ------------ | ------------------------------------------------------------------ |
| Botón de encendido | Apagar y volver a encender el dispositivo puede mostrar la pantalla de inicio    |
| Cable de alimentación  | Comprobar si el dispositivo se reinicia cuando se interrumpe brevemente la alimentación |
| Puertos USB    | Conectar un teclado físico para disponer de más atajos                      |
| Ethernet     | Un escaneo de red o sniffing puede permitir una explotación adicional           |

## Comprobar posibles acciones dentro de la aplicación GUI

Los **diálogos comunes** son aquellas opciones para **guardar un archivo**, **abrir un archivo**, seleccionar una fuente, un color... La mayoría de ellos **ofrecerán una funcionalidad completa de Explorer**. Esto significa que podrás acceder a las funcionalidades de Explorer si puedes acceder a estas opciones:

- Cerrar/Cerrar como
- Abrir/Abrir con
- Imprimir
- Exportar/Importar
- Buscar
- Escanear

Deberías comprobar si puedes:

- Modificar o crear archivos nuevos
- Crear symbolic links
- Obtener acceso a áreas restringidas
- Ejecutar otras aplicaciones

### Ejecución de comandos

Quizá **usando una opción `Open with`**\*\* puedas abrir o ejecutar algún tipo de shell.

#### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que pueden utilizarse para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Más información aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Evitar restricciones de rutas

- **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
- **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Atajos**: CTRL+N (abrir una sesión nueva), CTRL+R (ejecutar comandos), CTRL+SHIFT+ESC (Task Manager), Windows+E (abrir Explorer), CTRL-B, CTRL-I (favoritos), CTRL-H (historial), CTRL-L, CTRL-O (diálogo de archivo/abrir), CTRL-P (diálogo de impresión), CTRL-S (guardar como)
- Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Rutas UNC**: Rutas para conectarse a carpetas compartidas. Deberías intentar conectarte a la unidad C$ de la máquina local ("\\\127.0.0.1\c$\Windows\System32")
- **Más rutas UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Escapes de escritorios restringidos (Citrix/RDS/VDI)

- **Pivoting mediante diálogos**: Utiliza los diálogos de *Open/Save/Print-to-file* como un Explorer-lite. Prueba `*.*` / `*.exe` en el campo del nombre de archivo, haz clic derecho en las carpetas para **Open in new window** y utiliza **Properties → Open file location** para ampliar la navegación.<sup>[[1]](#references)</sup>
- **Crear rutas de ejecución desde los diálogos**: Crea un archivo nuevo y renómbralo a `.CMD` o `.BAT`, o crea un acceso directo que apunte a `%WINDIR%\System32` (o a un binario específico como `%WINDIR%\System32\cmd.exe`).
- **Pivots para lanzar una shell**: Si puedes navegar hasta `cmd.exe`, intenta arrastrar y soltar cualquier archivo sobre él para iniciar un prompt. Si Task Manager está disponible (`CTRL+SHIFT+ESC`), utiliza **Run new task**.
- **Bypass de Task Scheduler**: Si las shells interactivas están bloqueadas pero se permite la programación, crea una tarea para ejecutar `cmd.exe` (GUI `taskschd.msc` o `schtasks.exe`).
- **Allowlists débiles**: Si la ejecución se permite por **nombre/extensión**, renombra tu payload con un nombre permitido. Si se permite por **directorio**, copia el payload en una carpeta de programas permitida y ejecútalo allí.
- **Encontrar rutas de staging con permisos de escritura**: Comienza con `%TEMP%` y enumera las carpetas con permisos de escritura mediante Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Siguiente paso**: Si obtienes una shell, pasa a la checklist de Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Descarga tus binarios

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor del registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Acceder al sistema de archivos desde el navegador

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Atajos

- Sticky Keys – Pulsa SHIFT 5 veces
- Mouse Keys – SHIFT+ALT+NUMLOCK
- Alto contraste – SHIFT+ALT+PRINTSCN
- Toggle Keys – Mantén pulsado NUMLOCK durante 5 segundos
- Filter Keys – Mantén pulsado SHIFT derecho durante 12 segundos
- WINDOWS+F1 – Búsqueda de Windows
- WINDOWS+D – Mostrar el escritorio
- WINDOWS+E – Iniciar Windows Explorer
- WINDOWS+R – Ejecutar
- WINDOWS+U – Centro de accesibilidad
- WINDOWS+F – Buscar
- SHIFT+F10 – Menú contextual
- CTRL+SHIFT+ESC – Administrador de tareas
- CTRL+ALT+DEL – Pantalla de inicio en las versiones más recientes de Windows
- F1 – Ayuda F3 – Buscar
- F6 – Barra de direcciones
- F11 – Activar o desactivar pantalla completa en Internet Explorer
- CTRL+H – Historial de Internet Explorer
- CTRL+T – Internet Explorer – Nueva pestaña
- CTRL+N – Internet Explorer – Nueva página
- CTRL+O – Abrir archivo
- CTRL+S – Guardar CTRL+N – Nuevo RDP / Citrix

### Deslizamientos

- Desliza desde el lado izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizar la aplicación KIOSK y acceder directamente a todo el sistema operativo;
- Desliza desde el lado derecho hacia la izquierda para abrir el Centro de actividades, minimizar la aplicación KIOSK y acceder directamente a todo el sistema operativo;
- Desliza desde el borde superior para hacer visible la barra de título de una aplicación abierta en modo de pantalla completa;
- Desliza hacia arriba desde la parte inferior para mostrar la barra de tareas en una aplicación a pantalla completa.

### Trucos de Internet Explorer

#### 'Image Toolbar'

Es una barra de herramientas que aparece en la parte superior izquierda de una imagen al hacer clic en ella. Podrás guardar, imprimir, enviar por correo y abrir "My Pictures" en Explorer. El Kiosk debe estar utilizando Internet Explorer.

#### Shell Protocol

Escribe estas URL para obtener una vista de Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Panel de control
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Mi equipo
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Mis sitios de red
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrar las extensiones de archivo

Consulta esta página para obtener más información: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Trucos de navegadores

Versiones de respaldo de iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea un diálogo común mediante JavaScript y accede al explorador de archivos: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Fuente: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos y botones

- Desliza hacia arriba con cuatro (o cinco) dedos / Pulsa dos veces el botón Home: Para ver la vista multitarea y cambiar de App
- Desliza en una dirección u otra con cuatro o cinco dedos: Para cambiar a la siguiente/anterior App
- Pellizca la pantalla con cinco dedos / Pulsa el botón Home / Desliza hacia arriba con 1 dedo desde la parte inferior de la pantalla con un movimiento rápido hacia arriba: Para acceder a Home
- Desliza 1 dedo desde la parte inferior de la pantalla solo 1-2 pulgadas (lentamente): Aparecerá el dock
- Desliza hacia abajo desde la parte superior de la pantalla con 1 dedo: Para ver tus notificaciones
- Desliza hacia abajo con 1 dedo desde la esquina superior derecha de la pantalla: Para ver el centro de control del iPad Pro
- Desliza 1 dedo desde el lado izquierdo de la pantalla 1-2 pulgadas: Para ver la vista Hoy
- Desliza rápidamente 1 dedo desde el centro de la pantalla hacia la derecha o la izquierda: Para cambiar a la siguiente/anterior App
- Mantén pulsado el botón de encendido/**apagado**/reposo en la esquina superior derecha del **iPad +** Desplaza el control deslizante **apagar** completamente hacia la derecha: Para apagar
- Pulsa el botón de encendido/**apagado**/reposo en la esquina superior derecha del **iPad y el botón Home durante unos segundos**: Para forzar un apagado completo
- Pulsa rápidamente el botón de encendido/**apagado**/reposo en la esquina superior derecha del **iPad y el botón Home**: Para hacer una captura de pantalla que aparecerá en la parte inferior izquierda de la pantalla. Pulsa ambos botones al mismo tiempo durante un instante; si los mantienes pulsados unos segundos, se realizará un apagado completo.<sup>[[3]](#references)</sup>

### Atajos

Debes tener un teclado para iPad o un adaptador de teclado USB. Aquí solo se muestran los atajos que podrían ayudar a escapar de la aplicación.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Atajos del sistema

Estos atajos son para los ajustes visuales y de sonido, dependiendo del uso del iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Atenuar la pantalla                                                            |
| F2       | Aumentar el brillo de la pantalla                                              |
| F7       | Canción anterior                                                               |
| F8       | Reproducir/pausar                                                              |
| F9       | Saltar canción                                                                 |
| F10      | Silenciar                                                                     |
| F11      | Disminuir el volumen                                                           |
| F12      | Aumentar el volumen                                                           |
| ⌘ Space  | Mostrar una lista de idiomas disponibles; para elegir uno, pulsa de nuevo la barra espaciadora. |

#### Navegación del iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir a Home                                               |
| ⌘⇧H (Command-Shift-H)                              | Ir a Home                                               |
| ⌘ (Space)                                          | Abrir Spotlight                                         |
| ⌘⇥ (Command-Tab)                                   | Mostrar las diez últimas apps utilizadas                |
| ⌘\~                                                | Ir a la última App                                      |
| ⌘⇧3 (Command-Shift-3)                              | Captura de pantalla (aparece abajo a la izquierda para guardarla o realizar acciones) |
| ⌘⇧4                                                | Hacer una captura de pantalla y abrirla en el editor    |
| Mantén pulsado ⌘                                   | Lista de atajos disponibles para la App                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Mostrar el dock                                         |
| ^⌥H (Control-Option-H)                             | Botón Home                                              |
| ^⌥H H (Control-Option-H-H)                         | Mostrar la barra multitarea                             |
| ^⌥I (Control-Option-i)                             | Selector de elementos                                   |
| Escape                                             | Botón Atrás                                             |
| → (Right arrow)                                    | Siguiente elemento                                      |
| ← (Left arrow)                                     | Elemento anterior                                       |
| ↑↓ (Up arrow, Down arrow)                          | Pulsar simultáneamente el elemento seleccionado        |
| ⌥ ↓ (Option-Down arrow)                            | Desplazarse hacia abajo                                 |
| ⌥↑ (Option-Up arrow)                               | Desplazarse hacia arriba                                |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Desplazarse a la izquierda o a la derecha               |
| ^⌥S (Control-Option-S)                             | Activar o desactivar la voz de VoiceOver                |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Cambiar a la aplicación anterior                         |
| ⌘⇥ (Command-Tab)                                   | Volver a la aplicación original                          |
| ←+→, then Option + ← or Option+→                   | Navegar por el Dock                                     |

#### Atajos de Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Abrir ubicación                                  |
| ⌘T                      | Abrir una nueva pestaña                           |
| ⌘W                      | Cerrar la pestaña actual                           |
| ⌘R                      | Actualizar la pestaña actual                       |
| ⌘.                      | Detener la carga de la pestaña actual              |
| ^⇥                      | Cambiar a la siguiente pestaña                      |
| ^⇧⇥ (Control-Shift-Tab) | Moverse a la pestaña anterior                       |
| ⌘L                      | Seleccionar el campo de texto/URL para modificarlo |
| ⌘⇧T (Command-Shift-T)   | Abrir la última pestaña cerrada (se puede usar varias veces) |
| ⌘\[                     | Retroceder una página en el historial de navegación |
| ⌘]                      | Avanzar una página en el historial de navegación   |
| ⌘⇧R                     | Activar el modo Reader                             |

#### Atajos de Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Abrir ubicación                |
| ⌘T                         | Abrir una nueva pestaña        |
| ⌘W                         | Cerrar la pestaña actual      |
| ⌘R                         | Actualizar la pestaña actual  |
| ⌘.                         | Detener la carga de la pestaña actual |
| ⌘⌥F (Command-Option/Alt-F) | Buscar en tu buzón            |

## Referencias

- [1] [Salir de Citrix y otros entornos de escritorio restringidos](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Dame un navegador y te daré una shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 gestos exclusivos para iPad que debes conocer](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [Guía de atajos del iPad](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Mejores atajos de teclado para iPad](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [Atajos de teclado del iPad](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Mostrar las extensiones de archivo en Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
