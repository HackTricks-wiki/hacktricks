# Escapando de KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Comprobar el dispositivo físico

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Turning the device off and on again may expose the start screen    |
| Power cable  | Check whether the device reboots when the power is cut off briefly |
| USB ports    | Connect physical keyboard with more shortcuts                      |
| Ethernet     | Network scan or sniffing may enable further exploitation           |

## Comprobar acciones posibles dentro de la aplicación GUI

**Common Dialogs** son esas opciones de **saving a file**, **opening a file**, seleccionar una fuente, un color... La mayoría de ellas **ofrecerán una funcionalidad completa del Explorer**. Esto significa que podrás acceder a funcionalidades del Explorer si puedes acceder a estas opciones:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Debes comprobar si puedes:

- Modify or create new files
- Create symbolic links
- Get access to restricted areas
- Execute other apps

### Ejecución de comandos

Quizá **usando una `Open with` option\*\*** puedas abrir/ejecutar algún tipo de shell.

#### Windows

Por ejemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encuentra más binarios que pueden usarse para ejecutar comandos (y realizar acciones inesperadas) aquí: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypass de restricciones de rutas

- **Variables de entorno**: Hay muchas variables de entorno que apuntan a rutas
- **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Enlaces simbólicos**
- **Atajos**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Menú Administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Rutas para conectarse a carpetas compartidas. Deberías intentar conectarte al C$ de la máquina local ("\\\127.0.0.1\c$\Windows\System32")
- **Más UNC paths:**

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

### Evasiones en escritorios restringidos (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Usa los diálogos *Open/Save/Print-to-file* como un Explorer reducido. Prueba `*.*` / `*.exe` en el campo de nombre de archivo, haz clic derecho en carpetas para **Open in new window**, y usa **Properties → Open file location** para expandir la navegación.
- **Crear rutas de ejecución desde diálogos**: Crea un archivo nuevo y renómbralo a `.CMD` o `.BAT`, o crea un acceso directo apuntando a `%WINDIR%\System32` (o a un binario específico como `%WINDIR%\System32\cmd.exe`).
- **Pivotes para lanzar shell**: Si puedes navegar hasta `cmd.exe`, intenta **drag-and-drop** cualquier archivo sobre él para lanzar un prompt. Si el Task Manager es accesible (`CTRL+SHIFT+ESC`), usa **Run new task**.
- **Bypass del Task Scheduler**: Si los shells interactivos están bloqueados pero está permitido programar tareas, crea una tarea para ejecutar `cmd.exe` (GUI `taskschd.msc` o `schtasks.exe`).
- **Allowlists débiles**: Si la ejecución está permitida por **filename/extension**, renombra tu payload a un nombre permitido. Si está permitida por **directory**, copia el payload en una carpeta de programas permitida y ejecútalo allí.
- **Encontrar rutas de staging escribibles**: Empieza con `%TEMP%` y enumera carpetas con permiso de escritura con Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Siguiente paso**: Si consigues un shell, pivota a la lista de verificación de Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Descargar tus binarios

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

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

- Sticky Keys – Presiona SHIFT 5 veces
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Mantén NUMLOCK durante 5 segundos
- Filter Keys – Mantén la tecla SHIFT derecha durante 12 segundos
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Mostrar el escritorio
- WINDOWS+E – Abrir Windows Explorer
- WINDOWS+R – Ejecutar
- WINDOWS+U – Centro de facilidad de acceso
- WINDOWS+F – Buscar
- SHIFT+F10 – Menú contextual
- CTRL+SHIFT+ESC – Administrador de tareas
- CTRL+ALT+DEL – Pantalla de opciones en versiones recientes de Windows
- F1 – Ayuda F3 – Buscar
- F6 – Barra de direcciones
- F11 – Alternar pantalla completa en Internet Explorer
- CTRL+H – Historial de Internet Explorer
- CTRL+T – Internet Explorer – Nueva pestaña
- CTRL+N – Internet Explorer – Nueva página
- CTRL+O – Abrir archivo
- CTRL+S – Guardar CTRL+N – Nuevo RDP / Citrix

### Gestos de deslizamiento

- Desliza desde el lado izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizando la aplicación KIOSK y accediendo directamente al sistema operativo;
- Desliza desde el lado derecho hacia la izquierda para abrir el Action Center, minimizando la aplicación KIOSK y accediendo directamente al sistema operativo;
- Desliza desde el borde superior hacia dentro para hacer visible la barra de título en una aplicación abierta en pantalla completa;
- Desliza hacia arriba desde la parte inferior para mostrar la barra de tareas en una aplicación en pantalla completa.

### Trucos de Internet Explorer

#### 'Image Toolbar'

Es una barra de herramientas que aparece en la esquina superior izquierda de una imagen cuando se hace clic en ella. Podrás Guardar, Imprimir, Mailto, Abrir "My Pictures" en Explorer. El Kiosk necesita estar usando Internet Explorer.

#### Shell Protocol

Escribe estas URLs para obtener una vista de Explorer:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrar extensiones de archivo

Consulta esta página para más información: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Trucos para navegadores

Versiones de respaldo iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea un diálogo común usando JavaScript y accede al explorador de archivos: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos y botones

- Desliza hacia arriba con cuatro (o cinco) dedos / Doble toque en el botón Home: Para ver la vista de multitarea y cambiar de App
- Desliza con cuatro o cinco dedos hacia la izquierda o derecha: Para cambiar a la siguiente/anterior App
- Pellizca la pantalla con cinco dedos / Toca el botón Home / Desliza hacia arriba con 1 dedo desde la parte inferior de la pantalla con un movimiento rápido hacia arriba: Para acceder a Home
- Desliza un dedo desde la parte inferior de la pantalla solo 1-2 pulgadas (despacio): Aparecerá el dock
- Desliza hacia abajo desde la parte superior de la pantalla con 1 dedo: Para ver tus notificaciones
- Desliza hacia abajo con 1 dedo la esquina superior derecha de la pantalla: Para ver el centro de control de iPad Pro
- Desliza 1 dedo desde la izquierda de la pantalla 1-2 pulgadas: Para ver la vista Hoy
- Desliza rápido 1 dedo desde el centro de la pantalla hacia la derecha o izquierda: Para cambiar a la siguiente/anterior App
- Mantén presionado el botón On/**Off**/Sleep en la esquina superior derecha del **iPad +** Mueve el deslizador de **power off** totalmente hacia la derecha: Para apagar
- Mantén presionado el botón On/**Off**/Sleep en la esquina superior derecha del **iPad y el botón Home por unos segundos**: Para forzar un apagado completo
- Presiona rápidamente el botón On/**Off**/Sleep en la esquina superior derecha del **iPad y el botón Home**: Para tomar una captura de pantalla que aparecerá en la esquina inferior izquierda de la pantalla. Si mantienes ambos botones presionados unos segundos se realizará un apagado forzado.

### Atajos

Deberías tener un teclado para iPad o un adaptador de teclado USB. Solo se mostrarán atajos que puedan ayudar a escapar de la aplicación.

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

Estos atajos son para la configuración visual y de sonido, dependiendo del uso del iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Atenuar pantalla                                                               |
| F2       | Aumentar brillo                                                                |
| F7       | Pista anterior                                                                 |
| F8       | Reproducir/pausar                                                              |
| F9       | Saltar pista                                                                    |
| F10      | Silenciar                                                                      |
| F11      | Disminuir volumen                                                               |
| F12      | Aumentar volumen                                                               |
| ⌘ Space  | Muestra una lista de idiomas disponibles; para elegir uno, pulsa la barra espaciadora de nuevo. |

#### Navegación en iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir a Home                                               |
| ⌘⇧H (Command-Shift-H)                              | Ir a Home                                               |
| ⌘ (Space)                                          | Abrir Spotlight                                         |
| ⌘⇥ (Command-Tab)                                   | Lista de las diez apps usadas más recientemente         |
| ⌘\~                                                | Ir a la última App                                       |
| ⌘⇧3 (Command-Shift-3)                              | Captura de pantalla (aparece en la esquina inferior izquierda para guardar o actuar sobre ella) |
| ⌘⇧4                                                | Captura de pantalla y abrirla en el editor              |
| Press and hold ⌘                                   | Lista de atajos disponibles para la App                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Muestra el dock                                         |
| ^⌥H (Control-Option-H)                             | Botón Home                                              |
| ^⌥H H (Control-Option-H-H)                         | Mostrar barra de multitarea                              |
| ^⌥I (Control-Option-i)                             | Selector de ítems                                       |
| Escape                                             | Botón Atrás                                             |
| → (Right arrow)                                    | Siguiente ítem                                          |
| ← (Left arrow)                                     | Ítem anterior                                           |
| ↑↓ (Up arrow, Down arrow)                          | Tocar simultáneamente el ítem seleccionado              |
| ⌥ ↓ (Option-Down arrow)                            | Desplazar hacia abajo                                   |
| ⌥↑ (Option-Up arrow)                               | Desplazar hacia arriba                                  |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Desplazar hacia la izquierda o derecha                  |
| ^⌥S (Control-Option-S)                             | Activar o desactivar la voz de VoiceOver                |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Cambiar a la app anterior                               |
| ⌘⇥ (Command-Tab)                                   | Volver a la app original                                |
| ←+→, then Option + ← or Option+→                   | Navegar por el Dock                                     |

#### Atajos de Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Abrir ubicación                                  |
| ⌘T                      | Abrir una nueva pestaña                          |
| ⌘W                      | Cerrar la pestaña actual                         |
| ⌘R                      | Actualizar la pestaña actual                     |
| ⌘.                      | Detener la carga de la pestaña actual            |
| ^⇥                      | Cambiar a la siguiente pestaña                   |
| ^⇧⇥ (Control-Shift-Tab) | Mover a la pestaña anterior                      |
| ⌘L                      | Seleccionar el campo de texto/URL para modificarlo |
| ⌘⇧T (Command-Shift-T)   | Abrir la última pestaña cerrada (puede usarse varias veces) |
| ⌘\[                     | Volver una página en el historial de navegación  |
| ⌘]                      | Avanzar una página en el historial de navegación |
| ⌘⇧R                     | Activar Reader Mode                               |

#### Atajos de Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Abrir ubicación              |
| ⌘T                         | Abrir una nueva pestaña      |
| ⌘W                         | Cerrar la pestaña actual     |
| ⌘R                         | Actualizar la pestaña actual |
| ⌘.                         | Detener la carga de la pestaña |
| ⌘⌥F (Command-Option/Alt-F) | Buscar en tu buzón           |

## Referencias

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
