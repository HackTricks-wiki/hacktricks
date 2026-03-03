# Escapando de KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Comprobar el dispositivo físico

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Apagar y encender el dispositivo puede mostrar la pantalla de inicio |
| Power cable  | Comprueba si el dispositivo se reinicia cuando se corta la alimentación brevemente |
| USB ports    | Conecta un teclado físico para más atajos                          |
| Ethernet     | Un escaneo de red o sniffing puede permitir una explotación adicional |

## Comprueba acciones posibles dentro de la aplicación GUI

**Common Dialogs** are those options of **saving a file**, **opening a file**, selecting a font, a color... Most of them will **offer a full Explorer functionality**. This means that you will be able to access Explorer functionalities if you can access these options:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Deberías comprobar si puedes:

- Modificar o crear archivos nuevos
- Crear enlaces simbólicos
- Obtener acceso a áreas restringidas
- Ejecutar otras apps

### Ejecución de comandos

Quizá **usando la `Open with`** opción\*\* puedes abrir/ejecutar algún tipo de shell.

#### Windows

For example _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ find more binaries that can be used to execute commands (and perform unexpected actions) here: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Más aquí: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Evasión de restricciones de ruta

- **Variables de entorno**: Hay muchas variables de entorno que apuntan a alguna ruta
- **Otros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_ 
- **Enlaces simbólicos**
- **Atajos**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Menú administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paths to connect to shared folders. You should try to connect to the C$ of the local machine ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

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

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs as Explorer-lite. Try `*.*` / `*.exe` in the filename field, right-click folders for **Open in new window**, and use **Properties → Open file location** to expand navigation.
- **Create execution paths from dialogs**: Create a new file and rename it to `.CMD` or `.BAT`, or create a shortcut pointing to `%WINDIR%\System32` (or a specific binary like `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: If you can browse to `cmd.exe`, try **drag-and-drop** any file onto it to launch a prompt. If Task Manager is reachable (`CTRL+SHIFT+ESC`), use **Run new task**.
- **Task Scheduler bypass**: If interactive shells are blocked but scheduling is allowed, create a task to run `cmd.exe` (GUI `taskschd.msc` or `schtasks.exe`).
- **Weak allowlists**: If execution is allowed by **filename/extension**, rename your payload to a permitted name. If allowed by **directory**, copy the payload into an allowed program folder and run it there.
- **Buscar rutas de staging escribibles**: Empieza por `%TEMP%` y enumera carpetas escribibles con Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Siguiente paso**: Si consigues una shell, pivota al Windows LPE checklist:
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

- Sticky Keys – Press SHIFT 5 times
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Hold NUMLOCK for 5 seconds
- Filter Keys – Hold right SHIFT for 12 seconds
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Show Desktop
- WINDOWS+E – Launch Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen on newer Windows versions
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Toggle full screen within Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Gestos (Swipes)

- Desliza desde el borde izquierdo hacia la derecha para ver todas las ventanas abiertas, minimizando la app KIOSK y accediendo al sistema operativo completo directamente;
- Desliza desde el borde derecho hacia la izquierda para abrir el Action Center, minimizando la app KIOSK y accediendo al sistema operativo completo directamente;
- Desliza desde el borde superior hacia dentro para mostrar la barra de título de una app abierta en modo de pantalla completa;
- Desliza hacia arriba desde la parte inferior para mostrar la barra de tareas en una app en pantalla completa.

### Trucos de Internet Explorer

#### 'Image Toolbar'

Es una barra de herramientas que aparece en la esquina superior izquierda de una imagen cuando se hace clic en ella. Podrás Guardar, Imprimir, Mailto, Abrir "My Pictures" en Explorer. El Kiosk necesita estar usando Internet Explorer.

#### Protocolo Shell

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

Versiones de respaldo de iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crea un diálogo común usando JavaScript y accede al file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos y botones

- Desliza hacia arriba con cuatro (o cinco) dedos / Doble-toca el botón Home: Para ver la vista multitarea y cambiar de App
- Desliza en una u otra dirección con cuatro o cinco dedos: Para cambiar a la siguiente/anterior App
- Pellizca la pantalla con cinco dedos / Toca el botón Home / Desliza hacia arriba con 1 dedo desde la parte inferior de la pantalla en un movimiento rápido hacia arriba: Para acceder al Home
- Desliza un dedo desde la parte inferior de la pantalla apenas 1-2 pulgadas (despacio): Aparecerá el dock
- Desliza hacia abajo desde la parte superior de la pantalla con 1 dedo: Para ver tus notificaciones
- Desliza hacia abajo con 1 dedo la esquina superior derecha de la pantalla: Para ver el centro de control en iPad Pro
- Desliza 1 dedo desde la izquierda de la pantalla 1-2 pulgadas: Para ver la vista Hoy
- Desliza rápido 1 dedo desde el centro de la pantalla hacia la derecha o izquierda: Para cambiar a la siguiente/anterior App
- Mantén presionado el botón On/**Off**/Sleep en la esquina superior derecha del **iPad +** Mueve el deslizador Slide to **power off** totalmente hacia la derecha: Para apagar
- Mantén presionado el botón On/**Off**/Sleep en la esquina superior derecha del **iPad y el botón Home por unos segundos**: Para forzar un apagado forzado
- Presiona el botón On/**Off**/Sleep en la esquina superior derecha del **iPad y el botón Home rápidamente**: Para hacer una captura de pantalla que aparecerá en la esquina inferior izquierda de la pantalla. Presiona ambos botones al mismo tiempo muy brevemente; si los mantienes unos segundos se realizará un apagado forzado.

### Atajos

Deberías tener un teclado para iPad o un adaptador de teclado USB. Aquí se muestran solo los atajos que podrían ayudar a escapar de la aplicación.

| Key | Nombre       |
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

| Atajo    | Acción                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | Reducir brillo                                                         |
| F2       | Aumentar brillo                                                        |
| F7       | Volver una canción                                                     |
| F8       | Reproducir/pausar                                                      |
| F9       | Saltar canción                                                         |
| F10      | Silenciar                                                              |
| F11      | Disminuir volumen                                                      |
| F12      | Aumentar volumen                                                       |
| ⌘ Space  | Muestra una lista de idiomas disponibles; para elegir uno, pulsa la barra espaciadora otra vez. |

#### Navegación en iPad

| Atajo                                          | Acción                                                    |
| ----------------------------------------------- | --------------------------------------------------------- |
| ⌘H                                             | Ir a Home                                                |
| ⌘⇧H (Command-Shift-H)                          | Ir a Home                                                |
| ⌘ (Space)                                      | Abrir Spotlight                                          |
| ⌘⇥ (Command-Tab)                               | Lista de las diez apps usadas recientemente              |
| ⌘\~                                            | Ir a la última App                                       |
| ⌘⇧3 (Command-Shift-3)                          | Captura de pantalla (aparece en la esquina inferior izquierda para guardar o actuar) |
| ⌘⇧4                                          | Captura de pantalla y abrirla en el editor               |
| Mantener ⌘                                    | Lista de atajos disponibles para la App                  |
| ⌘⌥D (Command-Option/Alt-D)                     | Muestra el dock                                          |
| ^⌥H (Control-Option-H)                         | Botón Home                                               |
| ^⌥H H (Control-Option-H-H)                     | Mostrar barra multitarea                                  |
| ^⌥I (Control-Option-i)                         | Selector de elementos                                    |
| Escape                                         | Botón Atrás                                              |
| → (Right arrow)                                | Siguiente elemento                                       |
| ← (Left arrow)                                 | Elemento anterior                                        |
| ↑↓ (Up arrow, Down arrow)                      | Tocar simultáneamente el elemento seleccionado           |
| ⌥ ↓ (Option-Down arrow)                        | Desplazar hacia abajo                                    |
| ⌥↑ (Option-Up arrow)                           | Desplazar hacia arriba                                   |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Desplazar a la izquierda o derecha                       |
| ^⌥S (Control-Option-S)                         | Activar o desactivar la voz de VoiceOver                 |
| ⌘⇧⇥ (Command-Shift-Tab)                        | Cambiar a la app anterior                                |
| ⌘⇥ (Command-Tab)                               | Volver a la app original                                 |
| ←+→, then Option + ← or Option+→                | Navegar por el Dock                                      |

#### Atajos de Safari

| Atajo                    | Acción                                            |
| ------------------------ | ------------------------------------------------- |
| ⌘L (Command-L)           | Abrir ubicación                                   |
| ⌘T                      | Abrir una nueva pestaña                           |
| ⌘W                      | Cerrar la pestaña actual                          |
| ⌘R                      | Actualizar la pestaña actual                      |
| ⌘.                      | Detener la carga de la pestaña actual             |
| ^⇥                      | Cambiar a la siguiente pestaña                    |
| ^⇧⇥ (Control-Shift-Tab) | Ir a la pestaña anterior                          |
| ⌘L                      | Seleccionar el campo de texto/URL para modificarlo|
| ⌘⇧T (Command-Shift-T)   | Abrir la última pestaña cerrada (puede usarse varias veces) |
| ⌘\[                     | Volver una página en el historial                 |
| ⌘]                      | Avanzar una página en el historial                |
| ⌘⇧R                     | Activar el Modo Lector                             |

#### Atajos de Mail

| Atajo                     | Acción                       |
| ------------------------- | ---------------------------- |
| ⌘L                        | Abrir ubicación              |
| ⌘T                        | Abrir una nueva pestaña      |
| ⌘W                        | Cerrar la pestaña actual     |
| ⌘R                        | Actualizar la pestaña actual |
| ⌘.                        | Detener la carga de la pestaña actual |
| ⌘⌥F (Command-Option/Alt-F) | Buscar en tu buzón           |

## Referencias

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
