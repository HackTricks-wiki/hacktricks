# Bypasses de Admin Protection mediante UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Descripción general
- Windows AppInfo expone la ruta interna `RAiLaunchAdminProcess`, utilizada para iniciar aplicaciones UIAccess destinadas a la accesibilidad. UIAccess permite interacciones seleccionadas a través de los límites de User Interface Privilege Isolation (UIPI); no es un bypass general de todos los límites de seguridad de procesos.<sup>[[1]](#references)[[3]](#references)</sup>
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, por lo que los callers con pocos privilegios dependen del servicio. El servicio realiza tres comprobaciones sobre el binario de destino antes de establecer UIAccess:
- El manifest incrustado contiene `uiAccess="true"`.
- Está firmado por cualquier certificado de confianza del almacén de raíces de Local Machine (sin requisitos de EKU/Microsoft).
- Está ubicado en una ruta exclusiva para administradores en la unidad del sistema (por ejemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), excluyendo subrutas específicas con permisos de escritura.
- `RAiLaunchAdminProcess` no muestra ningún consent prompt para los lanzamientos de UIAccess (de lo contrario, las herramientas de accesibilidad no podrían controlar el prompt).<sup>[[1]](#references)</sup>

## Ajuste de tokens y niveles de integridad
- Si las comprobaciones tienen éxito, AppInfo **copia el token del caller**, habilita UIAccess y aumenta el Integrity Level (IL):
- Usuario administrador limitado (el usuario pertenece a Administrators, pero se ejecuta con filtrado) ➜ **High IL**.
- Usuario que no es administrador ➜ IL aumentado en **+16 niveles** hasta un límite de **High** (nunca se asigna System IL).
- Si el token del caller ya tiene UIAccess, el IL no cambia.
- Truco del “ratchet”: un proceso UIAccess puede deshabilitar UIAccess en sí mismo, volver a iniciarse mediante `RAiLaunchAdminProcess` y obtener otro incremento de +16 IL. Pasar de Medium➜High requiere 255 relanzamientos (ruidoso, pero funciona).<sup>[[1]](#references)</sup>

## Por qué UIAccess permite escapar de Admin Protection
- UIAccess permite que un proceso con IL inferior envíe mensajes de ventana a ventanas con IL superior (omitiendo los filtros de UIPI). Con **IL iguales**, las primitivas clásicas de UI, como `SetWindowsHookEx`, **sí permiten la inyección de código/carga de DLL** en cualquier proceso propietario de una ventana (incluidas las ventanas message-only utilizadas por COM).
- Admin Protection inicia el proceso UIAccess con la identidad del usuario limitado, pero con **High IL**, de forma silenciosa. Una vez que se ejecuta código arbitrario dentro de ese proceso UIAccess con High IL, el atacante puede inyectarse en otros procesos con High IL del escritorio (incluso si pertenecen a otros usuarios), rompiendo la separación prevista.<sup>[[1]](#references)</sup>

## Primitiva de handle de HWND a proceso (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- En Windows 10 1803 y posteriores, la API se trasladó a Win32k (`NtUserGetWindowProcessHandle`) y puede abrir un handle de proceso utilizando un `DesiredAccess` proporcionado por el caller. La ruta del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, lo que omite las comprobaciones normales de acceso en user mode.<sup>[[2]](#references)</sup>
- Requisitos previos en la práctica: la ventana de destino debe estar en el mismo escritorio y las comprobaciones de UIPI deben pasar. Históricamente, un caller con UIAccess podía omitir el fallo de UIPI y aun así obtener un handle en kernel mode (corregido como CVE-2023-41772).
- Impacto histórico: un handle de ventana se convertía en una **capacidad** para obtener acceso al proceso, como `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` o `PROCESS_VM_OPERATION`, que el caller normalmente no podía obtener. Antes de las correcciones documentadas, esto podía atravesar los límites de sandbox y de protected processes cuando un destino exponía una ventana, incluida una ventana message-only.<sup>[[2]](#references)</sup>
- Flujo de abuso práctico: enumerar o localizar HWNDs (por ejemplo, `EnumWindows`/`FindWindowEx`), resolver el PID propietario (`GetWindowThreadProcessId`), llamar a `GetProcessHandleFromHwnd` y utilizar el handle devuelto para primitivas de lectura/escritura de memoria o de secuestro de código.
- Comportamiento posterior a la corrección: UIAccess ya no concede aperturas en kernel mode cuando falla UIPI y los derechos de acceso permitidos están restringidos al conjunto de hooks heredado; Windows 11 24H2 añade comprobaciones de protección de procesos y rutas más seguras controladas por feature flags. Deshabilitar UIPI globalmente (`EnforceUIPI=0`) debilita estas protecciones.<sup>[[2]](#references)</sup>

## Debilidades de validación de directorios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta proporcionada mediante `GetFinalPathNameByHandle` y después aplica **comprobaciones de strings de allow/deny** contra raíces/exclusiones codificadas. Varias clases de bypass se deben a esa validación simplista:
- **Named streams de directorio**: los directorios excluidos con permisos de escritura (por ejemplo, `C:\Windows\tracing`) pueden omitirse utilizando un named stream en el propio directorio, como `C:\Windows\tracing:file.exe`. Las comprobaciones de strings detectan `C:\Windows\` y no identifican la subruta excluida.
- **Archivo/directorio con permisos de escritura dentro de una raíz permitida**: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo con permisos de escritura bajo una raíz permitida con un payload ejecutable funciona; también permite copiar un EXE firmado con `uiAccess="true"` a cualquier subdirectorio con permisos de escritura (por ejemplo, restos de actualizaciones como `Tasks_Migrated`, cuando estén presentes) y hacer que supere la comprobación de ruta segura.
- **MSIX en `C:\Program Files\WindowsApps` (corregido)**: los usuarios que no eran administradores podían instalar paquetes MSIX firmados que terminaban en `WindowsApps`, una ruta que no estaba excluida. Incluir un binario UIAccess dentro del MSIX y después iniciarlo mediante `RAiLaunchAdminProcess` producía un **proceso UIAccess con High IL sin prompt**. Microsoft mitigó el problema excluyendo esta ruta; la capability restringida `uiAccess` de MSIX ya requiere una instalación realizada por un administrador.<sup>[[1]](#references)</sup>

## Flujo de ataque (High IL sin prompt)
1. Obtener/compilar un **binario UIAccess firmado** (manifest `uiAccess="true"`). Para una evaluación realista, realizar las pruebas con material de confianza y rutas autorizadas explícitamente para el laboratorio; no añadir un certificado del atacante al almacén de raíces de Local Machine de una máquina de producción.
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un edge case de validación de rutas/un artefacto con permisos de escritura como se indicó anteriormente).
3. Llamar a `RAiLaunchAdminProcess` para iniciarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese foothold con High IL, apuntar a otro proceso con High IL del escritorio mediante **window hooks/inyección de DLL** u otras primitivas con el mismo IL para comprometer completamente el contexto del administrador.<sup>[[1]](#references)</sup>

## Enumeración de rutas candidatas con permisos de escritura
Ejecuta el helper de PowerShell para descubrir objetos con permisos de escritura o sobrescritura dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Ejecutar como Administrator para obtener una visibilidad más amplia; establecer `-ProcessId` en un proceso con pocos privilegios para reflejar el acceso de ese token.
- Filtrar manualmente para excluir subdirectorios conocidos como no permitidos antes de utilizar los candidatos con `RAiLaunchAdminProcess`.

## Relacionado

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — UIAccess applications](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
