# Bypasses de Admin Protection mediante UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Descripción general
- Windows AppInfo expone `RAiLaunchAdminProcess` para iniciar procesos UIAccess (destinados a la accesibilidad). UIAccess omite la mayor parte del filtrado de mensajes de User Interface Privilege Isolation (UIPI), de modo que el software de accesibilidad puede controlar interfaces de usuario con un IL superior.
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, por lo que los callers con pocos privilegios dependen del servicio. El servicio realiza tres comprobaciones sobre el binario objetivo antes de establecer UIAccess:
- El manifest incorporado contiene `uiAccess="true"`.
- Está firmado por cualquier certificado de confianza del almacén de raíces de Local Machine (sin requisitos de EKU/Microsoft).
- Está ubicado en una ruta exclusiva para administradores en la unidad del sistema (por ejemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), excluyendo subrutas específicas con permisos de escritura.
- `RAiLaunchAdminProcess` no muestra un aviso de consentimiento para los lanzamientos UIAccess (de lo contrario, las herramientas de accesibilidad no podrían controlar el aviso).<sup>[[1]](#references)</sup>

## Ajuste de tokens y niveles de integridad
- Si las comprobaciones tienen éxito, AppInfo **copia el token del caller**, habilita UIAccess e incrementa el Integrity Level (IL):
- Usuario administrador limitado (el usuario pertenece a Administrators, pero se ejecuta con filtrado) ➜ **High IL**.
- Usuario que no es administrador ➜ IL incrementado en **+16 niveles** hasta un límite **High** (nunca se asigna System IL).
- Si el token del caller ya tiene UIAccess, el IL no cambia.
- Truco del “ratchet”: un proceso UIAccess puede deshabilitar UIAccess en sí mismo, volver a iniciarse mediante `RAiLaunchAdminProcess` y obtener otro incremento de +16 en el IL. Pasar de Medium➜High requiere 255 relanzamientos (ruidoso, pero funciona).<sup>[[1]](#references)</sup>

## Por qué UIAccess permite escapar de Admin Protection
- UIAccess permite que un proceso con un IL inferior envíe mensajes de ventana a ventanas con un IL superior (omitiendo los filtros UIPI). Con un **IL equivalente**, las primitivas UI clásicas como `SetWindowsHookEx` **sí permiten la inyección de código/carga de DLL** en cualquier proceso que posea una ventana (incluidas las ventanas que solo envían mensajes utilizadas por COM).
- Admin Protection inicia el proceso UIAccess con la identidad del **usuario limitado**, pero con **High IL**, de forma silenciosa. Una vez que se ejecuta código arbitrario dentro de ese proceso UIAccess con High IL, el atacante puede inyectarlo en otros procesos con High IL del escritorio (incluso si pertenecen a otros usuarios), rompiendo la separación prevista.<sup>[[1]](#references)</sup>

## Primitiva de identificador de ventana a handle de proceso (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- En Windows 10 1803+ la API se trasladó a Win32k (`NtUserGetWindowProcessHandle`) y puede abrir un handle de proceso usando un `DesiredAccess` proporcionado por el caller. La ruta del kernel utiliza `ObOpenObjectByPointer(..., KernelMode, ...)`, lo que omite las comprobaciones normales de acceso en user-mode.<sup>[[2]](#references)</sup>
- Requisitos previos en la práctica: la ventana objetivo debe estar en el mismo escritorio y las comprobaciones UIPI deben pasar. Históricamente, un caller con UIAccess podía omitir el fallo de UIPI y aun así obtener un handle en kernel-mode (corregido como CVE-2023-41772).
- Impacto: un handle de ventana se convierte en una **capacidad** para obtener un handle de proceso con privilegios elevados (normalmente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que el caller normalmente no podría abrir. Esto permite el acceso entre sandboxes y puede romper los límites de Protected Process / PPL si el objetivo expone cualquier ventana (incluidas las ventanas que solo envían mensajes).
- Flujo práctico de abuso: enumerar o localizar HWNDs (por ejemplo, `EnumWindows`/`FindWindowEx`), resolver el PID propietario (`GetWindowThreadProcessId`), llamar a `GetProcessHandleFromHwnd` y utilizar después el handle devuelto para primitivas de lectura/escritura de memoria o secuestro de código.
- Comportamiento posterior a la corrección: UIAccess ya no concede aperturas en kernel-mode cuando falla UIPI y los derechos de acceso permitidos están restringidos al conjunto de hooks heredado; Windows 11 24H2 añade comprobaciones de protección de procesos y rutas más seguras controladas mediante feature flags. Deshabilitar UIPI en todo el sistema (`EnforceUIPI=0`) debilita estas protecciones.<sup>[[2]](#references)</sup>

## Debilidades de validación de directorios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta proporcionada mediante `GetFinalPathNameByHandle` y después aplica **comprobaciones de cadenas allow/deny** contra raíces/exclusiones codificadas. De esta validación simplista surgen varias clases de bypass:
- **Named streams de directorio**: los directorios excluidos con permisos de escritura (por ejemplo, `C:\Windows\tracing`) pueden eludirse mediante un named stream en el propio directorio, por ejemplo, `C:\Windows\tracing:file.exe`. Las comprobaciones de cadenas detectan `C:\Windows\` y no encuentran la subruta excluida.
- **Archivo/directorio con permisos de escritura dentro de una raíz permitida**: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo con permisos de escritura bajo una raíz permitida con un payload ejecutable funciona, o copiar un EXE firmado con `uiAccess="true"` a cualquier subdirectorio con permisos de escritura (por ejemplo, restos de actualizaciones como `Tasks_Migrated` cuando están presentes) permite superar la comprobación de ruta segura.
- **MSIX en `C:\Program Files\WindowsApps` (corregido)**: los usuarios que no eran administradores podían instalar paquetes MSIX firmados que terminaban en `WindowsApps`, una ruta que no estaba excluida. Incluir un binario UIAccess dentro del MSIX y después iniciarlo mediante `RAiLaunchAdminProcess` producía un **proceso UIAccess con High IL sin aviso**. Microsoft mitigó esto excluyendo la ruta; la propia capability restringida `uiAccess` de MSIX ya requiere una instalación con privilegios de administrador.<sup>[[1]](#references)</sup>

## Flujo de ataque (High IL sin aviso)
1. Obtener/crear un **binario UIAccess firmado** (manifest `uiAccess="true"`).
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un caso límite de validación de rutas/un artefacto con permisos de escritura, como se ha indicado anteriormente).
3. Llamar a `RAiLaunchAdminProcess` para iniciarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese punto de apoyo con High IL, atacar otro proceso con High IL del escritorio mediante **window hooks/inyección de DLL** u otras primitivas con el mismo IL para comprometer por completo el contexto del administrador.<sup>[[1]](#references)</sup>

## Enumeración de rutas candidatas con permisos de escritura
Ejecuta el helper de PowerShell para descubrir objetos con permisos de escritura/sobrescritura dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator for broader visibility; set `-ProcessId` to a low-priv process to mirror that token’s access.
- Filter manually to exclude known disallowed subdirectories before using candidates with `RAiLaunchAdminProcess`.

## Relacionado

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referencias

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
