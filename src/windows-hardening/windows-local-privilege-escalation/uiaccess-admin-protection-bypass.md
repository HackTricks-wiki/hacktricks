# Bypass de Admin Protection via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Resumen
- Windows AppInfo expone `RAiLaunchAdminProcess` para iniciar procesos UIAccess (destinados a accesibilidad). UIAccess evita la mayoría del filtrado de mensajes de User Interface Privilege Isolation (UIPI) para que el software de accesibilidad pueda controlar UI con IL más alto.
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, por lo que llamadores con pocos privilegios dependen del servicio. El servicio realiza tres comprobaciones en el binario objetivo antes de establecer UIAccess:
- El manifiesto embebido contiene `uiAccess="true"`.
- Firmado por cualquier certificado confiado por el almacén raíz del Local Machine (sin requisito de EKU/Microsoft).
- Ubicado en una ruta exclusiva para administradores en el disco del sistema (p. ej., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluyendo subrutas específicas escribibles).
- `RAiLaunchAdminProcess` no muestra un aviso de consentimiento para lanzamientos de UIAccess (si no, las herramientas de accesibilidad no podrían interactuar con el aviso).

## Modelado de tokens y niveles de integridad
- Si las comprobaciones tienen éxito, AppInfo **copia el token del llamador**, habilita UIAccess y aumenta el Integrity Level (IL):
- Usuario administrador limitado (el usuario está en Administrators pero ejecutándose filtrado) ➜ **High IL**.
- Usuario no administrador ➜ IL incrementado en **+16 niveles** hasta un tope **High** (System IL nunca se asigna).
- Si el token del llamador ya tiene UIAccess, el IL queda sin cambios.
- Truco “Ratchet”: un proceso UIAccess puede desactivar UIAccess en sí mismo, relanzarse vía `RAiLaunchAdminProcess` y obtener otro incremento de +16 IL. Pasar de Medium➜High requiere 255 relanzamientos (ruidoso, pero funciona).

## Por qué UIAccess permite evadir Admin Protection
- UIAccess permite que un proceso con IL inferior envíe mensajes de ventana a ventanas con IL superior (eludiendo los filtros UIPI). A **igual IL**, primitivas clásicas de UI como `SetWindowsHookEx` **do allow code injection/DLL loading** en cualquier proceso que posea una ventana (incluyendo **message-only windows** usadas por COM).
- Admin Protection inicia el proceso UIAccess bajo la **identidad del usuario limitado** pero con **High IL**, de forma silenciosa. Una vez que código arbitrario se ejecuta dentro de ese proceso UIAccess con High IL, el atacante puede inyectar en otros procesos con High IL en el escritorio (incluso de otros usuarios), rompiendo la separación prevista.

## Primitiva HWND-a-handle de proceso (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- En Windows 10 1803+ la API se movió a Win32k (`NtUserGetWindowProcessHandle`) y puede abrir un handle de proceso usando un `DesiredAccess` proporcionado por el llamador. La ruta del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, lo cual elude las comprobaciones normales de acceso en modo usuario.
- Condiciones previas en la práctica: la ventana objetivo debe estar en el mismo escritorio y las comprobaciones UIPI deben pasar. Históricamente, un llamador con UIAccess podía eludir la falla UIPI y aun así obtener un handle en modo kernel (corregido como CVE-2023-41772).
- Impacto: un handle de ventana se convierte en una **capability** para obtener un handle de proceso potente (comúnmente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que el llamador normalmente no podría abrir. Esto permite acceso cruzado entre sandboxes y puede romper los límites de Protected Process / PPL si el objetivo expone cualquier ventana (incluyendo message-only windows).
- Flujo de abuso práctico: enumerar o localizar HWNDs (p. ej., `EnumWindows`/`FindWindowEx`), resolver el PID propietario (`GetWindowThreadProcessId`), llamar a `GetProcessHandleFromHwnd`, y luego usar el handle retornado para lecturas/escrituras de memoria o primitivas de secuestro de código.
- Comportamiento tras la corrección: UIAccess ya no concede aperturas en modo kernel cuando UIPI falla y los derechos de acceso permitidos se restringen al conjunto de hooks heredado; Windows 11 24H2 añade comprobaciones de protección de procesos y rutas más seguras bajo feature flag. Desactivar UIPI a nivel sistema (`EnforceUIPI=0`) debilita estas protecciones.

## Debilidades en la validación de directorios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta suministrada mediante `GetFinalPathNameByHandle` y luego aplica **comprobaciones string de allow/deny** contra raíces/exclusiones codificadas. Varias clases de bypass derivan de esa validación simplista:
- **Directory named streams**: Los directorios excluidos y escribibles (p. ej., `C:\Windows\tracing`) pueden ser eludidos con un named stream en el propio directorio, p. ej. `C:\Windows\tracing:file.exe`. Las comprobaciones por cadena ven `C:\Windows\` y no detectan la subruta excluida.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo escribible bajo una raíz permitida con un payload ejecutable funciona, o copiar un EXE firmado con `uiAccess="true"` en cualquier subdirectorio escribible (p. ej., restos de actualización como `Tasks_Migrated` cuando están presentes) permite que pase la comprobación de ruta segura.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Usuarios no administradores podían instalar paquetes MSIX firmados que quedaban en `WindowsApps`, que no estaba excluido. Incluir un binario UIAccess dentro del MSIX y luego lanzarlo vía `RAiLaunchAdminProcess` producía un proceso UIAccess con **High IL** sin aviso. Microsoft mitigó excluyendo esta ruta; la capability MSIX `uiAccess` ya requiere instalación como admin.

## Attack workflow (High IL without a prompt)
1. Obtener/construir un **binario UIAccess firmado** (manifiesto `uiAccess="true"`).
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un caso límite de validación de ruta/artefacto escribible como arriba).
3. Llamar a `RAiLaunchAdminProcess` para iniciarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese foothold con High IL, atacar otro proceso con High IL en el escritorio usando **window hooks/DLL injection** u otras primitivas same-IL para comprometer completamente el contexto admin.

## Enumerar rutas escribibles candidatas
Ejecuta el PowerShell helper para descubrir objetos escribibles/sobrescribibles dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Ejecutar como Administrator para una visibilidad más amplia; establecer `-ProcessId` en un proceso de bajo privilegio para reflejar el acceso de ese token.
- Filtrar manualmente para excluir subdirectorios conocidos no permitidos antes de usar candidatos con `RAiLaunchAdminProcess`.

## Referencias
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
