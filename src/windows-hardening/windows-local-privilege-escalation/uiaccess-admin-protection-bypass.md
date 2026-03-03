# Evasiones de Admin Protection vía UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Resumen
- Windows AppInfo expone `RAiLaunchAdminProcess` para lanzar procesos UIAccess (destinado a accessibility). UIAccess evita la mayoría del filtrado de mensajes de User Interface Privilege Isolation (UIPI) para que el software de accessibility pueda controlar UI de mayor IL.
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, así que los llamantes con pocos privilegios dependen del servicio. El servicio realiza tres verificaciones sobre el binario objetivo antes de establecer UIAccess:
- El manifiesto embebido contiene `uiAccess="true"`.
- Firmado por cualquier certificado confiable por el almacén Local Machine root (sin requisito de EKU/Microsoft).
- Ubicado en una ruta del sistema solo accesible por administradores en el disco del sistema (p. ej., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluyendo subrutas específicas escribibles).
- `RAiLaunchAdminProcess` no muestra ningún prompt de consentimiento para lanzamientos UIAccess (de otro modo las herramientas de accessibility no podrían controlar el prompt).

## Ajuste de token y niveles de integridad
- Si las comprobaciones tienen éxito, AppInfo **copia el token del llamante**, habilita UIAccess y aumenta el Integrity Level (IL):
- Usuario admin limitado (el usuario está en Administrators pero ejecutándose filtrado) ➜ **High IL**.
- Usuario no-admin ➜ IL incrementado en **+16 niveles** hasta un tope **High** (System IL nunca se asigna).
- Si el token del llamante ya tiene UIAccess, el IL queda sin cambios.
- “Ratchet” trick: un proceso UIAccess puede deshabilitar UIAccess en sí mismo, relanzarse vía `RAiLaunchAdminProcess`, y ganar otro incremento de +16 IL. Medium➜High toma 255 relanzamientos (ruidoso, pero funciona).

## Por qué UIAccess permite una evasión de Admin Protection
- UIAccess permite a un proceso de menor IL enviar mensajes de ventana a ventanas de mayor IL (evadiendo los filtros UIPI). A **igual IL**, primitivas clásicas de UI como `SetWindowsHookEx` **sí permiten inyección de código/carga de DLL** en cualquier proceso que posea una ventana (incluyendo ventanas solo de mensajes usadas por COM).
- Admin Protection lanza el proceso UIAccess bajo la **identidad del usuario limitado** pero en **High IL**, silenciosamente. Una vez que código arbitrario se ejecuta dentro de ese proceso UIAccess en High IL, el atacante puede inyectar en otros procesos High IL en el escritorio (incluso pertenecientes a diferentes usuarios), rompiendo el aislamiento previsto.

## Primitiva HWND-a-handle de proceso (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- En Windows 10 1803+ la API se movió a Win32k (`NtUserGetWindowProcessHandle`) y puede abrir un handle de proceso usando un `DesiredAccess` suministrado por el llamante. El camino del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, lo que evita las comprobaciones normales de acceso en modo usuario.
- Precondiciones en la práctica: la ventana objetivo debe estar en el mismo desktop, y las comprobaciones UIPI deben pasar. Históricamente, un llamante con UIAccess podía evitar el fallo de UIPI y aun así obtener un handle en modo kernel (corregido como CVE-2023-41772).
- Impacto: un handle de ventana se convierte en una **capacidad** para obtener un handle de proceso poderoso (comúnmente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que el llamante normalmente no podría abrir. Esto permite acceso entre sandboxes y puede romper fronteras de Protected Process / PPL si el objetivo expone cualquier ventana (incluyendo ventanas solo de mensajes).
- Flujo de abuso práctico: enumerar o localizar HWNDs (p. ej., `EnumWindows`/`FindWindowEx`), resolver el PID propietario (`GetWindowThreadProcessId`), llamar a `GetProcessHandleFromHwnd`, y luego usar el handle retornado para lectura/escritura de memoria o primitivas de secuestro de código.
- Comportamiento post-arreglo: UIAccess ya no concede aperturas en modo kernel cuando UIPI falla y los derechos de acceso permitidos están restringidos al conjunto legado de hooks; Windows 11 24H2 añade comprobaciones de protección de proceso y rutas más seguras habilitadas por feature flags. Deshabilitar UIPI a nivel sistema (`EnforceUIPI=0`) debilita estas protecciones.

## Debilidades en la validación de directorios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta suministrada vía `GetFinalPathNameByHandle` y luego aplica **comprobaciones de cadena allow/deny** contra raíces/exclusiones codificadas. Múltiples clases de bypass provienen de esa validación simplista:
- Flujos con nombre en el directorio: directorios excluidos escribibles (p. ej., `C:\Windows\tracing`) pueden ser eludidos con un named stream en el propio directorio, p. ej. `C:\Windows\tracing:file.exe`. Las comprobaciones de cadena ven `C:\Windows\` y pasan por alto la subruta excluida.
- Archivo/directorio escribible dentro de una raíz permitida: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo escribible bajo una raíz permitida con un payload ejecutable funciona, o copiar un EXE firmado con `uiAccess="true"` en cualquier subdirectorio escribible (p. ej., restos de actualizaciones como `Tasks_Migrated` cuando están presentes) le permite pasar la comprobación de ruta segura.
- MSIX en `C:\Program Files\WindowsApps` (resuelto): No-admins podían instalar paquetes MSIX firmados que acababan en `WindowsApps`, que no estaba excluido. Empaquetar un binario UIAccess dentro del MSIX y luego lanzarlo vía `RAiLaunchAdminProcess` producía un proceso UIAccess en High IL **sin prompt**. Microsoft mitigó excluyendo esa ruta; la capability restringida `uiAccess` en MSIX ya requiere instalación por admin.

## Flujo de ataque (High IL sin prompt)
1. Obtener/compilar un **binario UIAccess firmado** (manifiesto `uiAccess="true"`).
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un caso límite de validación de ruta/artifact escribible como arriba).
3. Llamar a `RAiLaunchAdminProcess` para lanzarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese foothold en High IL, atacar otro proceso High IL en el escritorio usando **window hooks/DLL injection** u otras primitivas de mismo IL para comprometer completamente el contexto admin.

## Enumerar rutas escribibles candidatas
Ejecuta el helper de PowerShell para descubrir objetos escribibles/sobreescribibles dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Ejecute como Administrator para mayor visibilidad; establezca `-ProcessId` en un proceso low-priv para reflejar el acceso de ese token.
- Filtre manualmente para excluir subdirectorios no permitidos conocidos antes de usar candidatos con `RAiLaunchAdminProcess`.

## Referencias
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
