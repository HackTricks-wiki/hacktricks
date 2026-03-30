# Evasiones de Admin Protection vía UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Descripción general
- Windows AppInfo expone `RAiLaunchAdminProcess` para crear procesos UIAccess (destinados a la accesibilidad). UIAccess evita la mayoría del filtrado de mensajes de User Interface Privilege Isolation (UIPI) para que el software de accesibilidad pueda controlar UI de un IL superior.
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, por lo que los llamadores con pocos privilegios dependen del servicio. El servicio realiza tres comprobaciones sobre el binario objetivo antes de establecer UIAccess:
  - El manifest embebido contiene `uiAccess="true"`.
  - Firmado por cualquier certificado confiable en el almacén Local Machine root (sin requisito de EKU/Microsoft).
  - Ubicado en una ruta accesible solo por administradores en la unidad del sistema (por ejemplo, `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluyendo subrutas específicas escribibles).
- `RAiLaunchAdminProcess` no muestra ningún prompt de consentimiento para lanzamientos UIAccess (si no, las herramientas de accesibilidad no podrían interactuar con el prompt).

## Token shaping and integrity levels
- Si las comprobaciones tienen éxito, AppInfo **copia el token del llamador**, habilita UIAccess y aumenta el Integrity Level (IL):
  - Limited admin user (user is in Administrators but running filtered) ➜ **High IL**.
  - Non-admin user ➜ IL incrementado en **+16 levels** hasta un límite **High** (System IL nunca se asigna).
  - Si el token del llamador ya tiene UIAccess, el IL queda sin cambios.
- Truco “Ratchet”: un proceso UIAccess puede deshabilitar UIAccess en sí mismo, relanzarse vía `RAiLaunchAdminProcess` y obtener otro incremento de +16 IL. Medium➜High requiere 255 relanzamientos (ruidoso, pero funciona).

## Por qué UIAccess permite escapar de Admin Protection
- UIAccess permite que un proceso de IL inferior envíe mensajes de ventana a ventanas de IL superior (evadiendo los filtros UIPI). En IL iguales, primitivas clásicas de UI como `SetWindowsHookEx` **sí permiten inyección de código/carga de DLL** en cualquier proceso que posea una ventana (incluyendo las ventanas solo-mensaje usadas por COM).
- Admin Protection lanza el proceso UIAccess bajo la identidad del usuario limitado pero en **High IL**, silenciosamente. Una vez que se ejecuta código arbitrario dentro de ese proceso UIAccess en High IL, el atacante puede inyectar en otros procesos High IL en el escritorio (incluso pertenecientes a distintos usuarios), rompiendo la separación prevista.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- En Windows 10 1803+ la API se movió a Win32k (`NtUserGetWindowProcessHandle`) y puede abrir un handle de proceso usando un `DesiredAccess` suministrado por el llamador. La ruta del kernel usa `ObOpenObjectByPointer(..., KernelMode, ...)`, lo que evita las comprobaciones normales de acceso en user-mode.
- Precondiciones en la práctica: la ventana objetivo debe estar en el mismo desktop y las comprobaciones UIPI deben pasar. Históricamente, un llamador con UIAccess podía evadir el fallo UIPI y aun así obtener un handle en kernel-mode (arreglado como CVE-2023-41772).
- Impacto: un handle de ventana se convierte en una **capacidad** para obtener un handle de proceso potente (comúnmente `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) que el llamador normalmente no podría abrir. Esto permite acceso cross-sandbox y puede romper límites de Protected Process / PPL si el objetivo expone cualquier ventana (incluidas ventanas solo-mensaje).
- Flujo de abuso práctico: enumerar o localizar HWNDs (p. ej., `EnumWindows`/`FindWindowEx`), resolver el PID propietario (`GetWindowThreadProcessId`), llamar a `GetProcessHandleFromHwnd`, y luego usar el handle devuelto para primitives de lectura/escritura de memoria o secuestro de código.
- Comportamiento post-fix: UIAccess ya no concede aperturas en kernel-mode cuando falla UIPI y los derechos de acceso permitidos se restringen al conjunto legado de hooks; Windows 11 24H2 añade comprobaciones de protección de procesos y rutas más seguras habilitadas por flags. Deshabilitar UIPI a nivel sistema (`EnforceUIPI=0`) debilita estas protecciones.

## Weaknesses en la validación de directorios seguros (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta suministrada vía `GetFinalPathNameByHandle` y luego aplica **comprobaciones de string allow/deny** contra raíces/exclusiones codificadas. Varias clases de bypass provienen de esa validación simplista:
- **Directory named streams**: Las rutas excluidas y escribibles (p. ej., `C:\Windows\tracing`) pueden ser evadidas con un named stream en el propio directorio, p. ej. `C:\Windows\tracing:file.exe`. Las comprobaciones de string ven `C:\Windows\` y pasan por alto la subruta excluida.
- **Archivo/directorio escribible dentro de una raíz permitida**: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo escribible bajo una raíz permitida con un payload ejecutable funciona, o copiar un EXE firmado con `uiAccess="true"` en cualquier subdirectorio escribible (p. ej., restos de actualizaciones como `Tasks_Migrated` cuando están presentes) permite pasar la comprobación de ruta segura.
- **MSIX en `C:\Program Files\WindowsApps` (fixeado)**: Los no-admin podían instalar paquetes MSIX firmados que quedaban en `WindowsApps`, que no estaba excluida. Empaquetar un binario UIAccess dentro del MSIX y lanzarlo vía `RAiLaunchAdminProcess` producía un **proceso UIAccess en High IL sin prompt**. Microsoft mitigó excluyendo esta ruta; la capability restringida `uiAccess` en MSIX ya requiere instalación por admin.

## Flujo de ataque (High IL sin prompt)
1. Obtener/compilar un binario UIAccess **firmado** (manifest `uiAccess="true"`).
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un caso límite de validación de ruta/artefacto escribible como arriba).
3. Llamar a `RAiLaunchAdminProcess` para iniciarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese foothold en High IL, atacar otro proceso High IL en el escritorio usando **window hooks/DLL injection** u otras primitivas de mismo IL para comprometer completamente el contexto admin.

## Enumerar rutas candidatas escribibles
Ejecuta el helper de PowerShell para descubrir objetos escribibles/sobreescribibles dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Ejecutar como Administrador para una visibilidad más amplia; establecer `-ProcessId` en un proceso de bajo privilegio para reflejar el acceso de ese token.
- Filtrar manualmente para excluir subdirectorios conocidos no permitidos antes de usar candidatos con `RAiLaunchAdminProcess`.

## Related

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Referencias
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
