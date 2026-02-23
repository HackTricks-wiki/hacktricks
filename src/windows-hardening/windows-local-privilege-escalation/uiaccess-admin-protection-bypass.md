# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Overview
- Windows AppInfo expone `RAiLaunchAdminProcess` para iniciar procesos UIAccess (destinados a accessibility). UIAccess evita la mayor parte del User Interface Privilege Isolation (UIPI) message filtering para que el software de accessibility pueda controlar UI de IL superior.
- Habilitar UIAccess directamente requiere `NtSetInformationToken(TokenUIAccess)` con **SeTcbPrivilege**, así que los llamadores de bajo privilegio dependen del service. El service realiza tres comprobaciones sobre el binario objetivo antes de establecer UIAccess:
- El manifiesto embebido contiene `uiAccess="true"`.
- Firmado por cualquier certificado confiado por el Local Machine root store (sin requisito de EKU/Microsoft).
- Ubicado en una ruta solo para administradores en la unidad del sistema (p. ej., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, excluyendo subrutas específicas escribibles).
- `RAiLaunchAdminProcess` no muestra ningún consent prompt para lanzamientos UIAccess (si no, las herramientas de accessibility no podrían interactuar con el prompt).

## Token shaping and integrity levels
- Si las comprobaciones tienen éxito, AppInfo **copia el caller token**, habilita UIAccess y aumenta el Integrity Level (IL):
- Limited admin user (el usuario está en Administrators pero ejecutando filtrado) ➜ **High IL**.
- Non-admin user ➜ IL aumentado en **+16 levels** hasta un tope **High** (System IL nunca se asigna).
- Si el caller token ya tiene UIAccess, el IL se deja sin cambios.
- Truco de “ratchet”: un proceso UIAccess puede deshabilitar UIAccess en sí mismo, relanzarse vía `RAiLaunchAdminProcess` y obtener otro incremento de +16 IL. Medium➜High requiere 255 relanzamientos (ruidoso, pero funciona).

## Why UIAccess enables an Admin Protection escape
- UIAccess permite que un proceso de IL inferior envíe mensajes de ventana a ventanas de IL superior (evitando los filtros UIPI). A **igual IL**, primitivas clásicas de UI como `SetWindowsHookEx` **sí permiten code injection/DLL loading** en cualquier proceso que posea una ventana (incluidas las **message-only windows** usadas por COM).
- Admin Protection inicia el proceso UIAccess bajo la identidad del **limited user** pero en **High IL**, silenciosamente. Una vez que código arbitrario corre dentro de ese proceso UIAccess de High IL, el atacante puede inyectar en otros procesos de High IL en el desktop (incluso pertenecientes a usuarios diferentes), rompiendo la separación prevista.

## Secure-directory validation weaknesses (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo resuelve la ruta suministrada vía `GetFinalPathNameByHandle` y luego aplica **comprobaciones de cadena allow/deny** contra raíces/exclusiones hardcoded. Varias clases de bypass surgen de esa validación simplista:
- **Directory named streams**: Directorios excluidos escribibles (p. ej., `C:\Windows\tracing`) pueden ser eludidos con un named stream en el propio directorio, p. ej. `C:\Windows\tracing:file.exe`. Las comprobaciones de cadena ven `C:\Windows\` y no detectan la subruta excluida.
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` **no requiere una extensión `.exe`**. Sobrescribir cualquier archivo escribible bajo una raíz permitida con un payload ejecutable funciona, o copiar un EXE firmado con `uiAccess="true"` en cualquier subdirectorio escribible (p. ej., restos de actualizaciones como `Tasks_Migrated` cuando están presentes) le permite pasar la comprobación de ruta segura.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins podían instalar paquetes MSIX firmados que acababan en `WindowsApps`, que no estaba excluido. Empaquetar un binario UIAccess dentro del MSIX y lanzarlo vía `RAiLaunchAdminProcess` resultaba en un proceso UIAccess de **High IL sin prompt**. Microsoft mitigó excluyendo esa ruta; la capability restringida `uiAccess` en MSIX ya requiere instalación por admin.

## Attack workflow (High IL without a prompt)
1. Obtener/compilar un **signed UIAccess binary** (manifiesto `uiAccess="true"`).
2. Colocarlo donde la allowlist de AppInfo lo acepte (o abusar de un edge case de validación de ruta/artifact escribible como arriba).
3. Llamar a `RAiLaunchAdminProcess` para iniciarlo **silenciosamente** con UIAccess + IL elevado.
4. Desde ese foothold de High IL, apuntar a otro proceso de High IL en el desktop usando **window hooks/DLL injection** u otras primitivas same-IL para comprometer completamente el contexto admin.

## Enumerating candidate writable paths
Ejecuta el helper de PowerShell para descubrir objetos escribibles/sobrescribibles dentro de raíces nominalmente seguras desde la perspectiva de un token elegido:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Ejecutar como Administrator para mayor visibilidad; establezca `-ProcessId` en un proceso de bajo privilegio para reflejar el acceso de ese token.
- Filtre manualmente para excluir subdirectorios conocidos no permitidos antes de usar candidatos con `RAiLaunchAdminProcess`.

## Referencias
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
