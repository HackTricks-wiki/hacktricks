# Volumen del Sistema Sellado de macOS y DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volumen del Sistema Sellado (SSV)

### Información básica

A partir de **macOS Big Sur (11.0)**, el volumen del sistema se sella criptográficamente mediante un **árbol hash de snapshot de APFS**. Esto se denomina **Sealed System Volume (SSV)**. La partición del sistema se monta **read-only** y cualquier modificación rompe el sello, lo que se verifica durante el arranque.

El SSV proporciona:
- **Detección de manipulaciones** — cualquier modificación de los binarios o frameworks del sistema puede detectarse mediante el sello criptográfico roto
- **Protección contra rollback** — el proceso de arranque verifica la integridad del snapshot del sistema
- **Prevención de rootkits** — ni siquiera root puede modificar archivos de forma persistente en el volumen del sistema (sin romper el sello)

### Comprobación del estado del SSV
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### Entitlements de SSV Writers

Ciertos binarios del sistema de Apple tienen entitlements que les permiten modificar o gestionar el sealed system volume:

| Entitlement | Propósito |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Revertir el system volume a un snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Crear un nuevo sealed snapshot después de las actualizaciones del sistema |
| `com.apple.rootless.install.heritable` | Escribir en rutas protegidas por SIP (heredado por los procesos secundarios) |
| `com.apple.rootless.install` | Escribir en rutas protegidas por SIP |

### Encontrar SSV Writers
```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```
### Escenarios de ataque

#### Ataque de reversión de Snapshot

Si un atacante compromete un binario con `com.apple.private.apfs.revert-to-snapshot`, puede **revertir el volumen del sistema a un estado anterior a una actualización**, restaurando vulnerabilidades conocidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> El rollback de un snapshot **deshace las actualizaciones de seguridad**, restaurando vulnerabilidades del kernel y del sistema que ya habían sido parcheadas. Esta es una de las operaciones más peligrosas posibles en macOS moderno.

#### Reemplazo de binarios del sistema

Con un bypass de SIP + capacidad de escritura en SSV, un atacante puede:

1. Montar el volumen del sistema con permisos de lectura y escritura
2. Reemplazar un daemon del sistema o una biblioteca de framework por una versión troyanizada
3. Volver a sellar el snapshot (o aceptar el sello roto si SIP ya está degradado)
4. El rootkit persiste tras los reinicios y es invisible para las herramientas de detección de userland

### CVE del mundo real

| CVE | Descripción |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass de SIP que abusa del entitlement `com.apple.rootless.install.heritable` de `system_installd` para ejecutar scripts post-instalación arbitrarios ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | Bypass de SIP: `system_installd` preparaba el script post-instalación en una carpeta protegida por SIP bajo `/tmp`, pero `/tmp` no está protegido por SIP, por lo que la carpeta podía sustituirse montando una imagen sobre ella ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — race condition de copy-on-write en XNU que permite escribir en archivos de solo lectura propiedad de root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Información básica

**DataVault** es la capa de protección de Apple para las bases de datos sensibles del sistema. Incluso **root no puede acceder a los archivos protegidos por DataVault**; solo los procesos con entitlements específicos pueden leerlos o modificarlos.<sup>[1]</sup> Entre los almacenes protegidos se incluyen:

| Base de datos protegida | Ruta | Contenido |
|---|---|---|
| TCC (sistema) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decisiones de privacidad de TCC para todo el sistema |
| TCC (usuario) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decisiones de privacidad de TCC por usuario |
| Keychain (sistema) | `/Library/Keychains/System.keychain` | Keychain del sistema |
| Keychain (usuario) | `~/Library/Keychains/login.keychain-db` | Keychain del usuario |

La protección de DataVault se aplica a **nivel del sistema de archivos** mediante atributos extendidos y flags de protección del volumen, verificados por el kernel.

### Entitlements del controlador de DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Búsqueda de controladores de DataVault
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```
### Escenarios de ataque

#### Modificación directa de la base de datos de TCC

Si un atacante compromete un binario controlador de DataVault (por ejemplo, mediante code injection en un proceso con `com.apple.private.tcc.manager`), puede **modificar directamente la base de datos de TCC** para conceder a cualquier aplicación cualquier permiso de TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modificación de la base de datos de TCC es el **bypass definitivo de la privacidad**: concede cualquier permiso silenciosamente, sin ningún aviso al usuario ni indicador visible. Históricamente, varias cadenas de escalada de privilegios de macOS han terminado con escrituras en la base de datos de TCC como payload final.

#### Acceso a la base de datos de Keychain

DataVault también protege los archivos de respaldo de Keychain. Un controlador de DataVault comprometido puede:

1. Leer los archivos sin procesar de la base de datos de Keychain
2. Extraer elementos cifrados de Keychain
3. Intentar descifrarlos offline usando la contraseña del usuario o las claves recuperadas

### CVE reales relacionados con DataVault y el bypass de TCC

| CVE | Descripción |
|---|---|
| CVE-2024-44131 | Condición de carrera con symlink en FileProvider que permite que un helper privilegiado acceda a datos protegidos por TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Como root, **crear un usuario cuyo `NFSHomeDirectory` apunte a una `TCC.db` controlada por el atacante**; al iniciar sesión, `tccd` la consume y los permisos se aplican, permitiendo acceder a los datos de otros usuarios ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": cambiar el directorio de inicio del usuario para colocar una TCC.db controlada por el atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Fallo en la conclusión del bundle que permite que una app **herede los permisos TCC de un bundle donante** sin aviso; explotado in the wild por **XCSSET** para hacer capturas de pantalla del escritorio ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` construía la ruta de la DB a partir de `$HOME`, por lo que `launchctl setenv HOME` la redirigía a una `TCC.db` controlada por el atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` tenía `com.apple.private.tcc.manager` **y** deshabilitaba la validación de bibliotecas, por lo que un plug-in HAL colocado en `/Library/Audio/Plug-Ins/HAL` podía conceder derechos TCC arbitrarios ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referencias

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
