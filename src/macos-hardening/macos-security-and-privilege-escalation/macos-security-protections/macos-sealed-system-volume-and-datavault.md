# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Información básica

A partir de **macOS Big Sur (11.0)**, el volumen del sistema está sellado criptográficamente usando un **APFS snapshot hash tree**. Esto se llama el **Sealed System Volume (SSV)**. La partición del sistema se monta **read-only** y cualquier modificación rompe el sello, que se verifica durante el arranque.

El SSV proporciona:
- **Tamper detection** — cualquier modificación a los binarios/frameworks del sistema es detectable mediante el sello criptográfico roto
- **Rollback protection** — el proceso de arranque verifica la integridad del snapshot del sistema
- **Rootkit prevention** — incluso root no puede modificar de forma persistente archivos en el volumen del sistema (sin romper el sello)

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
### Permisos de escritor SSV

Algunos binarios del sistema de Apple tienen permisos que les permiten modificar o gestionar el volumen del sistema sellado:

| Permiso | Propósito |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Revertir el volumen del sistema a una instantánea anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Crear una nueva instantánea sellada después de actualizaciones del sistema |
| `com.apple.rootless.install.heritable` | Escribir en rutas protegidas por SIP (heredado por procesos hijo) |
| `com.apple.rootless.install` | Escribir en rutas protegidas por SIP |

### Encontrar escritores SSV
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

#### Snapshot Rollback Attack

Si un atacante compromete un binario con `com.apple.private.apfs.revert-to-snapshot`, puede **revertir el volumen del sistema a un estado anterior a la actualización**, restaurando vulnerabilidades conocidas:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> La reversión de snapshot efectivamente **deshace las actualizaciones de seguridad**, restaurando vulnerabilidades del kernel y del sistema que ya habían sido parcheadas. Esta es una de las operaciones más peligrosas posibles en macOS moderno.

#### System Binary Replacement

Con SIP bypass + SSV write capability, un atacante puede:

1. Montar el volumen del sistema en modo lectura-escritura
2. Reemplazar un daemon del sistema o una librería de framework con una versión troceada
3. Volver a sellar el snapshot (o aceptar el sello roto si SIP ya está degradado)
4. El rootkit persiste entre reinicios y es invisible para las herramientas de detección en userland

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass que permite la modificación de SSV vía `system_installd` |
| CVE-2022-22583 | SSV bypass a través del manejo de snapshots de PackageKit |
| CVE-2022-46689 | Race condition que permite escrituras en archivos protegidos por SIP |

---

## DataVault

### Basic Information

**DataVault** es la capa de protección de Apple para bases de datos sensibles del sistema. Incluso **root no puede acceder a archivos protegidos por DataVault** — solo los procesos con entitlements específicos pueden leer o modificarlos. Los almacenes protegidos incluyen:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Decisiones de privacidad de TCC a nivel del sistema |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Decisiones de privacidad de TCC por usuario |
| Keychain (system) | `/Library/Keychains/System.keychain` | Keychain del sistema |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Keychain del usuario |

La protección de DataVault se aplica a nivel de sistema de archivos usando atributos extendidos y banderas de protección de volumen, verificadas por el kernel.

### Entitlements del controlador de DataVault
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Encontrar controladores de DataVault
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

#### Modificación directa de la base de datos TCC

Si un atacante compromete un binario del controlador DataVault (p. ej., mediante inyección de código en un proceso con `com.apple.private.tcc.manager`), puede **modificar directamente la base de datos TCC** para otorgar a cualquier aplicación cualquier permiso de TCC:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> La modificación de la base de datos de TCC es el **ultimate privacy bypass** — concede cualquier permiso silenciosamente, sin ningún aviso al usuario ni indicador visible. Históricamente, múltiples cadenas de escalada de privilegios en macOS han terminado con escrituras en la base de datos de TCC como el payload final.

#### Acceso a la base de datos del Keychain

DataVault también protege los archivos de respaldo del keychain. Un controlador de DataVault comprometido puede:

1. Leer los archivos sin procesar de la base de datos del keychain
2. Extraer elementos cifrados del keychain
3. Intentar descifrado offline usando la contraseña del usuario o las claves recuperadas

### CVE reales que implican DataVault/TCC bypass

| CVE | Descripción |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## Referencias

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
