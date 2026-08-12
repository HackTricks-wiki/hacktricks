# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**NVRAM** (Non-Volatile Random-Access Memory) almacena el firmware y el estado del arranque temprano fuera del sistema de archivos normal de macOS. Su impacto en la seguridad depende tanto de la variable como de la arquitectura de arranque:

| Variable | Propósito / relevancia para la seguridad |
|---|---|
| `boot-args` | Argumentos ofrecidos al kernel. Los argumentos de depuración o que reducen la seguridad se filtran a menos que la boot policy los permita. |
| `csr-active-config` | Bitmask de SIP en Macs Intel. En Apple silicon, la política equivalente se almacena en el `LocalPolicy` por volumen y no se considera confiable directamente desde esta variable. |
| `efi-boot-device` / `efi-boot-device-data` | Objetivo de arranque EFI de Intel. |
| `boot-volume` | Estado de selección del boot volume en Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Ejemplos de configuraciones persistentes ordinarias. |

La distinción importante es entre los **datos almacenados en NVRAM** y una **security policy aceptada por la cadena de arranque**. En Apple silicon, el Secure Enclave firma un `LocalPolicy` por grupo de boot volume; un nonce almacenado en el Secure Storage Component proporciona protección anti-replay. En consecuencia, cambiar una propiedad de NVRAM con un nombre similar no reescribe por sí solo la boot policy aceptada.<sup>[[1]](#references)[[4]](#references)</sup>

## Acceso a NVRAM desde el espacio de usuario

### Lectura y recopilación de la línea base
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
No clasifiques cada clave desconocida como maliciosa. El hardware, recoveryOS, las actualizaciones, Find My y los fallos de arranque generan variables que dependen del modelo y de la versión. Compara una captura con una línea base anterior del **mismo Mac**, y trata los blobs binarios inesperados, los cambios en la selección de arranque o los argumentos que reducen la seguridad como indicios, no como una prueba de compromiso.

### Escritura de NVRAM

root puede crear o cambiar muchas variables ordinarias, pero las variables protegidas también dependen del espacio de nombres de la variable, SIP, las reglas del kernel para cada variable y los entitlements restringidos de Apple. Por lo tanto, que `sudo` tenga éxito con una clave personalizada inofensiva **no** demuestra que el proceso pueda modificar `boot-args`, SIP o las variables de la región del sistema.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Evita `nvram -c` durante las pruebas: solicita la eliminación de todas las variables eliminables y puede cambiar el comportamiento de arranque/recuperación. Algunas variables son exclusivas del kernel, están protegidas por entitlements, están ocultas al leerlas o solo se pueden eliminar durante un restablecimiento de NVRAM.

## NVRAM Entitlements and `CS_NVRAM_UNRESTRICTED`

En el momento de exec, XNU asigna `com.apple.rootless.restricted-nvram-variables.heritable` a la flag de proceso **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Esto no equivale a la comprobación habitual del UID efectivo 0. También existen entitlements privados más específicos para determinadas variables u operaciones.

Inspecciona los entitlements en lugar de basarte en la línea de flags genéricos que muestra `codesign`:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Al auditar un helper privilegiado, rastrea la **identidad real del cliente y la ruta de la solicitud**. Un error de confused-deputy en un servicio con entitlements puede ser más útil que invocar `nvram` directamente, pero la variable/operación accesible aún puede estar restringida por XNU.

## Estado de SIP en Intel frente a `LocalPolicy` en Apple Silicon

### Intel: `csr-active-config`

En Intel, `csr-active-config` codifica las excepciones `CSR_ALLOW_*`. Las posiciones de bits habitualmente relevantes son:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Lee la configuración efectiva con `csrutil status`; la salida sin procesar de `nvram` puede usar bytes little-endian codificados en porcentaje. Consulta [macOS SIP](../macos-security-protections/macos-sip.md) para conocer las implicaciones de protección y bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: inspeccionar la política de arranque aceptada

En Apple silicon, `sip0` en `LocalPolicy`, firmada por Secure Enclave, contiene los bits de política de SIP que anteriormente se almacenaban en NVRAM. Los otros campos de política relevantes son `sip1` (permitir un fallo en la verificación del root-hash de SSV), `sip2` (no bloquear la memoria del kernel con CTRR) y `sip3` (desactivar la allowlist de `boot-args` de iBoot). Estos campos solo se pueden modificar desde un One True recoveryOS (1TR emparejado); habilitar `sip3` también requiere cambiar a Permissive Security.<sup>[[4]](#references)</sup>

Usa únicamente las operaciones de visualización durante la enumeración:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> No uses las opciones de `bputil` que cambian políticas durante una auditoría. Un compromiso normal de macOS no debería poder activar silenciosamente los campos anteriores: la ruta de downgrade requiere deliberadamente acceso físico al 1TR emparejado y autenticación del propietario.<sup>[[4]](#references)</sup>

## Implicaciones de seguridad

### `boot-args` como amplificador tras el compromiso

Argumentos como las opciones de depuración del kernel, `kcsuffix=development` o `amfi_get_out_of_my_way=1` pueden debilitar las etapas posteriores del arranque, pero solo cuando la plataforma los acepta. En Apple silicon con Full o Reduced Security, iBoot filtra los argumentos que reducen la seguridad; los argumentos sin restricciones requieren el downgrade de la política `sip3` descrito anteriormente. En Intel, la restricción de NVRAM de SIP evita igualmente tratar un root shell como control automático de `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Consulta [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) y [kernel debugging](macos-kernel-extensions.md) en lugar de asumir que un argumento histórico se comporta de forma idéntica en todas las versiones de macOS.

### Ejecución de `rc.trampoline` respaldada por NVRAM

Investigaciones recientes documentaron un consumidor concreto de datos de NVRAM: el binario de plataforma de Apple `/System/Library/CoreServices/rc.trampoline`. Cuando launchd detecta el argumento de arranque `rc.trampoline=1`, esta tarea de arranque lee la propiedad `apple-trusted-trampoline` de `IODeviceTree:/options`, la escribe en un ejecutable temporal, lo inicia suspendido, comprueba su estado de code-signing, lo desvincula y, después, reanuda su ejecución. La tarea de arranque bloquea launchd hasta que el proceso hijo termina.<sup>[[5]](#references)</sup>

Esto es una **primitive de persistencia posterior a un downgrade, no un bypass de SIP**. La ruta demostrada requería que SIP estuviera deshabilitado para que la tarea de arranque se ejecutara y se pudiera establecer `boot-args`. La investigación también observó un límite aproximado de 390 KB para el tamaño del valor. Su utilidad consiste en que los bytes ejecutables pueden residir fuera del sistema de archivos normal y materializarse durante el arranque después de que un atacante ya haya obtenido el downgrade de seguridad requerido.<sup>[[5]](#references)</sup>

Busca ambos artefactos requeridos y el evento de launchd:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Las variables NVRAM personalizadas arbitrarias son, por lo demás, solo **almacenamiento**: no ejecutan nada a menos que el firmware, un componente de arranque de Apple o un mecanismo de persistencia independiente las consuma. Esta distinción evita exagerar un marcador como `nvram attacker-config=...`, presentándolo como ejecución de código del firmware.

## Script de enumeración

<details>
<summary>Auditoría de NVRAM y boot-policy en Apple silicon</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Guía de seguridad de Apple Platform — Proceso de arranque](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Actualizaciones de seguridad de Apple — CVE relacionados con NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Seguridad de Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Seguridad de Apple Platform — Contenido de un archivo LocalPolicy para un Mac con Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Más allá de los buenos y antiguos LaunchAgents — Persistencia mediante NVRAM con apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
