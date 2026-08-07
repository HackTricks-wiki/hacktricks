# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**NVRAM** (Non-Volatile Random-Access Memory) almacena la **configuración de arranque y del firmware** en el hardware Mac. Las variables más importantes para la seguridad incluyen:

| Variable | Propósito |
|---|---|
| `boot-args` | Argumentos de arranque del kernel (debug flags, arranque verbose, AMFI bypass) |
| `csr-active-config` | **Bitmask de configuración de SIP**: controla qué protecciones están activas |
| `SystemAudioVolume` | Volumen de audio durante el arranque |
| `prev-lang:kbd` | Idioma preferido / distribución del teclado |
| `efi-boot-device-data` | Selección del dispositivo de arranque |

En los Mac modernos, las variables de NVRAM se dividen entre variables del **sistema** (protegidas por Secure Boot) y variables **no pertenecientes al sistema**. Los Mac con Apple Silicon utilizan un **Secure Storage Component (SSC)** para vincular criptográficamente el estado de la NVRAM con la cadena de arranque.<sup>[[1]](#references)</sup>

## Acceso a la NVRAM desde el espacio de usuario

### Lectura de la NVRAM
```bash
# List all NVRAM variables
nvram -p

# Read a specific variable
nvram boot-args

# Export all NVRAM as XML plist
nvram -xp

# Read SIP configuration
nvram csr-active-config
csrutil status
```
### Escribir NVRAM

Escribir variables de NVRAM requiere **privilegios de root** y, para las variables críticas del sistema (como `csr-active-config`), el proceso debe tener flags o entitlements específicos de code-signing:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Indicador CS_NVRAM_UNRESTRICTED

Los binarios con el indicador de firma de código **`CS_NVRAM_UNRESTRICTED`** pueden modificar variables de NVRAM que normalmente están protegidas incluso frente a root.

### Búsqueda de binarios con NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicaciones de seguridad

### Debilitamiento de SIP mediante NVRAM

Si un atacante puede escribir en NVRAM (ya sea mediante un binario comprometido sin restricciones de NVRAM o explotando una vulnerabilidad), puede modificar `csr-active-config` para **deshabilitar las protecciones de SIP en el próximo arranque**:
```bash
# SIP configuration is a bitmask stored in NVRAM
# Each bit controls a different SIP protection:
#   Bit 0 (0x1):  Filesystem protection
#   Bit 1 (0x2):  Kext signing
#   Bit 2 (0x4):  Task-for-pid restriction
#   Bit 3 (0x8):  Unrestricted filesystem
#   Bit 4 (0x10): Apple Internal (debug)
#   Bit 5 (0x20): Unrestricted DTrace
#   Bit 6 (0x40): Unrestricted NVRAM
#   Bit 7 (0x80): Device configuration

# Current SIP configuration
nvram csr-active-config | xxd

# On older hardware, a compromised NVRAM-unrestricted binary could:
# nvram csr-active-config=%7f%00%00%00   # Disable most SIP protections
```
> [!WARNING]
> En los Mac modernos con Apple Silicon, la **Secure Boot chain valida los cambios en NVRAM** y evita la modificación de SIP durante el runtime. Los cambios en `csr-active-config` solo surten efecto a través de recoveryOS. Sin embargo, en **Mac con Intel** o sistemas con **reduced security mode**, la manipulación de NVRAM todavía puede debilitar SIP.

### Activación de Kernel Debugging
```bash
# Enable kernel debug flags via boot-args
sudo nvram boot-args="debug=0x144"

# Common debug flags:
#   0x01  DB_HALT      — Wait for debugger at boot
#   0x04  DB_KPRT      — Send kernel printf to serial
#   0x40  DB_KERN_DUMP — Dump kernel core on NMI
#   0x100 DB_REBOOT_POST_PANIC — Reboot after panic

# Use development kernel
sudo nvram boot-args="kcsuffix=development"
```
### Persistencia del firmware

Las modificaciones de NVRAM **sobreviven a la reinstalación del sistema operativo**: persisten en el nivel del firmware. Un atacante puede escribir variables de NVRAM personalizadas que un mecanismo de persistencia lea durante el arranque:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> La persistencia de NVRAM sobrevive al borrado de discos y a las reinstalaciones del sistema operativo. Requiere un **restablecimiento de PRAM/NVRAM** (Command+Option+P+R en Macs Intel) o una **restauración mediante DFU** (Apple Silicon) para eliminarla.

### AMFI Bypass

El argumento de arranque `amfi_get_out_of_my_way=1` deshabilita **Apple Mobile File Integrity**, lo que permite ejecutar código sin firmar:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE del mundo real

| CVE | Descripción |
|---|---|
| CVE-2020-9839 | Manipulación de NVRAM que permite el bypass persistente de SIP <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | Persistencia de NVRAM a nivel de firmware en Macs con T2 <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | Escalada de privilegios relacionada con NVRAM en PackageKit |
| CVE-2020-10004 | Problema lógico en el manejo de NVRAM que permite modificar el sistema |

## Script de enumeración
```bash
#!/bin/bash
echo "=== NVRAM Security Audit ==="

# Current SIP status
echo -e "\n[*] SIP Status:"
csrutil status

# Current boot-args
echo -e "\n[*] Boot Arguments:"
nvram boot-args 2>/dev/null || echo "  (none set)"

# All NVRAM variables
echo -e "\n[*] All NVRAM Variables:"
nvram -p | grep -v "^$" | wc -l
echo "  variables total"

# Security-relevant variables
echo -e "\n[*] Security-Relevant Variables:"
for var in csr-active-config boot-args StartupMute SystemAudioVolume efi-boot-device; do
echo "  $var: $(nvram "$var" 2>/dev/null || echo 'not set')"
done

# Check for custom (non-Apple) variables
echo -e "\n[*] Non-Standard Variables (potential persistence):"
nvram -p | grep -v "^$" | grep -vE "^(SystemAudioVolume|boot-args|csr-active-config|prev-lang|LocationServicesEnabled|fmm-mobileme-token|bluetoothInternalControllerAddress|bluetoothActiveControllerInfo|SystemAudioVolumeExtension|efi-)" | head -20
```
## Referencias

- [1] [Guía de seguridad de Apple — Proceso de arranque](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Actualizaciones de seguridad de Apple — CVE relacionados con NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Seguridad de Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
