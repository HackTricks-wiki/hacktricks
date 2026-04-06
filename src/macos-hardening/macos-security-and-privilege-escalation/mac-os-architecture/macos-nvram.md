# NVRAM de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**NVRAM** (memoria de acceso aleatorio no volátil) almacena la **configuración a nivel de firmware y de tiempo de arranque** en el hardware Mac. Las variables más críticas para la seguridad incluyen:

| Variable | Propósito |
|---|---|
| `boot-args` | Argumentos de arranque del kernel (flags de depuración, arranque verbose, bypass de AMFI) |
| `csr-active-config` | **máscara de bits de configuración de SIP** — controla qué protecciones están activas |
| `SystemAudioVolume` | Volumen de audio en el arranque |
| `prev-lang:kbd` | Idioma/ distribución de teclado preferidos |
| `efi-boot-device-data` | Selección del dispositivo de arranque |

En los Macs modernos, las variables NVRAM se dividen entre variables del sistema (protegidas por Secure Boot) y variables no del sistema. Los Macs con Apple Silicon usan un **Secure Storage Component (SSC)** para vincular criptográficamente el estado de la NVRAM a la cadena de arranque.

## Acceso a NVRAM desde espacio de usuario

### Lectura de NVRAM
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

Escribir variables NVRAM requiere **privilegios root** y, para variables críticas del sistema (como `csr-active-config`), el proceso debe tener banderas específicas de firma de código o entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Indicador CS_NVRAM_UNRESTRICTED

Los binarios con el indicador de firma de código **`CS_NVRAM_UNRESTRICTED`** pueden modificar variables NVRAM que normalmente están protegidas incluso frente a root.

### Encontrar binarios NVRAM sin restricciones
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicaciones de seguridad

### Debilitamiento de SIP vía NVRAM

Si un atacante puede escribir en NVRAM (ya sea a través de un NVRAM-unrestricted binary comprometido o explotando una vulnerabilidad), puede modificar `csr-active-config` para **desactivar las protecciones SIP en el próximo arranque**:
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
> En los Macs modernos con Apple Silicon, la **cadena de Secure Boot valida los cambios en NVRAM** y evita la modificación en tiempo de ejecución de SIP. Los cambios en `csr-active-config` solo surten efecto a través de recoveryOS. Sin embargo, en **Macs con Intel** o sistemas con **reduced security mode**, la manipulación de NVRAM aún puede debilitar SIP.
    
### Habilitar la depuración del kernel
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

Las modificaciones de NVRAM **sobreviven a la reinstalación del sistema operativo** — persisten a nivel de firmware. Un atacante puede escribir variables NVRAM personalizadas que un mecanismo de persistencia lee en el arranque:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> La persistencia de NVRAM sobrevive a los borrados de disco y a las reinstalaciones del sistema operativo. Requiere un reinicio de PRAM/NVRAM (Command+Option+P+R en Macs Intel) o una restauración DFU (Apple Silicon) para eliminarla.

### AMFI Bypass

El argumento de arranque `amfi_get_out_of_my_way=1` desactiva **Apple Mobile File Integrity**, permitiendo que código sin firma se ejecute:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVEs del mundo real

| CVE | Descripción |
|---|---|
| CVE-2020-9839 | Manipulación de NVRAM que permite bypass persistente de SIP |
| CVE-2019-8779 | Persistencia de NVRAM a nivel de firmware en T2 Macs |
| CVE-2022-22583 | PackageKit NVRAM-related privilege escalation |
| CVE-2020-10004 | Problema lógico en el manejo de NVRAM que permite la modificación del sistema |

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

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
