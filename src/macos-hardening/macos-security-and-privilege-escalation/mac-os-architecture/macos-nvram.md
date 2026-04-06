# NVRAM do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

**NVRAM** (Memória Não Volátil de Acesso Aleatório) armazena **configuração em tempo de boot e em nível de firmware** no hardware Mac. As variáveis mais críticas para segurança incluem:

| Variable | Purpose |
|---|---|
| `boot-args` | Kernel boot arguments (flags de depuração, inicialização detalhada, AMFI bypass) |
| `csr-active-config` | **Máscara de bits de configuração do SIP** — controla quais proteções estão ativas |
| `SystemAudioVolume` | Volume de áudio na inicialização |
| `prev-lang:kbd` | Idioma preferido / layout do teclado |
| `efi-boot-device-data` | Seleção do dispositivo de boot |

Em Macs modernos, as variáveis NVRAM são divididas entre variáveis **do sistema** (protegidas por Secure Boot) e variáveis **não do sistema**. Macs com Apple Silicon usam um **Secure Storage Component (SSC)** para ligar criptograficamente o estado da NVRAM à cadeia de boot.

## NVRAM Access from User Space

### Leitura da NVRAM
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
### Gravando NVRAM

Gravar variáveis NVRAM requer **privilégios de root** e, para variáveis críticas do sistema (como `csr-active-config`), o processo deve ter flags de assinatura de código específicas ou entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

Binários com a **`CS_NVRAM_UNRESTRICTED`** code-signing flag podem modificar variáveis NVRAM que normalmente estão protegidas mesmo contra root.

### Encontrando binários NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicações de Segurança

### Enfraquecendo o SIP via NVRAM

Se um atacante puder escrever no NVRAM (seja através de um binário NVRAM-unrestricted comprometido ou explorando uma vulnerabilidade), ele pode modificar `csr-active-config` para **desativar as proteções do SIP na próxima inicialização**:
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
> Em Macs Apple Silicon modernos, a **Secure Boot chain valida alterações na NVRAM** e previne modificações do SIP em tempo de execução. As alterações em `csr-active-config` só entram em vigor através do recoveryOS. No entanto, em **Intel Macs** ou sistemas com **reduced security mode**, a manipulação da NVRAM ainda pode enfraquecer o SIP.
 
### Habilitando depuração do kernel
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
### Persistência no firmware

Modificações na NVRAM **sobrevivem à reinstalação do sistema operacional** — elas persistem no nível do firmware. Um atacante pode gravar variáveis NVRAM personalizadas que um mecanismo de persistência lê na inicialização:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> A persistência na NVRAM sobrevive a formatações de disco e reinstalações do sistema. Requer **PRAM/NVRAM reset** (Command+Option+P+R em Intel Macs) ou **DFU restore** (Apple Silicon) para ser limpa.

### AMFI Bypass

The `amfi_get_out_of_my_way=1` boot argument disables **Apple Mobile File Integrity**, allowing unsigned code to execute:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVEs do mundo real

| CVE | Descrição |
|---|---|
| CVE-2020-9839 | Manipulação de NVRAM permitindo bypass persistente do SIP |
| CVE-2019-8779 | Persistência de NVRAM em nível de firmware em Macs com T2 |
| CVE-2022-22583 | Escalada de privilégios relacionada à NVRAM no PackageKit |
| CVE-2020-10004 | Problema lógico no tratamento de NVRAM permitindo modificação do sistema |

## Script de Enumeração
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
## Referências

* [Guia de Segurança da Plataforma Apple — processo de inicialização](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — CVEs relacionadas à NVRAM](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Segurança do Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
