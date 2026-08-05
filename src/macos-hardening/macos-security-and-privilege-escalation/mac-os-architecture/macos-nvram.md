# NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

A **NVRAM** (Non-Volatile Random-Access Memory) armazena a **configuração de inicialização e em nível de firmware** no hardware do Mac. As variáveis mais críticas para a segurança incluem:

| Variável | Finalidade |
|---|---|
| `boot-args` | Argumentos de inicialização do kernel (flags de debug, inicialização verbosa, bypass do AMFI) |
| `csr-active-config` | **Máscara de bits de configuração do SIP** — controla quais proteções estão ativas |
| `SystemAudioVolume` | Volume de áudio na inicialização |
| `prev-lang:kbd` | Idioma / layout de teclado preferido |
| `efi-boot-device-data` | Seleção do dispositivo de inicialização |

Nos Macs modernos, as variáveis da NVRAM são divididas entre variáveis do **sistema** (protegidas pelo Secure Boot) e variáveis **não pertencentes ao sistema**. Os Macs com Apple Silicon usam um **Secure Storage Component (SSC)** para vincular criptograficamente o estado da NVRAM à cadeia de inicialização.<sup>[1]</sup>

## Acesso à NVRAM a partir do espaço do usuário

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
### Gravação de NVRAM

A gravação de variáveis NVRAM requer **privilégios de root** e, para variáveis críticas do sistema (como `csr-active-config`), o processo deve ter flags ou entitlements específicos de assinatura de código:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Flag CS_NVRAM_UNRESTRICTED

Binaries com a flag de assinatura de código **`CS_NVRAM_UNRESTRICTED`** podem modificar variáveis NVRAM que normalmente são protegidas até mesmo contra o root.

### Encontrando Binaries NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implicações de Segurança

### Enfraquecendo o SIP via NVRAM

Se um atacante puder gravar na NVRAM (seja por meio de um binário comprometido com acesso irrestrito à NVRAM ou explorando uma vulnerabilidade), ele poderá modificar `csr-active-config` para **desativar as proteções do SIP na próxima inicialização**:
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
> Em Macs Apple Silicon modernos, a **Secure Boot chain valida as alterações na NVRAM** e impede a modificação do SIP em runtime. As alterações em `csr-active-config` só entram em vigor por meio do recoveryOS. No entanto, em **Macs Intel** ou sistemas com **reduced security mode**, a manipulação da NVRAM ainda pode enfraquecer o SIP.

### Habilitando a depuração do kernel
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
### Persistência no Firmware

As modificações na NVRAM **sobrevivem à reinstalação do SO** — elas persistem no nível do firmware. Um atacante pode gravar variáveis personalizadas na NVRAM que um mecanismo de persistência lê durante a inicialização:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> A persistência no NVRAM sobrevive a apagamentos do disco e reinstalações do sistema operacional. Para limpá-la, é necessário um **reset de PRAM/NVRAM** (Command+Option+P+R em Macs Intel) ou uma **restauração via DFU** (Apple Silicon).

### AMFI Bypass

O argumento de inicialização `amfi_get_out_of_my_way=1` desativa o **Apple Mobile File Integrity**, permitindo a execução de código não assinado:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVEs do Mundo Real

| CVE | Descrição |
|---|---|
| CVE-2020-9839 | Manipulação do NVRAM permitindo bypass persistente do SIP |
| CVE-2019-8779 | Persistência do NVRAM em nível de firmware em Macs T2 |
| CVE-2022-22583 | Escalonamento de privilégios relacionado ao NVRAM no PackageKit |
| CVE-2020-10004 | Problema lógico no tratamento do NVRAM permitindo a modificação do sistema |

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

- [1] [Guia de segurança das plataformas Apple — Processo de inicialização](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Atualizações de segurança da Apple — CVEs relacionados ao NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Segurança do Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
