# NVRAM macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

La **NVRAM** (Non-Volatile Random-Access Memory) stocke la **configuration au démarrage et au niveau du firmware** sur le matériel Mac. Les variables les plus critiques pour la sécurité incluent :

| Variable | Fonction |
|---|---|
| `boot-args` | Arguments de démarrage du kernel (flags de debug, démarrage verbose, AMFI bypass) |
| `csr-active-config` | **Bitmask de configuration du SIP** — contrôle les protections qui sont actives |
| `SystemAudioVolume` | Volume audio au démarrage |
| `prev-lang:kbd` | Langue préférée / disposition du clavier |
| `efi-boot-device-data` | Sélection du périphérique de démarrage |

Sur les Mac modernes, les variables NVRAM sont réparties entre les variables **système** (protégées par Secure Boot) et les variables **non système**. Les Mac Apple Silicon utilisent un **Secure Storage Component (SSC)** pour lier cryptographiquement l’état de la NVRAM à la chaîne de démarrage.<sup>[1]</sup>

## Accès à la NVRAM depuis l’espace utilisateur

### Lecture de la NVRAM
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
### Écriture de la NVRAM

L’écriture de variables NVRAM nécessite des **privilèges root** et, pour les variables critiques du système (comme `csr-active-config`), le processus doit disposer d’indicateurs de signature de code ou d’`entitlements` spécifiques :
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Indicateur CS_NVRAM_UNRESTRICTED

Les binaires dotés de l’indicateur de signature de code **`CS_NVRAM_UNRESTRICTED`** peuvent modifier les variables NVRAM qui sont normalement protégées, même contre root.

### Recherche de binaires NVRAM-Unrestricted
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implications en matière de sécurité

### Affaiblissement de SIP via NVRAM

Si un attaquant peut écrire dans la NVRAM (soit via un binaire NVRAM-unrestricted compromis, soit en exploitant une vulnérabilité), il peut modifier `csr-active-config` afin de **désactiver les protections de SIP au prochain démarrage** :
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
> Sur les Mac Apple Silicon modernes, la **Secure Boot chain valide les modifications de la NVRAM** et empêche la modification de SIP à l’exécution. Les modifications de `csr-active-config` ne prennent effet que via recoveryOS. Cependant, sur les **Mac Intel** ou les systèmes en **reduced security mode**, la manipulation de la NVRAM peut toujours affaiblir SIP.

### Activation du débogage du noyau
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
### Persistance du firmware

Les modifications de la NVRAM **survivent à la réinstallation de l’OS** — elles persistent au niveau du firmware. Un attaquant peut écrire des variables NVRAM personnalisées qu’un mécanisme de persistance lit au démarrage :
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> La persistance dans la NVRAM survit aux effacements du disque et aux réinstallations du système d’exploitation. Elle nécessite une **réinitialisation de la PRAM/NVRAM** (Commande+Option+P+R sur les Mac Intel) ou une **restauration DFU** (Apple Silicon) pour être supprimée.

### AMFI Bypass

L’argument de démarrage `amfi_get_out_of_my_way=1` désactive **Apple Mobile File Integrity**, permettant l’exécution de code non signé :
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE réels

| CVE | Description |
|---|---|
| CVE-2020-9839 | Manipulation de la NVRAM permettant un bypass persistant de SIP |
| CVE-2019-8779 | Persistance de la NVRAM au niveau du firmware sur les Mac équipés d’une puce T2 |
| CVE-2022-22583 | Élévation de privilèges liée à la NVRAM dans PackageKit |
| CVE-2020-10004 | Problème de logique dans la gestion de la NVRAM permettant la modification du système |

## Script d’énumération
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
## Références

- [1] [Guide de sécurité des plateformes Apple — Processus de démarrage](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Mises à jour de sécurité Apple — CVE liés à NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Sécurité Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
