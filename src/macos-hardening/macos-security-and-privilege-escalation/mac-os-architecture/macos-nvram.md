# NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

**NVRAM** (Non-Volatile Random-Access Memory) stocke l’état du firmware et du démarrage précoce en dehors du système de fichiers macOS normal. Son impact sur la sécurité dépend à la fois de la variable et de l’architecture de démarrage :

| Variable | Fonction / pertinence en matière de sécurité |
|---|---|
| `boot-args` | Arguments proposés au kernel. Les arguments de débogage ou réduisant la sécurité sont filtrés, sauf si la boot policy les autorise. |
| `csr-active-config` | Bitmask de SIP sur les Mac Intel. Sur Apple silicon, la policy équivalente est stockée dans la `LocalPolicy` propre à chaque volume et n’est pas approuvée directement à partir de cette variable. |
| `efi-boot-device` / `efi-boot-device-data` | Cible de démarrage EFI sur Intel. |
| `boot-volume` | État de sélection du volume de démarrage sur Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Exemples de paramètres persistants ordinaires. |

La distinction importante se situe entre les **données stockées dans la NVRAM** et une **security policy acceptée par la chaîne de démarrage**. Sur Apple silicon, le Secure Enclave signe une `LocalPolicy` propre à chaque groupe de volumes de démarrage ; un nonce conservé dans le Secure Storage Component fournit une protection anti-rejeu. Par conséquent, modifier une propriété NVRAM portant un nom similaire ne réécrit pas à elle seule la boot policy acceptée.<sup>[[1]](#references)[[4]](#references)</sup>

## Accès à la NVRAM depuis l’espace utilisateur

### Lecture et collecte de référence
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
Ne considérez pas chaque clé inconnue comme malveillante. Le matériel, recoveryOS, les mises à jour, Find My et les échecs de démarrage créent tous des variables dépendantes du modèle et de la version. Comparez une capture avec une référence antérieure du **même Mac**, et considérez les blobs binaires inattendus, la sélection de démarrage modifiée ou les arguments réduisant la sécurité comme des pistes plutôt que comme une preuve de compromission.

### Écriture de NVRAM

Root peut créer ou modifier de nombreuses variables ordinaires, mais les variables protégées dépendent en outre de l’espace de noms de la variable, de SIP, des règles du kernel propres à chaque variable et des entitlements Apple restreints. Par conséquent, la réussite de `sudo` pour une clé personnalisée inoffensive ne prouve **pas** que le processus peut modifier `boot-args`, SIP ou les variables de la région système.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Évitez `nvram -c` pendant les tests : cette commande demande la suppression de toutes les variables supprimables et peut modifier le comportement du démarrage/de la récupération. Certaines variables sont réservées au kernel, protégées par des entitlements, masquées lors de la lecture ou supprimables uniquement lors d'une réinitialisation de la NVRAM.

## Entitlements NVRAM et `CS_NVRAM_UNRESTRICTED`

Au moment de l'exécution, XNU mappe `com.apple.rootless.restricted-nvram-variables.heritable` vers le flag de processus **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Cela n'est pas équivalent à la vérification ordinaire de l'UID effectif 0. Il existe également des entitlements privés plus restreints pour certaines variables ou opérations.

Inspectez les entitlements plutôt que de vous fier à la ligne générique des flags affichée par `codesign` :
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
Lors de l’audit d’un helper privilégié, tracez **l’identité réelle du client et le chemin réel de la requête**. Une vulnérabilité de type confused-deputy dans un service doté d’entitlements peut être plus utile que l’invocation directe de `nvram`, mais la variable ou l’opération accessible peut tout de même être restreinte par XNU.

## État de SIP sur Intel vs `LocalPolicy` sur Apple Silicon

### Intel : `csr-active-config`

Sur Intel, `csr-active-config` encode les exceptions `CSR_ALLOW_*`. Les positions de bits couramment pertinentes sont :
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Lisez le paramètre effectif avec `csrutil status` ; la sortie brute de `nvram` peut utiliser des octets little-endian encodés en pourcentage. Consultez [macOS SIP](../macos-security-protections/macos-sip.md) pour connaître les implications en matière de protection et de contournement.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon : inspecter la politique de démarrage acceptée

Sur Apple silicon, `sip0` dans la `LocalPolicy` signée par le Secure Enclave contient les bits de la politique SIP autrefois stockés dans la NVRAM. Les autres champs de politique pertinents sont `sip1` (autoriser l’échec de la vérification du root-hash SSV), `sip2` (ne pas verrouiller la mémoire du kernel avec CTRR) et `sip3` (désactiver l’allowlist des `boot-args` d’iBoot). Ces champs ne sont modifiables que depuis un One True recoveryOS (1TR) associé ; l’activation de `sip3` nécessite également un downgrade vers Permissive Security.<sup>[[4]](#references)</sup>

Utilisez uniquement les opérations d’affichage pendant l’énumération :
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
> N'utilisez pas les options de modification de policy de `bputil` pendant un audit. Un compromis macOS normal ne devrait pas pouvoir activer silencieusement les champs ci-dessus : le downgrade path exige délibérément un accès physique au 1TR associé ainsi qu'une authentification du propriétaire.<sup>[[4]](#references)</sup>

## Implications de sécurité

### `boot-args` comme amplificateur post-compromission

Des arguments tels que les options de kernel-debugging, `kcsuffix=development` ou `amfi_get_out_of_my_way=1` peuvent affaiblir les étapes de boot ultérieures, mais uniquement lorsque la plateforme les accepte. Sur Apple silicon en mode Full ou Reduced Security, iBoot filtre les arguments qui réduisent la sécurité ; les arguments sans restriction nécessitent le policy downgrade `sip3` décrit ci-dessus. Sur Intel, la restriction NVRAM de SIP empêche de la même manière de considérer un root shell comme un contrôle automatique de `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Consultez [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) et [kernel debugging](macos-kernel-extensions.md) au lieu de supposer qu’un argument historique se comporte de manière identique sur chaque version de macOS.

### Exécution de `rc.trampoline` basée sur la NVRAM

Des recherches récentes ont documenté un consommateur concret de données NVRAM : le binaire de la plateforme Apple `/System/Library/CoreServices/rc.trampoline`. Lorsque launchd détecte l’argument de démarrage `rc.trampoline=1`, cette tâche de démarrage lit la propriété `apple-trusted-trampoline` depuis `IODeviceTree:/options`, l’écrit dans un fichier exécutable temporaire, le démarre en état suspendu, vérifie son état de signature de code, le supprime, puis reprend son exécution. La tâche de démarrage bloque launchd jusqu’à la fin du processus enfant.<sup>[[5]](#references)</sup>

Il s’agit d’une **primitive de persistence post-downgrade, et non d’un contournement de SIP**. Le chemin démontré nécessitait que SIP soit désactivé afin que la tâche de démarrage s’exécute et que `boot-args` puisse être défini. La recherche a également observé une limite approximative de 390 Ko pour la taille de la valeur. Son intérêt réside dans le fait que les octets exécutables peuvent être stockés en dehors du système de fichiers normal et matérialisés pendant le démarrage après qu’un attaquant a déjà obtenu le downgrade de sécurité requis.<sup>[[5]](#references)</sup>

Recherchez les deux artefacts requis ainsi que l’événement launchd :
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Les variables NVRAM personnalisées arbitraires ne servent sinon que de **stockage** : elles n'exécutent rien, sauf si le firmware, un composant de démarrage Apple ou un mécanisme de persistence distinct les exploite. Cette distinction évite de présenter à tort un marqueur tel que `nvram attacker-config=...` comme une exécution de code du firmware.

## Script d'énumération

<details>
<summary>Audit de la NVRAM et de la boot-policy des puces Apple</summary>
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

- [1] [Guide de sécurité des plateformes Apple — Processus de démarrage](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Mises à jour de sécurité Apple — CVE liés à la NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Sécurité de l’Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Sécurité des plateformes Apple — Contenu d’un fichier LocalPolicy pour un Mac avec Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Au-delà des bons vieux LaunchAgents — Persister via la NVRAM avec apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
