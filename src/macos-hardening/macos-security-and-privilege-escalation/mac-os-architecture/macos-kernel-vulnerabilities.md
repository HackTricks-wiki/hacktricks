# Vulnérabilités du kernel macOS

{{#include ../../../banners/hacktricks-training.md}}

L'exploitation récente du kernel macOS consiste moins à « charger un kext trivial non signé et obtenir le ring-0 » qu'à exploiter les **parsers Mach/MIG**, les **user clients IOKit**, les **data-only races dans XNU** et les **daemons disposant de privilèges spécifiques** qui peuvent encore rouvrir la surface d'attaque du kernel. Pour effectuer le reverse engineering des interfaces concrètes, consultez également les pages consacrées à [**IOKit**](macos-iokit.md) et aux [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Surfaces d'attaque qui restent importantes

- **Handlers Mach/MIG** dans les system daemons et les services tournés vers le kernel : descripteurs malformés, données out-of-line (OOL) et flux stateful composés de plusieurs messages.
- **User clients IOKit** : parsing spécifique aux selectors, méthodes protégées par des entitlements et wrapper libraries/daemons qui masquent le véritable call graph.
- **Primitives data-only de XNU** : races autour des credentials, pointeurs protégés par SMR, read-only zones et autres emplacements où une corruption modifie la policy sans obtenir au préalable le contrôle de RIP/PC.
- **Code kernel tiers / auxiliaire** : les kexts legacy sont plus rares, mais les flottes enterprise, les systèmes Apple Silicon en reduced security et les bundles vendor `.fs` / helper créent encore des chemins à haute valeur adjacents au kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), plusieurs bugs de la chaîne OTA/update sont combinés afin d'atteindre une compromission du kernel en exploitant le pipeline de software update et les capacités liées à rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024 : chaîne de bypass des protections du kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

Les [**releases de sécurité macOS de mars 2024**](https://support.apple.com/en-us/120895) d'Apple ont corrigé deux problèmes qui étaient **activement exploités** :

- **CVE-2024-23225 – Kernel** : un bug de corruption mémoire grâce auquel un attaquant disposant d'un read/write arbitraire du kernel pouvait contourner les protections de la mémoire du kernel.
- **CVE-2024-23296 – RTKit** : un second bug de corruption mémoire avec le même impact public décrit.

Les détails publics de la root cause restent limités, mais cette paire rappelle que les exploit chains modernes visant Apple nécessitent souvent **plus que « simplement » un kernel R/W** : le post-exploitation contre les protections mémoire, le code adjacent aux coprocessors ou les secondary trust boundaries constitue fréquemment l'étape où la chaîne réelle est stabilisée.

Triage rapide des patchs :
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Le [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) de Joseph Ravichandran constitue une très bonne étude de cas moderne de XNU, car il ne s'agit **pas** d'un classic buffer overflow :

- `proc_ro.p_ucred` est un **pointeur protégé par SMR** stocké dans un objet `proc_ro` **en lecture seule**.
- Les writers doivent mettre à jour ce pointeur de manière **atomique**.
- `kauth_cred_proc_update()` utilisait `zalloc_ro_mut(...)` pour modifier `p_ucred` ; sur x86_64, ce chemin finit par atteindre `memcpy` / `rep movsb`, ce qui permet à un reader concurrent d'observer un **pointeur partiellement écrit**.
- Le bug se transforme en **data-only privilege escalation** : si le pointeur de credential corrompu pointe vers un autre credential object valide, le thread courant peut hériter d'un état plus privilégié sans avoir d'abord réussi un détournement évident du control flow.

Minimal trigger pattern :
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Heuristique d’audit utile : lorsqu’un chemin du kernel mélange des **lecteurs SMR**, la **mutation de zones en lecture seule** et des **métadonnées d’identifiants ou de tâches**, vérifiez que les mises à jour utilisent les variantes atomiques `zalloc_ro_mut_*` plutôt que des helpers basés sur la copie.

---

## 2024-2025 : contournement de SIP qui rouvre les chemins de chargement du kernel (CVE-2024-44243)

Microsoft a montré que `storagekitd` pouvait être détourné pour **contourner SIP**, puis rendre à nouveau pertinent le code kernel tiers sur des machines qui, autrement, sembleraient être en mode « post-kext ». L’idée principale est la suivante :

1. Déposer ou écraser un bundle `.fs` malveillant sous `/Library/Filesystems`.
2. Déclencher `storagekitd` via Disk Utility ou `diskutil`.
3. Laisser le daemon spécialement autorisé lancer les exécutables du bundle **sans supprimer correctement les privilèges ni valider le chemin**.
4. Utiliser le contournement de SIP obtenu pour modifier l’état protégé du système de fichiers et, dans la démonstration de Microsoft, remplacer la liste d’exclusion des extensions du kernel.

Pour les chercheurs en sécurité du kernel, la leçon importante est que **la surface d’attaque du kernel peut être réintroduite depuis les daemons de gestion de l’espace utilisateur**, même lorsque le chargement direct de kext tiers est fortement restreint.

Triage utile :
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing & workflow de recherche

Si vous recherchez activement cette classe de bugs, les travaux publics récents vont dans la même direction :

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) reste l'une des meilleures références pour la recherche sur le kernel à l'ère Apple Silicon. Il utilise la **réécriture binaire statique** pour récupérer la couverture, désactive les chemins **protégés par entitlement** pendant les tests et déduit la structure des interfaces à partir des wrappers userspace.
- Le [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) de Project Zero présente un workflow très pratique pour **rebaser un kext / fileset dans l'espace utilisateur**, afin de pouvoir fuzzer le code principalement dédié au parsing à une vitesse bien supérieure avant de le reproduire sur l'appareil.
- Pour les cibles fortement basées sur Mach, construisez des harnesses autour de **layouts de messages réels et de machines à états multi-appels**, plutôt que de simples blobs de selectors. Les recherches récentes sur CoreAudio/Mach menées par Project Zero et les présentations de conférences telles que **Fuzzing at Mach Speed** montrent pourquoi les séquences de messages stateful restent particulièrement efficaces.

Commandes locales rapides que vous utiliserez très souvent :
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Aide-mémoire d’énumération rapide
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Références

* Joseph Ravichandran. “TRAVERTINE : CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Analyse de CVE-2024-44243, un bypass de la System Integrity Protection de macOS via des extensions kernel.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
