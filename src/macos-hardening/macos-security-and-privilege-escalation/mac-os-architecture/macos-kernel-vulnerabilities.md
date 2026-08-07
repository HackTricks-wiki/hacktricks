# Vulnérabilités du kernel de macOS

{{#include ../../../banners/hacktricks-training.md}}

L'exploitation récente du kernel de macOS consiste moins à « charger un kext unsigned trivial et obtenir le ring-0 » qu'à abuser des **parseurs Mach/MIG**, des **IOKit user clients**, des **races data-only dans XNU** et des **daemons disposant de specially entitled** qui peuvent encore rouvrir la surface d'attaque du kernel. Pour le reverse engineering des interfaces concrètes, consultez également les pages consacrées à [**IOKit**](macos-iokit.md) et à [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Surfaces d'attaque qui restent importantes

- **Handlers Mach/MIG** dans les daemons système et les services qui interagissent avec le kernel : descripteurs malformés, données out-of-line (OOL) et flux stateful composés de plusieurs messages.
- **IOKit user clients** : parsing spécifique aux selectors, méthodes gated par des entitlements et wrapper libraries/daemons qui masquent le véritable call graph.
- **Primitives data-only de XNU** : races autour des credentials, pointeurs protégés par SMR, zones read-only et autres endroits où une corruption modifie la policy sans qu'il soit nécessaire de prendre d'abord le contrôle de RIP/PC.
- **Code kernel tiers / auxiliaire** : les kexts legacy sont plus rares, mais les flottes enterprise, les systèmes Apple Silicon en reduced-security et les bundles vendor `.fs` / helper créent encore des chemins à forte valeur autour du kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Dans [**ce rapport**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/), plusieurs bugs de la chaîne OTA/update sont combinés pour atteindre une compromission du kernel en abusant du pipeline de software update et des capacités liées à rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024 : chaîne de bypass des protections du kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

Les [**releases de sécurité macOS de mars 2024**](https://support.apple.com/en-us/120895) d'Apple ont corrigé deux problèmes qui étaient **activement exploités** :<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel** : un bug de corruption mémoire permettant à un attaquant disposant d'un arbitrary kernel read/write de contourner les protections de la mémoire du kernel.
- **CVE-2024-23296 – RTKit** : un second bug de corruption mémoire avec le même impact public décrit.

Les détails publics de la root cause restent limités, mais cette paire rappelle que les exploit chains modernes visant Apple nécessitent souvent **plus que « simplement » du kernel R/W** : le travail de post-exploitation contre les protections mémoire, le code adjacent aux coprocessors ou les secondary trust boundaries constitue souvent l'étape où la chaîne réelle est stabilisée.

Triage rapide des correctifs :
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025 : SMR + read-only credential race (CVE-2025-24118)

Le [**write-up TRAVERTINE** de Joseph Ravichandran](https://jprx.io/cve-2025-24118/) constitue une très bonne étude de cas moderne de XNU, car il ne s'agit **pas** d'un buffer overflow classique :<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` est un **pointeur protégé par SMR**, stocké dans un objet `proc_ro` **en lecture seule**.
- Les writers doivent mettre à jour ce pointeur **atomiquement**.
- `kauth_cred_proc_update()` utilisait `zalloc_ro_mut(...)` pour modifier `p_ucred` ; sur x86_64, ce chemin finit par appeler `memcpy` / `rep movsb`, de sorte qu'un reader concurrent peut observer un **pointeur partiellement écrit**.
- Le bug se transforme en **privilege escalation data-only** : si le pointeur de credential corrompu aboutit à un autre objet de credential valide, le thread courant peut hériter d'un état plus privilégié sans avoir d'abord réussi un détournement évident du control flow.

Pattern de trigger minimal :
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
Heuristique d’audit utile : lorsqu’un chemin du kernel mélange des **SMR readers**, une **mutation de zone read-only** et des **métadonnées de credential ou de task**, vérifiez que les mises à jour utilisent les variantes atomiques `zalloc_ro_mut_*` plutôt que des helpers fondés sur la copie.

---

## 2024-2025 : contournement de SIP qui rouvre les chemins de chargement du kernel (CVE-2024-44243)

Microsoft a montré que `storagekitd` pouvait être utilisé pour **contourner SIP**, puis rendre à nouveau pertinente l’exécution de code kernel tiers sur des machines qui sembleraient autrement être en mode "post-kext". L’idée clé est la suivante :<sup>[[2]](#references)</sup>

1. Déposer ou écraser un bundle `.fs` malveillant sous `/Library/Filesystems`.
2. Déclencher `storagekitd` via Disk Utility ou `diskutil`.
3. Laisser le daemon doté des privilèges appropriés lancer les exécutables du bundle **sans supprimer correctement les privilèges ni valider le chemin**.
4. Utiliser le contournement de SIP obtenu pour modifier l’état protégé du système de fichiers et, dans la démonstration de Microsoft, remplacer la liste d’exclusion des extensions du kernel.

Pour les chercheurs en sécurité du kernel, la leçon importante est que la **surface d’attaque du kernel peut être réintroduite depuis des daemons de gestion en userland**, même lorsque le chargement direct de kexts tiers est fortement restreint.

Triage utile :
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow de fuzzing et de recherche

Si vous recherchez activement cette catégorie de bugs, les travaux publics récents vont dans la même direction :

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) reste l'une des meilleures références pour la recherche sur les kernels de l'ère Apple Silicon. Il utilise la **réécriture binaire statique** pour récupérer la couverture, désactive les chemins **contrôlés par des entitlements** pendant les tests et déduit la structure des interfaces à partir des wrappers userspace.<sup>[[4]](#references)</sup>
- Le billet de Project Zero [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) présente un workflow très pratique pour **rebaser un kext / fileset dans userspace**, afin de pouvoir fuzzer le code riche en parsers à une vitesse bien supérieure avant de le reproduire sur l'appareil.<sup>[[5]](#references)</sup>
- Pour les cibles fortement basées sur Mach, construisez des harnesses autour de **layouts de messages réels et de machines à états à appels multiples**, plutôt que de simples blobs de selectors. Les recherches récentes sur CoreAudio/Mach menées par Project Zero et les présentations de conférences telles que **Fuzzing at Mach Speed** montrent pourquoi les séquences de messages stateful continuent d'être payantes.

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
## Fiche mémo d'énumération rapide
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

- [1] [Joseph Ravichandran - TRAVERTINE : CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analyse de CVE-2024-44243, un contournement de System Integrity Protection de macOS via des extensions du kernel](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Le cauchemar de la mise à jour OTA d'Apple : contournement de la vérification de signature et prise de contrôle du kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz : fuzzing des extensions du kernel de macOS sur Apple Silicon via l'exploitation des mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Fuzzing simple des extensions du kernel de macOS en espace utilisateur avec IDA et TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [À propos du contenu de sécurité de macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
