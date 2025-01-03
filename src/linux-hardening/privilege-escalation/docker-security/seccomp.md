# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

**Seccomp**, qui signifie mode de calcul sécurisé, est une fonctionnalité de sécurité du **noyau Linux conçue pour filtrer les appels système**. Il restreint les processus à un ensemble limité d'appels système (`exit()`, `sigreturn()`, `read()`, et `write()` pour les descripteurs de fichiers déjà ouverts). Si un processus essaie d'appeler autre chose, il est terminé par le noyau en utilisant SIGKILL ou SIGSYS. Ce mécanisme ne virtualise pas les ressources mais isole le processus d'elles.

Il existe deux façons d'activer seccomp : via l'appel système `prctl(2)` avec `PR_SET_SECCOMP`, ou pour les noyaux Linux 3.17 et supérieurs, l'appel système `seccomp(2)`. L'ancienne méthode d'activation de seccomp en écrivant dans `/proc/self/seccomp` a été dépréciée au profit de `prctl()`.

Une amélioration, **seccomp-bpf**, ajoute la capacité de filtrer les appels système avec une politique personnalisable, en utilisant des règles de Berkeley Packet Filter (BPF). Cette extension est exploitée par des logiciels tels qu'OpenSSH, vsftpd, et les navigateurs Chrome/Chromium sur Chrome OS et Linux pour un filtrage des appels système flexible et efficace, offrant une alternative à l'ancien systrace pour Linux.

### **Mode Original/Strict**

Dans ce mode, Seccomp **n'autorise que les appels système** `exit()`, `sigreturn()`, `read()` et `write()` pour les descripteurs de fichiers déjà ouverts. Si un autre appel système est effectué, le processus est tué en utilisant SIGKILL.
```c:seccomp_strict.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

Ce mode permet **le filtrage des appels système à l'aide d'une politique configurable** mise en œuvre à l'aide de règles de filtre de paquets Berkeley.
```c:seccomp_bpf.c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Seccomp dans Docker

**Seccomp-bpf** est pris en charge par **Docker** pour restreindre les **syscalls** des conteneurs, réduisant ainsi efficacement la surface d'attaque. Vous pouvez trouver les **syscalls bloqués** par **défaut** sur [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) et le **profil seccomp par défaut** peut être trouvé ici [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Vous pouvez exécuter un conteneur docker avec une **politique seccomp** différente avec :
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Si vous souhaitez par exemple **interdire** à un conteneur d'exécuter un **syscall** comme `uname`, vous pouvez télécharger le profil par défaut depuis [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) et simplement **supprimer la chaîne `uname` de la liste**.\
Si vous voulez vous assurer que **certains binaires ne fonctionnent pas à l'intérieur d'un conteneur docker**, vous pouvez utiliser strace pour lister les syscalls que le binaire utilise et ensuite les interdire.\
Dans l'exemple suivant, les **syscalls** de `uname` sont découverts :
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Si vous utilisez **Docker uniquement pour lancer une application**, vous pouvez **profiler** avec **`strace`** et **permettre uniquement les syscalls** dont elle a besoin

### Exemple de politique Seccomp

[Exemple ici](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Pour illustrer la fonctionnalité Seccomp, créons un profil Seccomp désactivant l'appel système "chmod" comme ci-dessous.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Dans le profil ci-dessus, nous avons défini l'action par défaut sur "allow" et créé une liste noire pour désactiver "chmod". Pour être plus sécurisé, nous pouvons définir l'action par défaut sur "drop" et créer une liste blanche pour activer sélectivement les appels système.\
La sortie suivante montre l'appel "chmod" retournant une erreur car il est désactivé dans le profil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
La sortie suivante montre le “docker inspect” affichant le profil :
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
