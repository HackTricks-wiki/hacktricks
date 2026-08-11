# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**MACF** significa **Mandatory Access Control Framework**, un sistema de seguridad integrado en el sistema operativo que ayuda a proteger el equipo. Funciona estableciendo **reglas estrictas sobre quién o qué puede acceder a determinadas partes del sistema**, como archivos, aplicaciones y recursos del sistema. Al aplicar estas reglas automáticamente, MACF garantiza que solo los usuarios y procesos autorizados puedan realizar acciones específicas, reduciendo el riesgo de acceso no autorizado o actividades maliciosas.

Ten en cuenta que MACF realmente no toma ninguna decisión, ya que solo **intercepta** acciones; deja las decisiones en manos de los **módulos de políticas** (extensiones del kernel) que utiliza, como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` y `mcxalr.kext`.

- Una política puede estar aplicando restricciones (devuelve 0 o un valor distinto de cero en alguna operación)
- Una política puede estar monitorizando (devuelve 0 para no objetar, pero aprovechar el hook para hacer algo)
- Una política estática de MACF se instala durante el arranque y NUNCA se eliminará
- Una política dinámica de MACF se instala mediante un KEXT (kextload) y, hipotéticamente, puede descargarse mediante kextunload
- En iOS solo se permiten políticas estáticas, mientras que en macOS se permiten políticas estáticas y dinámicas.<sup>[[7]](#references)</sup>

### Flujo

1. El proceso realiza una syscall/mach trap
2. La función relevante se llama dentro del kernel
3. La función llama a MACF
4. MACF comprueba los módulos de políticas que solicitaron hacer hook de esa función en su política
5. MACF llama a las políticas relevantes
6. Las políticas indican si permiten o deniegan la acción

> [!CAUTION]
> Apple es la única entidad que puede utilizar la KPI de MAC Framework.

Normalmente, las funciones que comprueban permisos con MACF llaman a la macro `MAC_CHECK`. Por ejemplo, en el caso de una syscall para crear un socket, se llamará a la función `mac_socket_check_create`, que llama a `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Además, la macro `MAC_CHECK` está definida en security/mac_internal.h como:<sup>[[3]](#references)</sup>
```c
Resolver tambien MAC_POLICY_ITERATE, MAC_CHECK_CALL, MAC_CHECK_RSLT


#define MAC_CHECK(check, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_ ## check != NULL) {                   \
MAC_CHECK_CALL(check, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
MAC_CHECK_RSLT(check, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
Ten en cuenta que, al transformar `check` en `socket_check_create` y `args...` en `(cred, domain, type, protocol)`, obtienes:
```c
// Note the "##" just get the param name and append it to the prefix
#define MAC_CHECK(socket_check_create, args...) do {                                   \
error = 0;                                                           \
MAC_POLICY_ITERATE({                                                 \
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {                   \
MAC_CHECK_CALL(socket_check_create, mpc);                          \
int __step_err = mpc->mpc_ops->mpo_socket_check_create (args); \
MAC_CHECK_RSLT(socket_check_create, mpc);                          \
error = mac_error_select(__step_err, error);         \
}                                                            \
});                                                                  \
} while (0)
```
La expansión de las macros auxiliares muestra el flujo de control concreto:
```c
do {                                                // MAC_CHECK
error = 0;
do {                                            // MAC_POLICY_ITERATE
struct mac_policy_conf *mpc;
u_int i;
for (i = 0; i < mac_policy_list.staticmax; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK); // MAC_CHECK_CALL
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);                    // MAC_CHECK_RSLT
error = mac_error_select(__step_err, error);
}
}
if (mac_policy_list_conditional_busy() != 0) {
for (; i <= mac_policy_list.maxindex; i++) {
mpc = mac_policy_list.entries[i].mpc;
if (mpc == NULL) {
continue;
}
if (mpc->mpc_ops->mpo_socket_check_create != NULL) {
DTRACE_MACF3(mac__call__socket_check_create,
void *, mpc, int, error, int, MAC_ITERATE_CHECK);
int __step_err = mpc->mpc_ops->mpo_socket_check_create(args);
DTRACE_MACF2(mac__rslt__socket_check_create,
void *, mpc, int, __step_err);
error = mac_error_select(__step_err, error);
}
}
mac_policy_list_unbusy();
}
} while (0);
} while (0);
```
En otras palabras, `MAC_CHECK(socket_check_create, ...)` recorre primero las políticas estáticas, bloquea condicionalmente y itera sobre las políticas dinámicas, emite las sondas de DTrace alrededor de cada hook y combina el código de retorno de cada hook en el único resultado `error` mediante `mac_error_select()`.


### Etiquetas

MACF utiliza **etiquetas** que posteriormente serán utilizadas por las políticas para comprobar si deben conceder o no algún acceso. El código de declaración de la estructura de etiquetas se puede [encontrar aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), y se utiliza dentro de **`struct ucred`** [aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), en la parte **`cr_label`**. La etiqueta contiene flags y un número de **slots** que pueden ser utilizados por las **políticas MACF para asignar punteros**. Por ejemplo, Sandbox apuntará al perfil del contenedor.

## Políticas MACF

Una política MACF define **reglas y condiciones que se aplicarán en determinadas operaciones del kernel**.

Una extensión del kernel podría configurar una estructura `mac_policy_conf` y luego registrarla llamando a `mac_policy_register`. Desde [aquí](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered entry-point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better alignment on 64bit platforms */
struct mac_policy_conf {
const char		*mpc_name;		/** policy name */
const char		*mpc_fullname;		/** full name */
const char		**mpc_labelnames;	/** managed label namespaces */
unsigned int		 mpc_labelname_count;	/** number of managed label namespaces */
struct mac_policy_ops	*mpc_ops;		/** operation vector */
int			 mpc_loadtime_flags;	/** load time flags */
int			*mpc_field_off;		/** label slot */
int			 mpc_runtime_flags;	/** run time flags */
mpc_t			 mpc_list;		/** List reference */
void			*mpc_data;		/** module data */
};
```
Es fácil identificar las extensiones del kernel que configuran estas políticas comprobando las llamadas a `mac_policy_register`. Además, al revisar el desensamblado de la extensión, también es posible encontrar la estructura `mac_policy_conf` utilizada.

Ten en cuenta que las políticas MACF también pueden registrarse y anularse **dinámicamente**.

Uno de los campos principales de `mac_policy_conf` es **`mpc_ops`**. Este campo especifica qué operaciones interesan a la política. Hay cientos de ellas, por lo que es posible poner a cero todas las entradas y seleccionar después solo las que necesita la política. Desde [aquí](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>
```c
struct mac_policy_ops {
mpo_audit_check_postselect_t		*mpo_audit_check_postselect;
mpo_audit_check_preselect_t		*mpo_audit_check_preselect;
mpo_bpfdesc_label_associate_t		*mpo_bpfdesc_label_associate;
mpo_bpfdesc_label_destroy_t		*mpo_bpfdesc_label_destroy;
mpo_bpfdesc_label_init_t		*mpo_bpfdesc_label_init;
mpo_bpfdesc_check_receive_t		*mpo_bpfdesc_check_receive;
mpo_cred_check_label_update_execve_t	*mpo_cred_check_label_update_execve;
mpo_cred_check_label_update_t		*mpo_cred_check_label_update;
[...]
```
Casi todos los hooks serán invocados mediante callbacks por MACF cuando se intercepte una de esas operaciones. Sin embargo, los hooks **`mpo_policy_*`** son una excepción, porque **`mpo_hook_policy_init()`** es un callback invocado durante el registro (es decir, después de **`mac_policy_register()`**) y **`mpo_hook_policy_initbsd()`** se invoca durante el registro tardío, una vez que el subsistema BSD se ha inicializado correctamente.

Además, cualquier kext puede registrar el hook **`mpo_policy_syscall`** para exponer una **interface** privada de llamadas de estilo **ioctl**. Entonces, un cliente de usuario podrá llamar a `mac_syscall` (#381), especificando como parámetros el **nombre de la policy**, un **code** entero y **arguments** opcionales.\
Por ejemplo, **`Sandbox.kext`** utiliza esto con frecuencia.

Es posible examinar **`__DATA.__const*`** del kext para identificar la estructura `mac_policy_ops` utilizada al registrar la policy. Es posible encontrarla porque su puntero se encuentra en un offset dentro de `mpo_policy_conf` y también debido a la cantidad de punteros NULL que habrá en esa área.

Además, también es posible obtener la lista de kexts que han configurado una policy volcando desde la memoria la estructura **`_mac_policy_list`**, que se actualiza con cada policy registrada.

También se puede utilizar la herramienta `xnoop` para volcar todas las policies registradas en el sistema:
```bash
xnoop offline .

Xn👀p> macp
mac_policy_list(@0xfffffff0447159b8): 3 Mac Policies@0xfffffff0447153f0
0: 0xfffffff044886f18:
mpc_name: AppleImage4
mpc_fullName: AppleImage4 hooks
mpc_ops: mac_policy_ops@0xfffffff044886f68
1: 0xfffffff0448d7d40:
mpc_name: AMFI
mpc_fullName: Apple Mobile File Integrity
mpc_ops: mac_policy_ops@0xfffffff0448d72c8
2: 0xfffffff044b0b950:
mpc_name: Sandbox
mpc_fullName: Seatbelt sandbox policy
mpc_ops: mac_policy_ops@0xfffffff044b0b9b0
Xn👀p> dump mac_policy_opns@0xfffffff0448d72c8
Type 'struct mac_policy_opns' is unrecognized - dumping as raw 64 bytes
Dumping 64 bytes from 0xfffffff0448d72c8
```
Y luego vuelca todas las comprobaciones de `check policy` con:
```bash
Xn👀p> dump mac_policy_ops@0xfffffff044b0b9b0
Dumping 2696 bytes from 0xfffffff044b0b9b0 (as struct mac_policy_ops)

mpo_cred_check_label_update_execve(@0x30): 0xfffffff046d7fb54(PACed)
mpo_cred_check_label_update(@0x38): 0xfffffff046d7348c(PACed)
mpo_cred_label_associate(@0x58): 0xfffffff046d733f0(PACed)
mpo_cred_label_destroy(@0x68): 0xfffffff046d733e4(PACed)
mpo_cred_label_update_execve(@0x90): 0xfffffff046d7fb60(PACed)
mpo_cred_label_update(@0x98): 0xfffffff046d73370(PACed)
mpo_file_check_fcntl(@0xe8): 0xfffffff046d73164(PACed)
mpo_file_check_lock(@0x110): 0xfffffff046d7309c(PACed)
mpo_file_check_mmap(@0x120): 0xfffffff046d72fc4(PACed)
mpo_file_check_set(@0x130): 0xfffffff046d72f2c(PACed)
mpo_reserved08(@0x168): 0xfffffff046d72e3c(PACed)
mpo_reserved09(@0x170): 0xfffffff046d72e34(PACed)
mpo_necp_check_open(@0x1f0): 0xfffffff046d72d9c(PACed)
mpo_necp_check_client_action(@0x1f8): 0xfffffff046d72cf8(PACed)
mpo_vnode_notify_setextattr(@0x218): 0xfffffff046d72ca4(PACed)
mpo_vnode_notify_setflags(@0x220): 0xfffffff046d72c84(PACed)
mpo_proc_check_get_task_special_port(@0x250): 0xfffffff046d72b98(PACed)
mpo_proc_check_set_task_special_port(@0x258): 0xfffffff046d72ab4(PACed)
mpo_vnode_notify_unlink(@0x268): 0xfffffff046d72958(PACed)
mpo_vnode_check_copyfile(@0x290): 0xfffffff046d726c0(PACed)
mpo_mount_check_quotactl(@0x298): 0xfffffff046d725c4(PACed)
...
```
## Inicialización de MACF en XNU

### Bootstrap temprano y mac_policy_init()

- MACF se inicializa muy pronto. En `bootstrap_thread` (en el código de inicio de XNU), después de `ipc_bootstrap`, XNU llama a `mac_policy_init()` (en `mac_base.c`).
- `mac_policy_init()` inicializa la `mac_policy_list` global (un array o una lista de policy slots) y configura la infraestructura para MAC (Mandatory Access Control) dentro de XNU.
- Más adelante, se invoca `mac_policy_initmach()`, que gestiona el registro de policies en el lado del kernel para las policies integradas o incluidas.

### `mac_policy_initmach()` y la carga de “security extensions”

- `mac_policy_initmach()` examina las kernel extensions (kexts) precargadas (o incluidas en una lista de “policy injection”) e inspecciona su Info.plist en busca de la clave `AppleSecurityExtension`.
- Las kexts que declaran `<key>AppleSecurityExtension</key>` (o `true`) en su Info.plist se consideran “security extensions”, es decir, aquellas que implementan una MAC policy o se integran con la infraestructura de MACF.
- Algunos ejemplos de kexts de Apple con esa clave son **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre otras (como ya enumeraste).
- El kernel garantiza que esas kexts se carguen pronto y, a continuación, llama a sus rutinas de registro (mediante `mac_policy_register`) durante el arranque, insertándolas en la `mac_policy_list`.

- Cada policy module (kext) proporciona una estructura `mac_policy_conf`, con hooks (`mpc_ops`) para varias operaciones de MAC (comprobaciones de vnode, comprobaciones de exec, actualizaciones de labels, etc.).
- Los flags de tiempo de carga pueden incluir `MPC_LOADTIME_FLAG_NOTLATE`, que significa “debe cargarse pronto” (por lo que se rechazan los intentos de registro tardío).
- Una vez registrado, cada módulo obtiene un handle y ocupa un slot en `mac_policy_list`.
- Cuando se invoca posteriormente un MAC hook (por ejemplo, para el acceso a un vnode, exec, etc.), MACF itera sobre todas las policies registradas para tomar decisiones colectivas.

- En particular, **AMFI** (Apple Mobile File Integrity) es una de estas security extensions. Su Info.plist incluye `AppleSecurityExtension`, lo que la identifica como una security policy.
- Como parte del arranque del kernel, la lógica de carga del kernel garantiza que la “security policy” (AMFI, etc.) ya esté activa antes de que muchos subsistemas dependan de ella. Por ejemplo, el kernel “se prepara para las tareas posteriores cargando … security policy, incluyendo AppleMobileFileIntegrity (AMFI), Sandbox y Quarantine policy”.
```bash
cd /System/Library/Extensions
find . -name Info.plist | xargs grep AppleSecurityExtension 2>/dev/null

./AppleImage4.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./ALF.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./CoreTrust.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleMobileFileIntegrity.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Quarantine.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./Sandbox.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
./AppleSystemPolicy.kext/Contents/Info.plist:	<key>AppleSecurityExtension</key>
```
## Dependencia de KPI y com.apple.kpi.dsep en los kexts de políticas MAC

Al escribir un kext que utiliza el framework MAC (es decir, al llamar a `mac_policy_register()`, etc.), debes declarar dependencias de los KPI (Kernel Programming Interfaces) para que el enlazador de kexts (kxld) pueda resolver esos símbolos. Por lo tanto, para declarar que un `kext` depende de MACF, debes indicarlo en `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); entonces el kext hará referencia a símbolos como `mac_policy_register`, `mac_policy_unregister` y punteros a funciones de hooks de MAC. Para resolverlos, debes incluir `com.apple.kpi.dsep` como dependencia.

Fragmento de ejemplo de `Info.plist` (dentro de tu `.kext`):
```xml
<key>OSBundleLibraries</key>
<dict>
<key>com.apple.kpi.dsep</key>
<string>18.0</string>
<key>com.apple.kpi.libkern</key>
<string>18.0</string>
<key>com.apple.kpi.bsd</key>
<string>18.0</string>
<key>com.apple.kpi.mach</key>
<string>18.0</string>
… (other kpi dependencies as needed)
</dict>
```
## MACF en versiones modernas de macOS

En macOS moderno, las políticas de seguridad de Apple normalmente no se abordan mejor como bundles `.kext` independientes y aislados. Desde **macOS 11**, las extensiones del kernel se vinculan en **kernel collections**; en **Apple Silicon** no existe un **SystemKC** independiente, y los kexts de terceros solo se pueden cargar después de integrarse en el **Auxiliary Kernel Collection (AuxKC)** y reiniciar el sistema. Para la investigación de MACF, esto significa que las políticas integradas, como **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** o **Quarantine**, suelen ser más fáciles de enumerar con `kmutil` que con herramientas obsoletas como `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> En Apple Silicon, si un security kext no está en el BootKC, comprueba después el AuxKC. Esto suele ser más útil que buscar un standalone bundle en `/System/Library/Extensions`.

## Llamadas de MACF

Es habitual encontrar llamadas a MACF definidas en código mediante bloques condicionales como: **`#if CONFIG_MAC`**. Además, dentro de estos bloques es posible encontrar llamadas a `mac_proc_check*`, que llaman a MACF para **comprobar los permisos** necesarios para realizar determinadas acciones. Asimismo, el formato de las llamadas a MACF es: **`mac_<object>_<opType>_opName`**.

El objeto es uno de los siguientes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
El `opType` suele ser check, que se utilizará para permitir o denegar la acción. Sin embargo, también es posible encontrar `notify`, que permitirá al kext reaccionar ante la acción indicada.

Puedes encontrar un ejemplo en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

<pre class="language-c"><code class="lang-c">int
mmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)
{
[...]
#if CONFIG_MACF
<strong>			error = mac_file_check_mmap(vfs_context_ucred(ctx),
</strong>			    fp->fp_glob, prot, flags, file_pos + pageoff,
&maxprot);
if (error) {
(void)vnode_put(vp);
goto bad;
}
#endif /* MAC */
[...]
</code></pre>

Después, es posible encontrar el código de `mac_file_check_mmap` en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)
```c
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
int flags, uint64_t offset, int *maxprot)
{
int error;
int maxp;

maxp = *maxprot;
MAC_CHECK(file_check_mmap, cred, fg, NULL, prot, flags, offset, &maxp);
if ((maxp | *maxprot) != *maxprot) {
panic("file_check_mmap increased max protections");
}
*maxprot = maxp;
return error;
}
```
Que llama a la macro `MAC_CHECK`, cuyo código se puede encontrar en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>.
```c
/*
* MAC_CHECK performs the designated check by walking the policy
* module list and checking with each as to how it feels about the
* request.  Note that it returns its value via 'error' in the scope
* of the caller.
*/
#define MAC_CHECK(check, args...) do {                              \
error = 0;                                                      \
MAC_POLICY_ITERATE({                                            \
if (mpc->mpc_ops->mpo_ ## check != NULL) {              \
DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_CHECK); \
int __step_err = mpc->mpc_ops->mpo_ ## check (args); \
DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_err); \
error = mac_error_select(__step_err, error);         \
}                                                           \
});                                                             \
} while (0)
```
Que recorrerá todas las políticas mac registradas, llamando a sus funciones y almacenando el resultado en la variable `error`, que solo podrá ser sobrescrita por `mac_error_select` mediante códigos de éxito; por lo tanto, si alguna comprobación falla, la comprobación completa fallará y no se permitirá la acción.

> [!TIP]
> Sin embargo, recuerda que no todos los callouts de MACF se utilizan únicamente para denegar acciones. Por ejemplo, `mac_priv_grant` llama a la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá el privilegio solicitado si alguna política responde con un 0:
>
> ```c
> /*
> * MAC_GRANT performs the designated check by walking the policy
> * module list and checking with each as to how it feels about the
> * request.  Unlike MAC_CHECK, it grants if any policies return '0',
> * and otherwise returns EPERM.  Note that it returns its value via
> * 'error' in the scope of the caller.
> */
> #define MAC_GRANT(check, args...) do {                              \
>    error = EPERM;                                                  \
>    MAC_POLICY_ITERATE({                                            \
> 	if (mpc->mpc_ops->mpo_ ## check != NULL) {                  \
> 	        DTRACE_MACF3(mac__call__ ## check, void *, mpc, int, error, int, MAC_ITERATE_GRANT); \
> 	        int __step_res = mpc->mpc_ops->mpo_ ## check (args); \
> 	        if (__step_res == 0) {                              \
> 	                error = 0;                                  \
> 	        }                                                   \
> 	        DTRACE_MACF2(mac__rslt__ ## check, void *, mpc, int, __step_res); \
> 	    }                                                           \
>    });                                                             \
> } while (0)
> ```

### priv_check y priv_grant

Estas llamadas están destinadas a comprobar y proporcionar (decenas de) **privilegios** definidos en [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Parte del código del kernel llamaría a `priv_check_cred()` desde [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con las credenciales de KAuth del proceso y uno de los códigos de privilegio, lo que llamará a `mac_priv_check` para comprobar si alguna política **deniega** la concesión del privilegio; después, llamará a `mac_priv_grant` para comprobar si alguna política concede el `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Este hook permite interceptar todas las llamadas al sistema. En `bsd/dev/[i386|arm]/systemcalls.c` es posible ver la función declarada [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), que contiene este código:
```c
#if CONFIG_MACF
if (__improbable(proc_syscall_filter_mask(proc) != NULL && !bitstr_test(proc_syscall_filter_mask(proc), syscode))) {
error = mac_proc_check_syscall_unix(proc, syscode);
if (error) {
goto skip_syscall;
}
}
#endif /* CONFIG_MACF */
```
Lo que comprobará en el **bitmask** del proceso que realiza la llamada si el syscall actual debe llamar a `mac_proc_check_syscall_unix`. Esto se debe a que los syscalls se llaman con tanta frecuencia que resulta conveniente evitar llamar a `mac_proc_check_syscall_unix` cada vez.

Ten en cuenta que la función `proc_set_syscall_filter_mask()`, que establece los syscalls del bitmask en un proceso, es llamada por Sandbox para establecer máscaras en procesos sandboxed.

## Syscalls MACF expuestos

Es posible interactuar con MACF mediante algunos syscalls definidos en [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
```c
/*
* Extended non-POSIX.1e interfaces that offer additional services
* available from the userland and kernel MAC frameworks.
*/
#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int      __mac_execve(char *fname, char **argv, char **envv, mac_t _label);
int      __mac_get_fd(int _fd, mac_t _label);
int      __mac_get_file(const char *_path, mac_t _label);
int      __mac_get_link(const char *_path, mac_t _label);
int      __mac_get_pid(pid_t _pid, mac_t _label);
int      __mac_get_proc(mac_t _label);
int      __mac_set_fd(int _fildes, const mac_t _label);
int      __mac_set_file(const char *_path, mac_t _label);
int      __mac_set_link(const char *_path, mac_t _label);
int      __mac_mount(const char *type, const char *path, int flags, void *data,
struct mac *label);
int      __mac_get_mount(const char *path, struct mac *label);
int      __mac_set_proc(const mac_t _label);
int      __mac_syscall(const char *_policyname, int _call, void *_arg);
__END_DECLS
#endif /*__APPLE_API_PRIVATE*/
```
Para el reversing ofensivo, **`__mac_syscall`** sigue siendo uno de los mejores chokepoints de userland. Transporta un **nombre de policy** (por ejemplo, `"Sandbox"` o `"AMFI"`), un **selector/código específico de la policy** y un puntero al **opaque argument blob** que será gestionado por `mpo_policy_syscall`. Esto resulta muy útil al hacer reversing de operaciones no documentadas primero desde userland y pivotar después hacia la implementación del kernel. Sandbox suele llegar a él mediante `__sandbox_ms`, y AMFI utiliza el mismo mecanismo para las decisiones de policy de dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Notas prácticas de investigación ofensiva

Los bugs recientes de macOS rara vez "rompen MACF" directamente. En su lugar, normalmente abusan de una **desincronización entre una decisión de MACF / Sandbox / TCC y la acción privilegiada que ocurre después**.

### Comprobaciones de rutas del broker frente a la acción privilegiada real

Un patrón recurrente consiste en que un daemon privilegiado realice una **comprobación previa en userland** (por ejemplo, `sandbox_check_by_audit_token()`) sobre una versión de una ruta y, posteriormente, ejecute el sink privilegiado real con una **ruta controlada por el atacante diferente o no canónica**. Las investigaciones recientes sobre `diskarbitrationd` / `storagekitd` son un buen ejemplo: **directory traversal** más **symlink swaps** permiten al atacante superar la validación de Sandbox del daemon y montar después sobre ubicaciones sensibles como `~/Library/Application Support/com.apple.TCC`, convirtiendo el bug en un **sandbox escape**, una **local privilege escalation** o un **TCC bypass**, dependiendo del mount point elegido.<sup>[[6]](#references)</sup>

Al auditar root brokers accesibles desde el sandbox, busca primero con grep:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalización de rutas
- sinks privilegiados como `mount`, `rename`, `copyfile`, métodos XPC de helper-tools o cualquier elemento que posteriormente toque rutas controladas por el atacante como root

### Trusted deputies con entitlements privados

Otro patrón práctico consiste en evitar atacar directamente los hooks de MACF y, en su lugar, abusar de un **proceso de confianza** que ya posee los derechos necesarios para cruzar el límite. Las investigaciones recientes sobre Safari/TCC son un buen ejemplo: la primitive interesante no consistía en "desactivar TCC en el kernel", sino en modificar la policy/configuración local para que un proceso firmado por Apple con **`com.apple.private.tcc.allow`** realizara la acción sensible en tu nombre.<sup>[[8]](#references)</sup> En la práctica, los objetivos de auditoría de alto valor son daemons/apps de Apple que combinan:

- **private entitlements** o un alcance similar a FDA
- una config / database / mount point / policy file modificable
- una operación sensible posterior mediada por **Sandbox**, **AMFI**, **TCC** u otra policy de MACF

Para profundizar en el reversing específico de cada producto, consulta las páginas dedicadas a [macOS Sandbox](macos-sandbox/README.md) y [macOS TCC](macos-tcc/README.md).

## References

- [1] [XNU — `security/mac_policy.h` (el vector completo de operaciones de policy de MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (códigos de privilegio utilizados por `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [AMFI Syscall (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Descubriendo vulnerabilidades de Apple: auditoría de diskarbitrationd y storagekitd, parte 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — herramienta de referencias cruzadas de XNU](https://newosxbook.com/xxr/index.php)
- [8] [Nueva vulnerabilidad de macOS, "HM Surf", podría permitir el acceso no autorizado a datos (blog de seguridad de Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
{{#include ../../../banners/hacktricks-training.md}}
