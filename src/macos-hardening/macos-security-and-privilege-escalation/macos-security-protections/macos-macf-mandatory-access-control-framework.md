# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**MACF** significa **Mandatory Access Control Framework**, que es un sistema de seguridad integrado en el sistema operativo para ayudar a proteger tu ordenador. Funciona estableciendo **reglas estrictas sobre quién o qué puede acceder a ciertas partes del sistema**, como archivos, aplicaciones y recursos del sistema. Al aplicar estas reglas automáticamente, MACF garantiza que solo usuarios y procesos autorizados puedan realizar acciones específicas, reduciendo el riesgo de acceso no autorizado o actividades maliciosas.

Ten en cuenta que MACF realmente no toma ninguna decisión, ya que solo **intercepta** acciones; deja las decisiones a los **policy modules** (extensiones del kernel) que llama, como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` y `mcxalr.kext`.

- Una policy puede ser enforceing (devolver 0 o distinto de cero en alguna operación)
- Una policy puede estar monitorizando (devolver 0, para no اعتراضar pero aprovechar el hook para hacer algo)
- Una MACF static policy se instala en el arranque y NUNCA se eliminará
- Una MACF dynamic policy es instalada por un KEXT (kextload) y, hipotéticamente, puede ser kextunloaded
- En iOS solo se permiten static policies y en macOS static + dynamic.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flow

1. El proceso realiza un syscall/mach trap
2. La función relevante se llama dentro del kernel
3. La función llama a MACF
4. MACF comprueba los policy modules que solicitaron enganchar esa función en su policy
5. MACF llama a las policy relevantes
6. Las policies indican si permiten o deniegan la acción

> [!CAUTION]
> Apple es la única que puede usar el MAC Framework KPI.

Normalmente, las funciones que comprueban permisos con MACF llamarán a la macro `MAC_CHECK`. Como en el caso del syscall para crear un socket, que llamará a la función `mac_socket_check_create`, la cual llama a `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Además, la macro `MAC_CHECK` está definida en security/mac_internal.h como:
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
Ten en cuenta que al transformar `check` en `socket_check_create` y `args...` en `(cred, domain, type, protocol)` obtienes:
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
Expandir las macros helper muestra el flujo de control concreto:
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
En otras palabras, `MAC_CHECK(socket_check_create, ...)` recorre primero las políticas estáticas, luego bloquea condicionalmente e itera sobre las políticas dinámicas, emite los DTrace probes alrededor de cada hook, y colapsa el código de retorno de cada hook en el único resultado `error` mediante `mac_error_select()`.


### Labels

MACF usa **labels** que luego usarán las políticas que comprueban si deben conceder algún acceso o no. El código de la declaración de la struct de labels puede [encontrarse aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), que luego se usa dentro de **`struct ucred`** [**aquí**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) en la parte **`cr_label`**. El label contiene flags y un número de **slots** que pueden ser usados por **MACF policies to allocate pointers**. Por ejemplo, Sanbox apuntará al container profile

## MACF Policies

Una MACF Policy define **reglas y condiciones para ser aplicadas en ciertas operaciones del kernel**.

Una extensión del kernel podría configurar una struct `mac_policy_conf` y luego registrarla llamando a `mac_policy_register`. Desde [aquí](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
```c
#define mpc_t	struct mac_policy_conf *

/**
@brief Mac policy configuration

This structure specifies the configuration information for a
MAC policy module.  A policy module developer must supply
a short unique policy name, a more descriptive full name, a list of label
namespaces and count, a pointer to the registered enty point operations,
any load time flags, and optionally, a pointer to a label slot identifier.

The Framework will update the runtime flags (mpc_runtime_flags) to
indicate that the module has been registered.

If the label slot identifier (mpc_field_off) is NULL, the Framework
will not provide label storage for the policy.  Otherwise, the
Framework will store the label location (slot) in this field.

The mpc_list field is used by the Framework and should not be
modified by policies.
*/
/* XXX - reorder these for better aligment on 64bit platforms */
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
Es fácil identificar las extensiones del kernel que configuran estas políticas comprobando llamadas a `mac_policy_register`. Además, revisando el disassemble de la extensión también es posible encontrar la struct `mac_policy_conf` utilizada.

Ten en cuenta que las políticas MACF también pueden registrarse y desregistrarse **dinámicamente**.

Uno de los campos principales de `mac_policy_conf` es `mpc_ops`. Este campo especifica en qué opreations está interesada la policy. Ten en cuenta que hay cientos de ellas, por lo que es posible ponerlas todas a cero y luego seleccionar solo las que le interesan a la policy. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Casi todos los hooks serán llamados de vuelta por MACF cuando una de esas operaciones sea interceptada. Sin embargo, los hooks **`mpo_policy_*`** son una excepción porque **`mpo_hook_policy_init()`** es una callback llamada durante el registro (así que después de `mac_policy_register()`) y **`mpo_hook_policy_initbsd()`** se llama durante el registro tardío una vez que el subsistema BSD se ha inicializado correctamente.

Además, el hook **`mpo_policy_syscall`** puede ser registrado por cualquier kext para exponer una **interface** privada de estilo **ioctl**. Entonces, un usuario cliente podrá llamar a `mac_syscall` (#381) especificando como parámetros el **policy name** con un **code** entero y **arguments** opcionales.\
Por ejemplo, **`Sandbox.kext`** usa esto mucho.

Comprobar el **`__DATA.__const*`** del kext permite identificar la estructura `mac_policy_ops` usada al registrar la policy. Es posible encontrarla porque su puntero está en un offset dentro de `mpo_policy_conf` y también por la cantidad de punteros NULL que habrá en esa zona.

Además, también es posible obtener la lista de kexts que han configurado una policy volcándola desde memoria desde la struct **`_mac_policy_list`**, que se actualiza con cada policy que se registra.

También podrías usar la herramienta `xnoop` para volcar todas las policies registradas en el sistema:
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
Y luego volcar todas las comprobaciones de check policy con:
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

### Bootstrap temprano y `mac_policy_init()`

- MACF se inicializa muy pronto. En `bootstrap_thread` (en el código de arranque de XNU), después de `ipc_bootstrap`, XNU llama a `mac_policy_init()` (en `mac_base.c`).
- `mac_policy_init()` inicializa la `mac_policy_list` global (un array o lista de slots de policy) y prepara la infraestructura para MAC (Mandatory Access Control) dentro de XNU.
- Más tarde, se invoca `mac_policy_initmach()`, que gestiona el lado del kernel del registro de policies para policies integradas o empaquetadas.

### `mac_policy_initmach()` y la carga de “security extensions”

- `mac_policy_initmach()` examina las kernel extensions (kexts) que están precargadas (o en una lista de “policy injection”) e inspecciona su Info.plist en busca de la clave `AppleSecurityExtension`.
- Los kexts que declaran `<key>AppleSecurityExtension</key>` (o `true`) en su Info.plist se consideran “security extensions” — es decir, los que implementan una MAC policy o se enganchan en la infraestructura de MACF.
- Ejemplos de kexts de Apple con esa clave incluyen **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre otros (como ya listaste).
- El kernel se asegura de que esos kexts se carguen temprano, y luego llama a sus rutinas de registro (vía `mac_policy_register`) durante el arranque, insertándolos en `mac_policy_list`.

- Cada módulo de policy (kext) proporciona una estructura `mac_policy_conf`, con hooks (`mpc_ops`) para varias operaciones MAC (comprobaciones de vnode, comprobaciones de exec, actualizaciones de label, etc.).
- Los flags de tiempo de carga pueden incluir `MPC_LOADTIME_FLAG_NOTLATE`, que significa “debe cargarse temprano” (por lo que los intentos de registro tardío se rechazan).
- Una vez registrado, cada módulo obtiene un handle y ocupa un slot en `mac_policy_list`.
- Cuando más tarde se invoca un hook de MAC (por ejemplo, acceso a vnode, exec, etc.), MACF itera sobre todas las policies registradas para tomar decisiones colectivas.

- En particular, **AMFI** (Apple Mobile File Integrity) es una de estas security extensions. Su Info.plist incluye `AppleSecurityExtension`, marcándola como una security policy.
- Como parte del arranque del kernel, la lógica de carga del kernel se asegura de que la “security policy” (AMFI, etc.) ya esté activa antes de que muchos subsistemas dependan de ella. Por ejemplo, el kernel “se prepara para las tareas futuras cargando ... security policy, incluyendo AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## KPI dependency & com.apple.kpi.dsep in MAC policy kexts

Cuando escribes un kext que usa el MAC framework (es decir, llamando a `mac_policy_register()` etc.), debes declarar dependencias de KPIs (Kernel Programming Interfaces) para que el kext linker (kxld) pueda resolver esos symbols. ASÍ que, para declarar que un `kext` depende de MACF, necesitas indicarlo en el `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`), entonces el kext hará referencia a symbols como `mac_policy_register`, `mac_policy_unregister`, y MAC hook function pointers. Para resolver esos, debes listar `com.apple.kpi.dsep` como una dependency.

Example Info.plist snippet (inside your .kext):
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
## MACF en las versiones modernas de macOS

En macOS moderno, las políticas de seguridad de Apple normalmente no se abordan mejor como bundles `.kext` independientes y sueltos. Desde **macOS 11**, las extensiones del kernel se enlazan en **kernel collections**; en **Apple Silicon** no hay un **SystemKC** separado, y los kexts de terceros solo se vuelven cargables después de ser compilados dentro de la **Auxiliary Kernel Collection (AuxKC)** y tras un reinicio. Para la investigación de MACF, esto significa que las políticas integradas como **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** o **Quarantine** suelen ser más fáciles de enumerar con `kmutil` que con herramientas obsoletas como `kextstat`.
```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```
> [!TIP]
> En Apple Silicon, si un security kext no está en el BootKC, revisa el AuxKC después. Esto suele ser más útil que buscar un bundle independiente en `/System/Library/Extensions`.

## MACF Callouts

Es común encontrar callouts a MACF definidos en código como: bloques condicionales **`#if CONFIG_MAC`**. Además, dentro de estos bloques es posible encontrar llamadas a `mac_proc_check*` que invocan MACF para **comprobar permisos** para realizar ciertas acciones. Además, el formato de los callouts de MACF es: **`mac_<object>_<opType>_opName`**.

El object es uno de los siguientes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
El `opType` suele ser check, que se usará para permitir o denegar la acción. Sin embargo, también es posible encontrar `notify`, que permitirá que el kext reaccione a la acción dada.

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
Que está llamando a la macro `MAC_CHECK`, cuyo código se puede encontrar en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)
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
Lo que recorrerá todas las políticas MAC registradas llamando a sus funciones y almacenando la salida dentro de la variable error, la cual solo podrá ser sobrescrita por `mac_error_select` con códigos de éxito, así que si cualquier comprobación falla, la comprobación completa fallará y la acción no será permitida.

> [!TIP]
> Sin embargo, recuerda que no todos los callouts de MACF se usan solo para denegar acciones. Por ejemplo, `mac_priv_grant` llama a la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá el privilegio solicitado si cualquier policy responde con un 0:
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
>    }); \
> } while (0)
> ```

### priv_check & priv_grant

Estas llamadas están destinadas a comprobar y proporcionar (docenas de) **privilegios** definidos en [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Algunos códigos del kernel llamarían a `priv_check_cred()` desde [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con las credenciales KAuth del proceso y uno de los códigos de privilegio, lo que llamará a `mac_priv_check` para ver si alguna policy **deniega** conceder el privilegio y luego llama a `mac_priv_grant` para ver si alguna policy concede el `privilege`.

### proc_check_syscall_unix

Este hook permite interceptar todas las system calls. En `bsd/dev/[i386|arm]/systemcalls.c` es posible ver la función declarada [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), que contiene este código:
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
Que comprobará en el proceso que llama la **bitmask** si el syscall actual debería llamar a `mac_proc_check_syscall_unix`. Esto se debe a que los syscalls se llaman con tanta frecuencia que resulta interesante evitar llamar a `mac_proc_check_syscall_unix` cada vez.

Ten en cuenta que la función `proc_set_syscall_filter_mask()`, que establece el bitmask de syscalls en un proceso, es llamada por Sandbox para establecer masks en procesos sandboxed.

## Exposed MACF syscalls

Es posible interactuar con MACF a través de algunos syscalls definidos en [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):
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
Para reversing ofensivo, **`__mac_syscall`** sigue siendo uno de los mejores chokepoints de userland. Lleva un **policy name** (por ejemplo `"Sandbox"` o `"AMFI"`), un **selector/code** específico de la policy, y un puntero al **opaque argument blob** que será manejado por `mpo_policy_syscall`. Esto es muy útil cuando haces reversing de operaciones no documentadas desde userland primero y solo después pivotas a la implementación del kernel. Sandbox normalmente llega ahí vía `__sandbox_ms`, y AMFI usa el mismo mecanismo para decisiones de policy de dyld.

## Practical offensive research notes

Los bugs recientes de macOS rara vez "rompen MACF" directamente. En su lugar, suelen abusar de una **desincronización entre una decisión de MACF / Sandbox / TCC y la acción privilegiada que ocurre después**.

### Broker path checks vs real privileged action

Un patrón recurrente es un daemon privilegiado haciendo un **userland pre-check** (por ejemplo `sandbox_check_by_audit_token()`) sobre una versión de un path, y después ejecutando el verdadero sink privilegiado con un **path diferente o no canónico controlado por el atacante**. La investigación reciente de `diskarbitrationd` / `storagekitd` es un buen ejemplo: **directory traversal** más **symlink swaps** permiten al atacante pasar la validación de sandbox del daemon y luego montar sobre ubicaciones sensibles como `~/Library/Application Support/com.apple.TCC`, convirtiendo el bug en un **sandbox escape**, **local privilege escalation** o **TCC bypass** dependiendo del punto de montaje elegido.

Al auditar root brokers accesibles desde el sandbox, busca primero:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalización de paths
- sinks privilegiados como `mount`, `rename`, `copyfile`, métodos XPC de helper tools, o cualquier cosa que luego toque paths controlados por el atacante como root

### Trusted deputies with private entitlements

Otro patrón práctico es evitar atacar directamente los hooks de MACF y, en su lugar, abusar de un **trusted process** que ya tiene los derechos necesarios para cruzar la frontera. La investigación reciente de Safari/TCC es un buen ejemplo: la primitive interesante no era "desactivar TCC en el kernel", sino modificar la policy/configuración local para que un proceso firmado por Apple con **`com.apple.private.tcc.allow`** realice la acción sensible en tu nombre. En la práctica, los targets de auditoría de alto valor son daemons/apps de Apple que combinan:

- **private entitlements** o alcance tipo FDA
- un config / database / mount point / policy file writable
- una operación sensible posterior mediada por **Sandbox**, **AMFI**, **TCC** u otra policy de MACF

Para un reversing más profundo específico de producto, revisa las páginas dedicadas sobre [macOS Sandbox](macos-sandbox/README.md) y [macOS TCC](macos-tcc/README.md).

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [**AMFI Syscall (Offensive Security)**](https://www.offsec.com/blog/amfi-syscall/)
- [**Uncovering Apple Vulnerabilities: diskarbitrationd and storagekitd Audit Part 2**](https://blog.kandji.io/macos-audit-story-part2)


{{#include ../../../banners/hacktricks-training.md}}
