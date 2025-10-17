# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**MACF** significa **Mandatory Access Control Framework**, que es un sistema de seguridad integrado en el sistema operativo para ayudar a proteger tu equipo. Funciona estableciendo **reglas estrictas sobre quién o qué puede acceder a ciertas partes del sistema**, como archivos, aplicaciones y recursos del sistema. Al aplicar estas reglas automáticamente, MACF asegura que solo usuarios y procesos autorizados puedan realizar acciones específicas, reduciendo el riesgo de accesos no autorizados o actividades maliciosas.

Ten en cuenta que MACF en realidad no toma decisiones, solo **intercepta** acciones; deja las decisiones a los **módulos de política** (extensiones del kernel) que llama como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` y `mcxalr.kext`.

- Una política puede estar en modo enforcing (retornar 0 o un valor no-cero en alguna operación)
- Una política puede estar en modo monitoring (retornar 0, para no objetar pero aprovechar el hook para hacer algo)
- Una política MACF estática se instala en el arranque y NUNCA será eliminada
- Una política MACF dinámica se instala por una KEXT (kextload) y hipotéticamente podría ser kextunloaded
- En iOS solo se permiten políticas estáticas y en macOS estáticas + dinámicas.
- [https://newosxbook.com/xxr/index.php](https://newosxbook.com/xxr/index.php)


### Flujo

1. El proceso ejecuta un syscall/mach trap
2. La función relevante es llamada dentro del kernel
3. La función llama a MACF
4. MACF verifica los módulos de política que solicitaron hookear esa función en su política
5. MACF llama a las políticas relevantes
6. Las políticas indican si permiten o deniegan la acción

> [!CAUTION]
> Apple es la única que puede usar el MAC Framework KPI.

Por lo general, las funciones que comprueban permisos con MACF invocan la macro `MAC_CHECK`. Por ejemplo, la syscall para crear un socket llamará a la función `mac_socket_check_create`, la cual invoca `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Además, la macro `MAC_CHECK` está definida en security/mac_internal.h como:
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
Nota que al transformar `check` en `socket_check_create` y `args...` en `(cred, domain, type, protocol)` obtienes:
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
Al expandir las macros auxiliares se muestra el flujo de control concreto:
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
En otras palabras, `MAC_CHECK(socket_check_create, ...)` recorre primero las políticas estáticas, bloquea condicionalmente e itera sobre las políticas dinámicas, emite las DTrace probes alrededor de cada hook, y colapsa el código de retorno de cada hook en el único resultado `error` mediante `mac_error_select()`.


### Etiquetas

MACF usa **etiquetas** que las políticas utilizan luego para decidir si deben conceder o no algún acceso. El código de la declaración del struct de etiquetas se puede [found here](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), que luego se usa dentro de **`struct ucred`** en [**here**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86) en la parte **`cr_label`**. La etiqueta contiene flags y un número de **slots** que pueden ser usados por **MACF policies to allocate pointers**. Por ejemplo Sandbox apuntará al container profile

## Políticas MACF

Una MACF Policy define **reglas y condiciones que se aplican en ciertas operaciones del kernel**.

Una extensión del kernel podría configurar una estructura `mac_policy_conf` y luego registrarla llamando a `mac_policy_register`. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Es fácil identificar las kernel extensions que configuran estas políticas comprobando las llamadas a `mac_policy_register`. Además, al inspeccionar el desensamblado de la extensión también es posible encontrar la estructura `mac_policy_conf` utilizada.

Ten en cuenta que las políticas MACF pueden registrarse y anularse también de forma **dinámica**.

Uno de los campos principales de la `mac_policy_conf` es **`mpc_ops`**. Este campo especifica en qué operaciones está interesada la política. Ten en cuenta que hay cientos de ellas, por lo que es posible ponerlas todas a cero y luego seleccionar solo las que interesan a la política. From [here](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):
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
Casi todos los hooks serán invocados por MACF cuando una de esas operaciones sea interceptada. Sin embargo, los hooks **`mpo_policy_*`** son una excepción porque `mpo_hook_policy_init()` es un callback llamado al registrarse (es decir, después de `mac_policy_register()`) y `mpo_hook_policy_initbsd()` se llama durante el registro tardío una vez que el subsistema BSD se haya inicializado correctamente.

Además, el hook **`mpo_policy_syscall`** puede ser registrado por cualquier kext para exponer una **interfaz** de llamada de tipo **ioctl** privada. Entonces, un user client podrá llamar a `mac_syscall` (#381) especificando como parámetros el **policy name** con un entero **code** y **arguments** opcionales.\
Por ejemplo, **`Sandbox.kext`** usa esto mucho.

Comprobando la sección del kext **`__DATA.__const*`** es posible identificar la estructura `mac_policy_ops` usada al registrar la policy. Se puede encontrar porque su puntero está en un offset dentro de `mpo_policy_conf` y también por la cantidad de punteros NULL que habrá en esa zona.

Además, también es posible obtener la lista de kexts que han configurado una policy volcando desde memoria la struct **`_mac_policy_list`**, que se actualiza con cada policy que se registra.

También puedes usar la herramienta `xnoop` para volcar todas las policies registradas en el sistema:
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
Y luego vuelca todas las comprobaciones de check policy con:
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

- MACF se inicializa muy pronto. En `bootstrap_thread` (en el código de arranque de XNU), después de `ipc_bootstrap`, XNU llama a `mac_policy_init()` (en `mac_base.c`).
- `mac_policy_init()` inicializa la `mac_policy_list` global (un array o lista de ranuras de políticas) y configura la infraestructura para MAC (Mandatory Access Control) dentro de XNU.
- Más adelante se invoca `mac_policy_initmach()`, que maneja el lado del kernel del registro de políticas para políticas integradas o empaquetadas.

### `mac_policy_initmach()` y carga de “extensiones de seguridad”

- `mac_policy_initmach()` examina los kernel extensions (kexts) que están precargados (o en una lista de “policy injection”) e inspecciona su Info.plist buscando la clave `AppleSecurityExtension`.
- Los kexts que declaran `<key>AppleSecurityExtension</key>` (o `true`) en su Info.plist se consideran “security extensions” — es decir, aquellos que implementan una MAC policy o se enganchan en la infraestructura MACF.
- Ejemplos de kexts de Apple con esa clave incluyen **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre otros (como ya listaste).
- El kernel asegura que esos kexts se carguen temprano, luego llama a sus rutinas de registro (vía `mac_policy_register`) durante el boot, insertándolos en la `mac_policy_list`.

- Cada módulo de política (kext) provee una estructura `mac_policy_conf`, con hooks (`mpc_ops`) para varias operaciones MAC (chequeos de vnode, chequeos de exec, actualizaciones de etiquetas, etc.).
- Las flags de carga pueden incluir `MPC_LOADTIME_FLAG_NOTLATE`, lo que significa “debe cargarse temprano” (por lo que los intentos de registro tardío son rechazados).
- Una vez registrados, cada módulo obtiene un handle y ocupa una ranura en `mac_policy_list`.
- Cuando más adelante se invoca un hook MAC (por ejemplo, acceso a vnode, exec, etc.), MACF itera sobre todas las políticas registradas para tomar decisiones colectivas.

- En particular, **AMFI** (Apple Mobile File Integrity) es una de esas extensiones de seguridad. Su Info.plist incluye `AppleSecurityExtension` marcándola como una política de seguridad.
- Como parte del boot del kernel, la lógica de carga del kernel asegura que la “security policy” (AMFI, etc.) ya esté activa antes de que muchos subsistemas dependan de ella. Por ejemplo, el kernel “se prepara para tareas posteriores cargando … security policy, incluyendo AppleMobileFileIntegrity (AMFI), Sandbox, Quarantine policy.”
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
## Dependencia de KPI y com.apple.kpi.dsep en kexts de políticas MAC

Al escribir un `kext` que usa el framework MAC (p. ej. llamando a `mac_policy_register()` etc.), debes declarar dependencias en los KPIs (Interfaces de Programación del Kernel) para que el linker de kext (kxld) pueda resolver esos símbolos. Por lo tanto, para declarar que un `kext` depende de MACF necesitas indicarlo en el `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`); entonces el kext hará referencia a símbolos como `mac_policy_register`, `mac_policy_unregister` y punteros a funciones hook de MAC. Para resolverlos, debes listar `com.apple.kpi.dsep` como dependencia.

Ejemplo de fragmento de Info.plist (dentro de tu .kext):
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
## Invocaciones a MACF

Es común encontrar invocaciones a MACF definidas en código como: **`#if CONFIG_MAC`** bloques condicionales. Además, dentro de estos bloques es posible encontrar llamadas a `mac_proc_check*` que llaman a MACF para **comprobar permisos** para realizar ciertas acciones. Además, el formato de las invocaciones MACF es: **`mac_<object>_<opType>_opName`**.

El objeto es uno de los siguientes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
El `opType` suele ser check, que se utiliza para permitir o denegar la acción. Sin embargo, también es posible encontrar `notify`, que permitirá al kext reaccionar ante la acción dada.

You can find an example in [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_mman.c#L621):

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
Que llama a la macro `MAC_CHECK`, cuyo código se puede encontrar en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261).
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
Esto recorrerá todas las políticas MAC registradas llamando a sus funciones y almacenando la salida en la variable error, la cual solo podrá ser sobrescrita por `mac_error_select` mediante códigos de éxito; por tanto, si alguna comprobación falla, la comprobación completa fallará y la acción no será permitida.

> [!TIP]
> Sin embargo, recuerda que no todos los callouts de MACF se usan únicamente para denegar acciones. Por ejemplo, `mac_priv_grant` llama a la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá el privilegio solicitado si alguna política responde con un 0:
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

### priv_check & priv_grant

Estas llamadas están destinadas a comprobar y proporcionar (docenas de) **privilegios** definidos en [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Parte del código del kernel llamaría a `priv_check_cred()` desde [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con las credenciales KAuth del proceso y uno de los códigos de privilegio, lo que llamará a `mac_priv_check` para ver si alguna política **niega** conceder el privilegio y luego llama a `mac_priv_grant` para ver si alguna política otorga el `privilege`.

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
Que comprobará en el **bitmask** del proceso llamador si el syscall actual debe llamar a `mac_proc_check_syscall_unix`. Esto se debe a que los syscalls se invocan con tanta frecuencia que resulta interesante evitar llamar a `mac_proc_check_syscall_unix` en cada ocasión.

Nótese que la función `proc_set_syscall_filter_mask()`, que establece el bitmask de syscalls en un proceso, es llamada por Sandbox para establecer máscaras en procesos sandboxed.

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
## Referencias

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)


{{#include ../../../banners/hacktricks-training.md}}
