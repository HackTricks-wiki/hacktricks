# macOS MACF

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

**MACF** significa **Mandatory Access Control Framework** (framework de control de acceso obligatorio), un sistema de seguridad integrado en el sistema operativo que ayuda a proteger tu computadora. Funciona estableciendo **reglas estrictas sobre quién o qué puede acceder a ciertas partes del sistema**, como archivos, aplicaciones y recursos del sistema. Al aplicar estas reglas automáticamente, MACF garantiza que solo los usuarios y procesos autorizados puedan realizar acciones específicas, lo que reduce el riesgo de acceso no autorizado o actividades maliciosas.

Ten en cuenta que MACF en realidad no toma decisiones; solo **intercepta** acciones y delega las decisiones en los **policy modules** (extensiones del kernel) que invoca, como `AppleMobileFileIntegrity.kext`, `Quarantine.kext`, `Sandbox.kext`, `TMSafetyNet.kext` y `mcxalr.kext`.

- Una policy puede aplicar restricciones (devolver un valor distinto de 0 en algunas operaciones)
- Una policy puede monitorizar (devolver 0 para no oponerse, pero aprovechar el hook para hacer algo)
- Una policy estática de MACF se instala durante el arranque y NUNCA se eliminará
- Una policy dinámica de MACF se instala mediante un KEXT (`kextload`) y, en teoría, se puede descargar con `kextunload`
- En iOS solo se permiten policies estáticas, mientras que en macOS se permiten policies estáticas y dinámicas.<sup>[[7]](#references)</sup>

### Flujo

1. Un proceso realiza una syscall o un mach trap
2. Se llama a la función correspondiente dentro del kernel
3. La función llama a MACF
4. MACF comprueba qué policy modules solicitaron engancharse a esa función en su policy
5. MACF llama a las policies correspondientes
6. Las policies indican si permiten o deniegan la acción

> [!CAUTION]
> Solo Apple puede usar el MAC Framework KPI.

Por lo general, las funciones que comprueban permisos con MACF llaman a la macro `MAC_CHECK`. Por ejemplo, en el caso de una syscall para crear un socket, se llama a la función `mac_socket_check_create`, que a su vez llama a `MAC_CHECK(socket_check_create, cred, domain, type, protocol);`. Además, la macro `MAC_CHECK` se define en security/mac_internal.h como:<sup>[[3]](#references)</sup>
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

En otras palabras, `MAC_CHECK(socket_check_create, ...)` recorre primero las políticas estáticas, bloquea e itera condicionalmente sobre las políticas dinámicas, emite las sondas de DTrace alrededor de cada hook y combina el código de retorno de cada hook en un único resultado `error` mediante `mac_error_select()`.


### Etiquetas

MACF usa **etiquetas** que luego utilizan las políticas para comprobar si deben conceder o no cierto acceso. El código de la declaración de la estructura de etiquetas se puede [encontrar aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/_label.h), que luego se utiliza dentro de **`struct ucred`** [aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ucred.h#L86), en la parte **`cr_label`**. La etiqueta contiene flags y un número de **slots** que las **políticas de MACF pueden usar para asignar punteros**. Por ejemplo, Sandbox apuntará al perfil del contenedor.

## Políticas de MACF

Una política de MACF define **reglas y condiciones que se aplicarán en determinadas operaciones del kernel**.

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

Es fácil identificar las extensiones del kernel que configuran estas políticas buscando llamadas a `mac_policy_register`. Además, al revisar el desensamblado de la extensión, también es posible encontrar la estructura `mac_policy_conf` utilizada.

Ten en cuenta que las políticas de MACF también se pueden registrar y cancelar su registro de forma **dinámica**.

Uno de los campos principales de `mac_policy_conf` es **`mpc_ops`**. Este campo especifica qué operaciones le interesan a la política. Hay cientos, por lo que es posible poner todas las entradas a cero y luego seleccionar solo las que necesita la política. De [aquí](https://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h.auto.html):<sup>[[1]](#references)</sup>

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

Casi todos los hooks reciben una llamada de retorno de MACF cuando se intercepta una de esas operaciones. Sin embargo, los hooks **`mpo_policy_*`** son una excepción, porque `mpo_hook_policy_init()` es un callback que se ejecuta al registrar la política (es decir, después de `mac_policy_register()`), y `mpo_hook_policy_initbsd()` se ejecuta durante el registro tardío, una vez que el subsistema BSD se ha inicializado correctamente.

Además, cualquier kext puede registrar el hook **`mpo_policy_syscall`** para exponer una **interfaz** de llamadas privadas de tipo **ioctl**. Entonces, un user client podrá llamar a `mac_syscall` (#381), especificando como parámetros el **nombre de la política**, un **código** entero y **argumentos** opcionales.\
Por ejemplo, `Sandbox.kext` lo utiliza mucho.

Es posible identificar la estructura `mac_policy_ops` que se usa al registrar la política examinando el **`__DATA.__const*`** del kext. Se puede encontrar porque su puntero está en un offset dentro de `mpo_policy_conf` y también por la cantidad de punteros NULL que habrá en esa zona.

Además, también es posible obtener la lista de kexts que han configurado una política volcando de la memoria la estructura **`_mac_policy_list`**, que se actualiza con cada política registrada.

También puedes usar la herramienta `xnoop` para volcar todas las políticas registradas en el sistema:

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

### Arranque temprano y mac_policy_init()

- MACF se inicializa muy pronto. En `bootstrap_thread` (en el código de inicio de XNU), después de `ipc_bootstrap`, XNU llama a `mac_policy_init()` (en `mac_base.c`).  
- `mac_policy_init()` inicializa la lista global `mac_policy_list` (una matriz o lista de espacios para políticas) y configura la infraestructura de MAC (Mandatory Access Control) en XNU.  
- Más adelante, se invoca `mac_policy_initmach()`, que gestiona el registro de políticas integradas o incluidas en el kernel.

### `mac_policy_initmach()` y la carga de «extensiones de seguridad»

- `mac_policy_initmach()` examina las extensiones del kernel (kexts) precargadas (o incluidas en una lista de «inyección de políticas») e inspecciona su Info.plist para buscar la clave `AppleSecurityExtension`.  
- Las kexts que declaran `<key>AppleSecurityExtension</key>` (o `true`) en su Info.plist se consideran «extensiones de seguridad», es decir, aquellas que implementan una política MAC o se integran en la infraestructura de MACF.  
- Algunos ejemplos de kexts de Apple que incluyen esa clave son **ALF.kext**, **AppleMobileFileIntegrity.kext (AMFI)**, **Sandbox.kext**, **Quarantine.kext**, **TMSafetyNet.kext**, **CoreTrust.kext**, **AppleSystemPolicy.kext**, entre otras (como ya se indicó).  
- El kernel se asegura de que esas kexts se carguen pronto y, durante el arranque, llama a sus rutinas de registro (mediante `mac_policy_register`), que las insertan en `mac_policy_list`.

  - Cada módulo de políticas (kext) proporciona una estructura `mac_policy_conf`, con hooks (`mpc_ops`) para distintas operaciones MAC (comprobaciones de vnode, comprobaciones de ejecución, actualizaciones de etiquetas, etc.).  
  - Las flags de tiempo de carga pueden incluir `MPC_LOADTIME_FLAG_NOTLATE`, que significa «debe cargarse pronto» (por lo que se rechazan los intentos de registro tardío).  
  - Una vez registrado, cada módulo recibe un identificador y ocupa un espacio en `mac_policy_list`.  
  - Cuando se invoca un hook de MAC más adelante (por ejemplo, para el acceso a vnode, la ejecución, etc.), MACF recorre todas las políticas registradas para tomar decisiones colectivas.

- En particular, **AMFI** (Apple Mobile File Integrity) es una de estas extensiones de seguridad. Su Info.plist incluye `AppleSecurityExtension`, que la identifica como una política de seguridad. 
- Como parte del arranque del kernel, la lógica de carga del kernel se asegura de que la «política de seguridad» (AMFI, etc.) ya esté activa antes de que muchos subsistemas dependan de ella. Por ejemplo, el kernel «se prepara para las tareas que tiene por delante cargando… la política de seguridad, que incluye AppleMobileFileIntegrity (AMFI), Sandbox y la política de Quarantine». 

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

Al escribir un kext que usa el framework MAC (es decir, que llama a `mac_policy_register()`, etc.), debes declarar dependencias de KPI (Kernel Programming Interfaces) para que el enlazador de kexts (kxld) pueda resolver esos símbolos. Por lo tanto, para declarar que un `kext` depende de MACF, debes indicarlo en `Info.plist` con `com.apple.kpi.dsep` (`find . Info.plist | grep AppleSecurityExtension`). Luego, el kext hará referencia a símbolos como `mac_policy_register`, `mac_policy_unregister` y los punteros a funciones hook de MAC. Para resolverlos, debes incluir `com.apple.kpi.dsep` como dependencia.

Fragmento de ejemplo de Info.plist (dentro de tu .kext):

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

En las versiones modernas de macOS, las políticas de seguridad de Apple no suelen abordarse mejor como bundles `.kext` independientes. Desde **macOS 11**, las extensiones del kernel se enlazan en **kernel collections**; en **Apple Silicon** no existe un **SystemKC** independiente, y los kexts de terceros solo se pueden cargar después de integrarse en la **Auxiliary Kernel Collection (AuxKC)** y reiniciar el equipo. Para la investigación de MACF, esto significa que las políticas integradas, como **Sandbox**, **AMFI**, **AppleSystemPolicy**, **CoreTrust** o **Quarantine**, suelen ser más fáciles de enumerar con `kmutil` que con herramientas obsoletas como `kextstat`.

```bash
# Loaded policies from the running kernel
kmutil showloaded --collection boot | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
kmutil showloaded --collection aux  | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'

# Policies present in the on-disk BootKC
kmutil inspect --show-fileset-entries   -B /System/Library/KernelCollections/BootKernelExtensions.kc   | egrep 'Sandbox|AppleMobileFileIntegrity|AppleSystemPolicy|CoreTrust|Quarantine'
```

> [!TIP]
> En Apple Silicon, si un kext de seguridad no está en BootKC, comprueba AuxKC a continuación. Esto suele ser más útil que buscar un bundle independiente en `/System/Library/Extensions`.

## Callouts de MACF

Es habitual encontrar callouts a MACF definidos en bloques condicionales como **`#if CONFIG_MAC`**. Además, dentro de estos bloques es posible encontrar llamadas a `mac_proc_check*`, que invocan MACF para **comprobar los permisos** necesarios para realizar determinadas acciones. Además, el formato de los callouts de MACF es: **`mac_<object>_<opType>_opName`**.

El objeto es uno de los siguientes: `bpfdesc`, `cred`, `file`, `proc`, `vnode`, `mount`, `devfs`, `ifnet`, `inpcb`, `mbuf`, `ipq`, `pipe`, `sysv[msg/msq/shm/sem]`, `posix[shm/sem]`, `socket`, `kext`.\
El `opType` suele ser `check`, que se utiliza para permitir o denegar la acción. Sin embargo, también es posible encontrar `notify`, que permite al kext reaccionar a la acción indicada.

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

Después, puedes encontrar el código de `mac_file_check_mmap` en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_file.c#L174)

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

Que llama a la macro `MAC_CHECK`, cuyo código se puede encontrar en [https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L261)<sup>[[3]](#references)</sup>

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

Esto recorre las políticas registradas y combina sus resultados con `mac_error_select()`. Un valor de retorno cero de una comprobación posterior no puede anular una denegación anterior; si varias políticas deniegan la acción, la función elige el error según su prioridad (por ejemplo, `EACCES` antes que `EPERM`).<sup>[[2]](#references)</sup>

> [!TIP]
> Sin embargo, recuerda que no todas las llamadas de MACF se usan solo para denegar acciones. Por ejemplo, `mac_priv_grant` llama a la macro [**MAC_GRANT**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac_internal.h#L274), que concederá el privilegio solicitado si alguna política responde con un 0:
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

Estas llamadas están pensadas para comprobar y conceder (decenas de) **privilegios** definidos en [**bsd/sys/priv.h**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/priv.h).\
Parte del código del kernel llamaría a `priv_check_cred()` desde [**bsd/kern/kern_priv.c**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_priv.c) con las credenciales KAuth del proceso y uno de los códigos de privilegio, lo que llamará a `mac_priv_check` para comprobar si alguna política **deniega** la concesión del privilegio. Después, llamará a `mac_priv_grant` para comprobar si alguna política concede el `privilege`.<sup>[[4]](#references)</sup>

### proc_check_syscall_unix

Este hook permite interceptar todas las llamadas al sistema. En `bsd/dev/[i386|arm]/systemcalls.c` se puede ver la función declarada [`unix_syscall`](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/dev/arm/systemcalls.c#L160C1-L167C25), que contiene este código:

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

Lo cual comprobará la **máscara de bits** del proceso llamante para determinar si la llamada al sistema actual debe llamar a `mac_proc_check_syscall_unix`. Esto se debe a que las llamadas al sistema se ejecutan con tanta frecuencia que conviene evitar llamar a `mac_proc_check_syscall_unix` cada vez.

Ten en cuenta que la función `proc_set_syscall_filter_mask()`, que establece la máscara de bits de las llamadas al sistema en un proceso, es llamada por Sandbox para establecer máscaras en los procesos en sandbox.

## Llamadas al sistema MACF expuestas

Es posible interactuar con MACF mediante algunas llamadas al sistema definidas en [security/mac.h](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/security/mac.h#L151):

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

Para el reversing ofensivo, **`__mac_syscall`** sigue siendo uno de los mejores puntos de interceptación en userland. Transporta un **nombre de policy** (por ejemplo, `"Sandbox"` o `"AMFI"`), un **selector/código específico de la policy** y un puntero al **bloque opaco de argumentos** que manejará `mpo_policy_syscall`. Esto resulta muy útil para analizar operaciones no documentadas primero desde userland y solo después pasar a la implementación en el kernel. Sandbox suele llegar a esta función mediante `__sandbox_ms`, y AMFI usa el mismo mecanismo para las decisiones de policy de dyld.<sup>[[2]](#references)[[5]](#references)</sup>

## Notas prácticas de investigación ofensiva

Los bugs recientes de macOS rara vez «rompen MACF» directamente. En su lugar, suelen aprovechar una **desincronización entre una decisión de MACF / Sandbox / TCC y la acción privilegiada que se produce después**.

### Atributos de spawn específicos de una policy como entrada de MACF

`posix_spawnattr_setmacpolicyinfo_np()` adjunta un nombre de policy y bytes opacos a una solicitud `posix_spawn()`. XNU busca esos bytes usando el `mpc_name` de cada policy registrada y se los pasa al hook de etiqueta exec de esa policy; el hook de launch constraints también lee los bytes correspondientes. Esta es una ruta de entrada a MACF controlada por el atacante, independiente de `__mac_syscall`. Audita si la policy trata esos bytes como una *restricción adicional* o permite que sustituyan la policy existente del padre o del ejecutable.<sup>[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Para una prueba controlada, empieza con un proceso padre restringido y ejecuta el mismo proceso hijo **sin** y **con** un atributo específico de policy. Compara el acceso efectivo del hijo a un recurso que el padre no puede usar; que el spawn tenga éxito no demuestra por sí solo que se haya cruzado un límite.<sup>[[12]](#references)[[13]](#references)</sup>

Al analizar la policy, sigue `mpo_cred_label_update_execve` y `mpo_proc_check_launch_constraints`, y luego comprueba si quien realiza la llamada puede proporcionar el atributo.<sup>[[10]](#references)[[11]](#references)</sup> Históricamente, AMFI aceptaba launch constraints proporcionadas por el usuario en lugar de las integradas; Sandbox podía aplicar un perfil integrado con nombre al proceso hijo en vez de conservar las restricciones del padre.<sup>[[13]](#references)[[12]](#references)</sup> Ambos comportamientos se corrigieron, así que no des por hecho que ninguno está presente en los sistemas actuales.<sup>[[13]](#references)[[12]](#references)</sup>

Consulta el [análisis de launch constraints](macos-launch-environment-constraints.md) para el caso de AMFI y [depuración de Sandbox](macos-sandbox/macos-sandbox-debug-and-bypass/) para probar la policy efectiva del proceso hijo.

### Comprobaciones de rutas del broker frente a la acción privilegiada real

Un patrón recurrente es que un daemon privilegiado haga una **comprobación previa en userland** (por ejemplo, `sandbox_check_by_audit_token()`) sobre una versión de una ruta y después ejecute la operación privilegiada real con una **ruta distinta o no canónica controlada por el atacante**. La investigación reciente de `diskarbitrationd` / `storagekitd` es un buen ejemplo: la **traversal de directorios** junto con **intercambios de symlinks** permite al atacante superar la validación de Sandbox del daemon y luego montar sobre ubicaciones sensibles como `~/Library/Application Support/com.apple.TCC`, convirtiendo el bug en un **escape de Sandbox**, una **escalada local de privilegios** o un **bypass de TCC**, según el punto de montaje elegido.<sup>[[6]](#references)</sup>

Al auditar brokers con privilegios de root accesibles desde Sandbox, busca primero:

- `sandbox_check`, `sandbox_check_by_audit_token`
- `realpath`, `CFURL*`, helpers de canonicalización de rutas
- operaciones privilegiadas, como `mount`, `rename`, `copyfile`, métodos XPC de helper tools o cualquier operación que posteriormente acceda como root a rutas controladas por el atacante

### Intermediarios de confianza con entitlements privados

Otro patrón práctico consiste en evitar atacar directamente los hooks de MACF y, en su lugar, abusar de un **proceso de confianza** que ya tiene los derechos necesarios para cruzar el límite. La investigación reciente sobre Safari/TCC es un buen ejemplo: la primitiva interesante no consistía en «desactivar TCC en el kernel», sino en modificar la policy/configuración local para que un proceso firmado por Apple con **`com.apple.private.tcc.allow`** realizara la acción sensible en tu nombre.<sup>[[8]](#references)</sup> En la práctica, los objetivos de auditoría de alto valor son los daemons/apps de Apple que combinan:

- **entitlements privados** o un alcance similar a FDA
- una configuración / base de datos / punto de montaje / archivo de policy modificable
- una operación sensible posterior mediada por **Sandbox**, **AMFI**, **TCC** u otra policy de MACF

Para profundizar en el reversing específico de cada producto, consulta las páginas dedicadas a [macOS Sandbox](macos-sandbox/README.md) y [macOS TCC](macos-tcc/README.md).



## References

- [1] [XNU — `security/mac_policy.h` (el vector completo de operaciones de policy de MACF)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`mac_policy_register`, `__mac_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [XNU — `security/mac_internal.h` (macros `MAC_CHECK` / `MAC_GRANT` / `MAC_POLICY_ITERATE`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_internal.h)
- [4] [XNU — `bsd/sys/priv.h` (códigos de privilegio usados por `priv_check`/`priv_grant`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/priv.h)
- [5] [Llamada al sistema de AMFI (Offensive Security)](https://www.offsec.com/blog/amfi-syscall/)
- [6] [Descubriendo vulnerabilidades de Apple: auditoría de diskarbitrationd y storagekitd, parte 2](https://blog.kandji.io/macos-audit-story-part2)
- [7] [XXR — herramienta de referencias cruzadas de XNU](https://newosxbook.com/xxr/index.php)
- [8] [Nueva vulnerabilidad de macOS, «HM Surf», podría permitir el acceso no autorizado a datos (blog de seguridad de Microsoft)](https://www.microsoft.com/en-us/security/blog/2024/10/17/new-macos-vulnerability-hm-surf-could-lead-to-unauthorized-data-access/)
- [9] [XNU — setter del atributo de policy de posix_spawn](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/spawn/posix_spawn.c)
- [10] [XNU — despacho del atributo de etiqueta exec específico de policy](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_vfs.c)
- [11] [XNU — despacho de policy de launch constraints](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_process.c)
- [12] [Escapar del Sandbox de Apple ejecutando un ejecutable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [13] [Eludir launch constraints en macOS](https://wts.dev/posts/bypassing-launch-constraints/)
{{#include ../../../banners/hacktricks-training.md}}
