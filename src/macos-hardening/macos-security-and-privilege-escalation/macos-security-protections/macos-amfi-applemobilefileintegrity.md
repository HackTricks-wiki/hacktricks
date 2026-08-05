# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext y amfid

Se centra en hacer cumplir la integridad del código que se ejecuta en el sistema, proporcionando la lógica detrás de la verificación de firmas de código de XNU. También puede comprobar entitlements y gestionar otras tareas sensibles, como permitir la depuración u obtener task ports.

Además, para algunas operaciones, el kext prefiere ponerse en contacto con el daemon ejecutándose en user space `/usr/libexec/amfid`. Esta relación de confianza ha sido abusada en varios jailbreaks.

En versiones recientes de macOS, AMFI ya no se expone convenientemente como un kext independiente en disco, por lo que hacer reversing normalmente implica trabajar desde el **kernelcache** o un **KDK**, en lugar de explorar `/System/Library/Extensions`.

AMFI utiliza políticas **MACF** y registra sus hooks en el momento en que se inicia. Además, impedir su carga o descargarlo podría provocar un kernel panic. Sin embargo, existen algunos boot arguments que permiten debilitar AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid se autorice sin los entitlements requeridos
- `amfi_allow_any_signature`: Permite cualquier firma de código
- `cs_enforcement_disable`: Argumento de todo el sistema utilizado para deshabilitar la aplicación de firmas de código
- `amfi_prevent_old_entitled_platform_binaries`: Invalida los platform binaries con entitlements
- `amfi_get_out_of_my_way`: Deshabilita amfi por completo

Estas son algunas de las políticas MACF que registra:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** Se realizará la actualización de la etiqueta y se devolverá 1
- **`cred_label_associate`**: Actualiza el mac label slot de AMFI con la etiqueta
- **`cred_label_destroy`**: Elimina el mac label slot de AMFI
- **`cred_label_init`**: Mueve 0 al mac label slot de AMFI
- **`cred_label_update_execve:`** Comprueba los entitlements del proceso para determinar si se le debe permitir modificar las etiquetas.
- **`file_check_mmap:`** Comprueba si mmap está adquiriendo memoria y estableciéndola como ejecutable. En ese caso, comprueba si se necesita library validation y, si es así, llama a la función de library validation.
- **`file_check_library_validation`**: Llama a la función de library validation, que comprueba, entre otras cosas, si un platform binary está cargando otro platform binary o si el proceso y el nuevo archivo cargado tienen el mismo TeamID. Ciertos entitlements también permitirán cargar cualquier library.
- **`policy_initbsd`**: Configura trusted NVRAM Keys
- **`policy_syscall`**: Comprueba las políticas de DYLD, como si el binary tiene unrestricted segments o si se deben permitir las env vars... Esto también se llama cuando se inicia un proceso mediante `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Comprueba si, cuando un proceso ejecuta un nuevo binary, otros procesos con derechos SEND sobre el task port del proceso deben conservarlos o no. Los platform binaries tienen permiso, el entitlement `get-task-allow` lo permite, los entitlements `task_for_pid-allow` tienen permiso y también los binaries con el mismo TeamID.
- **`proc_check_expose_task`**: Hace cumplir los entitlements
- **`amfi_exc_action_check_exception_send`**: Se envía un mensaje de excepción al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida de la etiqueta durante la gestión de excepciones (debugging)
- **`proc_check_get_task`**: Comprueba entitlements como `get-task-allow`, que permite a otros procesos obtener el task port del proceso, y `task_for_pid-allow`, que permite al proceso obtener los task ports de otros procesos. Si no está presente ninguno de ellos, llama a `amfid permitunrestricteddebugging` para comprobar si está permitido.
- **`proc_check_mprotect`**: Deniega la operación si `mprotect` se llama con el flag `VM_PROT_TRUSTED`, que indica que la región debe tratarse como si tuviera una firma de código válida.
- **`vnode_check_exec`**: Se llama cuando se cargan archivos ejecutables en memoria y establece `cs_hard | cs_kill`, lo que finalizará el proceso si alguna de las páginas deja de ser válida<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: Comprueba `com.apple.root.installed` y `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Igual que get + los entitlements `com.apple.private.allow-bless` e `internal-installer-equivalent`
- **`vnode_check_signature`**: Código que llama a XNU para comprobar la firma de código utilizando entitlements, trust cache y `amfid`<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: Intercepta las llamadas a `ptrace()` (`PT_ATTACH` y `PT_TRACE_ME`). Comprueba cualquiera de los entitlements `get-task-allow`, `run-invalid-allow` y `run-unsigned-code` y, si no encuentra ninguno, comprueba si la depuración está permitida.
- **`proc_check_map_anon`**: Si se llama a mmap con el flag **`MAP_JIT`**, AMFI comprobará el entitlement `dynamic-codesigning`.

`AMFI.kext` también expone una API para otros kernel extensions, y es posible encontrar sus dependencias con:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Este es el daemon que se ejecuta en modo usuario y que `AMFI.kext` utilizará para comprobar las firmas de código en modo usuario.\
Para que `AMFI.kext` se comunique con el daemon, utiliza mensajes mach a través del puerto `HOST_AMFID_PORT`, que es el puerto especial `18`.

Ten en cuenta que en macOS ya no es posible que los procesos root secuestren puertos especiales, ya que están protegidos por `SIP` y solo launchd puede obtenerlos. En iOS se comprueba que el proceso que envía la respuesta tenga el CDHash de `amfid` hardcodeado.

Es posible ver cuándo se solicita a `amfid` que compruebe un binario y cuál es su respuesta mediante debugging y estableciendo un breakpoint en `mach_msg`.

Una vez que se recibe un mensaje a través del puerto especial, se utiliza **MIG** para enviar cada función a la función que está llamando. Las funciones principales fueron reverseadas y explicadas dentro del libro.

### Política de DYLD y validación de bibliotecas

Las versiones recientes de `dyld` llaman a `amfi_check_dyld_policy_self()` muy pronto desde `configureProcessRestrictions()` para preguntar a AMFI si el proceso puede utilizar variables de ruta `DYLD_*`, interposing, rutas de fallback, variables embebidas o tolerar fallos en la inserción de bibliotecas. Por tanto, al analizar una superficie de injection no basta con inspeccionar únicamente los load commands de Mach-O: también es necesario inspeccionar los entitlements y los runtime flags que AMFI traducirá a la política de `dyld`.

Un ciclo práctico de triage es:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
En las versiones modernas de macOS, muchos binarios de Apple ya no incluyen directamente `com.apple.security.cs.disable-library-validation` y, en su lugar, incorporan `com.apple.private.security.clear-library-validation`. En ese caso, la validación de bibliotecas no se deshabilita en el momento de `execve`: el proceso debe llamar a `csops(..., CS_OPS_CLEAR_LV, ...)` sobre sí mismo, y XNU solo permite esta operación en el proceso que realiza la llamada cuando el entitlement está presente. Desde una perspectiva ofensiva, esto es importante porque un objetivo puede volverse susceptible de inyección únicamente **después** de alcanzar la ruta de código que borra explícitamente LV (por ejemplo, poco antes de cargar plugins opcionales).<sup>[4][5]</sup>

## Perfiles de aprovisionamiento

Un perfil de aprovisionamiento puede utilizarse para firmar código. Existen perfiles **Developer** que pueden utilizarse para firmar código y probarlo, y perfiles **Enterprise** que pueden utilizarse en todos los dispositivos.

Después de enviar una App a Apple Store, si se aprueba, Apple la firma y el perfil de aprovisionamiento deja de ser necesario.

Un perfil normalmente utiliza la extensión `.mobileprovision` o `.provisionprofile` y puede extraerse con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Aunque a veces se denominan certificados, estos provisioning profiles contienen más que un certificado:

- **AppIDName:** El Application Identifier
- **AppleInternalProfile**: Designa este perfil como un perfil interno de Apple
- **ApplicationIdentifierPrefix**: Se antepone a AppIDName (igual que TeamIdentifier)
- **CreationDate**: Fecha en formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array de uno o varios certificados (normalmente uno), codificados como datos Base64
- **Entitlements**: Los entitlements permitidos para este perfil
- **ExpirationDate**: Fecha de expiración en formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: El nombre de la aplicación, igual que AppIDName
- **ProvisionedDevices**: Un array (para developer certificates) de UDIDs para los que este perfil es válido
- **ProvisionsAllDevices**: Un booleano (true para enterprise certificates)
- **TeamIdentifier**: Un array de una o varias cadenas alfanuméricas (normalmente una) utilizadas para identificar al desarrollador con fines de interacción entre aplicaciones
- **TeamName**: Un nombre legible utilizado para identificar al desarrollador
- **TimeToLive**: Validez (en días) del certificado
- **UUID**: Un Universally Unique Identifier para este perfil
- **Version**: Actualmente establecido en 1

Ten en cuenta que la entrada de entitlements contendrá un conjunto restringido de entitlements y que el provisioning profile solo podrá proporcionar esos entitlements específicos, para evitar conceder private entitlements de Apple.

Ten en cuenta que los perfiles suelen encontrarse en `/var/MobileDeviceProvisioningProfiles` y es posible comprobarlos con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta es la biblioteca externa que `amfid` llama para preguntar si debe permitir algo o no. Históricamente, se ha abusado de ella en jailbreaking ejecutando una versión backdoored que lo permitía todo.

En macOS se encuentra dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Los trust caches no son un concepto exclusivo de iOS. En las versiones modernas de macOS, especialmente en **Apple silicon**, el static trust cache y los loadable trust caches forman parte de la cadena de Secure Boot. Cuando el **CodeDirectory hash** de un Mach-O está presente en ellos, AMFI puede concederle **platform privilege** sin realizar comprobaciones adicionales de autenticidad durante el launch. Esto también permite a Apple vincular los binarios de plataforma a una versión específica del sistema operativo y evitar que binarios antiguos firmados por Apple se reproduzcan en sistemas más recientes.<sup>[6]</sup>

En las versiones recientes de macOS, los metadatos del trust cache también están vinculados a **launch constraints**, por lo que las aplicaciones del sistema y los binarios copiados e iniciados desde el parent/location incorrecto pueden ser rechazados por AMFI aunque sigan estando firmados por Apple. El flujo de trabajo detallado de extracción y reversing se explica en:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

En la investigación sobre iOS y jailbreak todavía encontrarás el modelo tradicional de **loadable trust caches** utilizado para incluir en una whitelist binarios firmados ad hoc.

## Referencias

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
