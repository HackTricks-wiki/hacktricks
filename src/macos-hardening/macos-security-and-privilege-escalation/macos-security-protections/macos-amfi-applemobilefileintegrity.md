# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Se centra en hacer cumplir la integridad del código que se ejecuta en el sistema, proporcionando la lógica detrás de la verificación de firmas de código de XNU. También es capaz de comprobar entitlements y manejar otras tareas sensibles como permitir debugging u obtener task ports.

Además, para algunas operaciones, la kext prefiere contactar con el daemon en user space `/usr/libexec/amfid`. Esta relación de confianza ha sido abusada en varios jailbreaks.

En versiones recientes de macOS, AMFI ya no se expone cómodamente como una kext independiente en disco, así que normalmente hacer reverse implica trabajar a partir del **kernelcache** o de un **KDK** en lugar de navegar por `/System/Library/Extensions`.

AMFI usa políticas **MACF** y registra sus hooks en el momento en que se inicia. Además, impedir su carga o descargarla podría provocar un kernel panic. Sin embargo, hay algunos boot arguments que permiten debilitar AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid se autorice sin los entitlements requeridos
- `amfi_allow_any_signature`: Permite cualquier code signature
- `cs_enforcement_disable`: Argumento de sistema usado para desactivar la aplicación de code signing
- `amfi_prevent_old_entitled_platform_binaries`: Anula platform binaries con entitlements
- `amfi_get_out_of_my_way`: Desactiva amfi por completo

Estas son algunas de las políticas MACF que registra:

- **`cred_check_label_update_execve:`** La actualización de label se realizará y devolverá 1
- **`cred_label_associate`**: Actualiza el slot de mac label de AMFI con el label
- **`cred_label_destroy`**: Elimina el slot de mac label de AMFI
- **`cred_label_init`**: Pone 0 en el slot de mac label de AMFI
- **`cred_label_update_execve`:** Comprueba los entitlements del proceso para ver si se le debe permitir modificar los labels.
- **`file_check_mmap`:** Comprueba si mmap está adquiriendo memoria y marcándola como executable. En ese caso, comprueba si se necesita library validation y, si es así, llama a la función de library validation.
- **`file_check_library_validation`**: Llama a la función de library validation, que comprueba, entre otras cosas, si un platform binary está cargando otro platform binary o si el proceso y el nuevo archivo cargado tienen el mismo TeamID. Ciertos entitlements también permitirán cargar cualquier library.
- **`policy_initbsd`**: Configura claves de NVRAM de confianza
- **`policy_syscall`**: Comprueba políticas de DYLD como si el binary tiene segmentos unrestricted, si debe permitir env vars... esto también se llama cuando un proceso se inicia mediante `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Comprueba si, cuando un proceso ejecuta un nuevo binary, otros procesos con permisos SEND sobre el task port del proceso deben conservarlos o no. Los platform binaries están permitidos, `get-task-allow` entitlement lo permite, `task_for_pid-allow` entitles están permitidos y binaries con el mismo TeamID.
- **`proc_check_expose_task`**: aplica entitlements
- **`amfi_exc_action_check_exception_send`**: Se envía un exception message al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida del label durante el manejo de excepciones (debugging)
- **`proc_check_get_task`**: Comprueba entitlements como `get-task-allow`, que permite a otros procesos obtener el task port, y `task_for_pid-allow`, que permite al proceso obtener los task ports de otros procesos. Si ninguno de esos, llama a `amfid permitunrestricteddebugging` para comprobar si está permitido.
- **`proc_check_mprotect`**: Deniega si `mprotect` se llama con la flag `VM_PROT_TRUSTED`, que indica que la región debe tratarse como si tuviera una code signature válida.
- **`vnode_check_exec`**: Se llama cuando archivos ejecutables se cargan en memoria y establece `cs_hard | cs_kill`, lo que matará el proceso si alguna de las páginas se vuelve inválida
- **`vnode_check_getextattr`**: MacOS: Comprueba `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Igual que get + `com.apple.private.allow-bless` y el entitlement internal-installer-equivalent
- **`vnode_check_signature`**: Código que llama a XNU para comprobar la code signature usando entitlements, trust cache y `amfid`
- **`proc_check_run_cs_invalid`**: Intercepta llamadas a `ptrace()` (`PT_ATTACH` y `PT_TRACE_ME`). Comprueba cualquiera de los entitlements `get-task-allow`, `run-invalid-allow` y `run-unsigned-code` y, si ninguno está presente, comprueba si el debugging está permitido.
- **`proc_check_map_anon`**: Si mmap se llama con la flag **`MAP_JIT`**, AMFI comprobará el entitlement `dynamic-codesigning`.

`AMFI.kext` también expone una API para otras extensiones del kernel, y es posible encontrar sus dependencias con:
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

Este es el daemon en modo usuario que `AMFI.kext` usará para comprobar las firmas de código en modo usuario.\
Para que `AMFI.kext` se comunique con el daemon, utiliza mensajes mach sobre el puerto `HOST_AMFID_PORT`, que es el puerto especial `18`.

Ten en cuenta que en macOS ya no es posible para procesos root secuestrar puertos especiales, ya que están protegidos por `SIP` y solo `launchd` puede obtenerlos. En iOS se comprueba que el proceso que envía la respuesta tenga el CDHash hardcodeado de `amfid`.

Es posible ver cuándo `amfid` es solicitado para comprobar un binario y la respuesta de este depurándolo y estableciendo un breakpoint en `mach_msg`.

Una vez que se recibe un mensaje a través del puerto especial, **MIG** se usa para enviar cada función a la función que está llamando. Las funciones principales fueron revertidas y explicadas dentro del libro.

### Política de DYLD y validación de bibliotecas

Las versiones recientes de `dyld` llaman a `amfi_check_dyld_policy_self()` muy pronto desde `configureProcessRestrictions()` para preguntar a AMFI si el proceso puede usar variables de ruta `DYLD_*`, interposing, rutas fallback, variables embebidas, o tolerar la inserción fallida de bibliotecas. Por lo tanto, al analizar una superficie de inyección no basta con inspeccionar solo los comandos de carga de Mach-O: también necesitas inspeccionar las entitlements y las banderas de runtime que AMFI traducirá en política de `dyld`.

Un ciclo práctico de análisis es:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
En las versiones modernas de macOS, muchos binarios de Apple ya no llevan `com.apple.security.cs.disable-library-validation` directamente y, en su lugar, incluyen `com.apple.private.security.clear-library-validation`. En ese caso, la library validation no se deshabilita en el momento de `execve`: el proceso debe llamar a `csops(..., CS_OPS_CLEAR_LV, ...)` sobre sí mismo, y XNU solo अनुमति esa operación en el proceso que llama cuando el entitlement está presente. Desde una perspectiva ofensiva, esto importa porque un objetivo puede volverse inyectable solo **después** de llegar a la ruta de código que borra explícitamente LV (por ejemplo, justo antes de cargar plugins opcionales).

## Provisioning Profiles

Un provisioning profile puede usarse para firmar código. Hay perfiles **Developer** que pueden usarse para firmar código y probarlo, y perfiles **Enterprise** que pueden usarse en todos los dispositivos.

Después de que una App se envía a la Apple Store, si se aprueba, queda firmada por Apple y el provisioning profile ya no es necesario.

Un profile normalmente usa la extensión `.mobileprovision` o `.provisionprofile` y puede volcarse con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Aunque a veces se les denomina certificated, estos perfiles de aprovisionamiento tienen más que un certificate:

- **AppIDName:** El identificador de la aplicación
- **AppleInternalProfile**: Designa esto como un perfil interno de Apple
- **ApplicationIdentifierPrefix**: Se antepone a AppIDName (igual que TeamIdentifier)
- **CreationDate**: Fecha en formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array de (normalmente uno) certificate(s), codificados como datos Base64
- **Entitlements**: Los entitlements permitidos con entitlements para este perfil
- **ExpirationDate**: Fecha de expiración en formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: El nombre de la aplicación, igual que AppIDName
- **ProvisionedDevices**: Un array (para developer certificates) de UDIDs para los que este perfil es válido
- **ProvisionsAllDevices**: Un booleano (true para enterprise certificates)
- **TeamIdentifier**: Un array de (normalmente una) cadena(s) alfanumérica(s) usada(s) para identificar al desarrollador con fines de interacción entre apps
- **TeamName**: Un nombre legible por humanos usado para identificar al desarrollador
- **TimeToLive**: Validez (en días) del certificate
- **UUID**: Un Identificador Único Universal para este perfil
- **Version**: Actualmente establecido en 1

Ten en cuenta que la entrada entitlements contendrá un conjunto restringido de entitlements y el provisioning profile solo podrá otorgar esos entitlements específicos para evitar conceder Apple private entitlements.

Ten en cuenta que los profiles suelen estar ubicados en `/var/MobileDeviceProvisioningProfiles` y es posible verificarlos con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta es la librería externa que `amfid` llama para preguntar si debe permitir algo o no. Históricamente se ha abusado de esto en jailbreaking ejecutando una versión con backdoor que permitiría todo.

En macOS esto está dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Los trust caches no son solo un concepto de iOS. En macOS moderno, especialmente en **Apple silicon**, el static trust cache y los loadable trust caches forman parte de la cadena de Secure Boot. Cuando el **CodeDirectory hash** de un Mach-O está presente allí, AMFI puede concederle **platform privilege** sin realizar más comprobaciones de autenticidad en el momento del lanzamiento. Esto también significa que Apple puede bloquear binarios de plataforma a una versión específica del OS e impedir que binarios antiguos firmados por Apple se reutilicen en sistemas más nuevos.

En versiones recientes de macOS, los metadatos del trust-cache también están vinculados a **launch constraints**, de modo que las aplicaciones y binarios del sistema copiados y ejecutados desde el padre/ubicación incorrectos pueden ser rechazados por AMFI incluso si siguen estando firmados por Apple. El proceso detallado de extracción y reversing se cubre en:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

En investigaciones de iOS y jailbreak todavía encontrarás el modelo tradicional de **loadable trust caches** usado para poner en whitelist binarios firmados ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
