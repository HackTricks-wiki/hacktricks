# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Se centra en hacer cumplir la integridad del código que se ejecuta en el sistema, proporcionando la lógica detrás de la verificación de firmas de código de XNU. También puede comprobar entitlements y gestionar otras tareas sensibles, como permitir debugging u obtener task ports.

Además, para algunas operaciones, el kext prefiere contactar con el daemon en user space `/usr/libexec/amfid`. Esta relación de confianza ha sido abusada en varios jailbreaks.

En versiones recientes de macOS, AMFI ya no se expone cómodamente como un kext independiente en disco, así que invertirlo normalmente implica trabajar desde el **kernelcache** o un **KDK** en lugar de explorar `/System/Library/Extensions`.

AMFI usa políticas **MACF** y registra sus hooks en el momento en que se inicia. Además, impedir su carga o descargarlo podría provocar un kernel panic. Sin embargo, hay algunos argumentos de arranque que permiten debilitar AMFI:

- `amfi_unrestricted_task_for_pid`: Permite que task_for_pid se autorice sin los entitlements requeridos
- `amfi_allow_any_signature`: Permite cualquier firma de código
- `cs_enforcement_disable`: Argumento global del sistema usado para desactivar la aplicación de code signing
- `amfi_prevent_old_entitled_platform_binaries`: Invalida platform binaries con entitlements antiguos
- `amfi_get_out_of_my_way`: Desactiva amfi por completo

Estas son algunas de las políticas MACF que registra:

- **`cred_check_label_update_execve:`** La actualización de la etiqueta se realizará y devolverá 1
- **`cred_label_associate`**: Actualiza el espacio de etiqueta mac de AMFI con la etiqueta
- **`cred_label_destroy`**: Elimina el espacio de etiqueta mac de AMFI
- **`cred_label_init`**: Pone 0 en el espacio de etiqueta mac de AMFI
- **`cred_label_update_execve`:** Comprueba los entitlements del proceso para ver si se le debe permitir modificar las etiquetas.
- **`file_check_mmap`:** Comprueba si mmap está adquiriendo memoria y marcándola como ejecutable. En ese caso comprueba si se necesita library validation y, si es así, llama a la función de library validation.
- **`file_check_library_validation`**: Llama a la función de library validation, que comprueba entre otras cosas si un platform binary está cargando otro platform binary o si el proceso y el archivo recién cargado tienen el mismo TeamID. Ciertos entitlements también permitirán cargar cualquier library.
- **`policy_initbsd`**: Configura claves NVRAM de confianza
- **`policy_syscall`**: Comprueba políticas DYLD, como si el binary tiene segmentos sin restricciones, si debe permitir variables de entorno... esto también se llama cuando un proceso se inicia mediante `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Comprueba si, cuando un proceso ejecuta un nuevo binary, otros procesos con derechos SEND sobre el task port del proceso deben conservarlos o no. Se permiten platform binaries, los entitlements `get-task-allow` lo permiten, los entitlements `task_for_pid-allow` lo permiten y los binaries con el mismo TeamID.
- **`proc_check_expose_task`**: aplica entitlements
- **`amfi_exc_action_check_exception_send`**: Se envía un mensaje de excepción al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo de vida de la etiqueta durante el manejo de excepciones (debugging)
- **`proc_check_get_task`**: Comprueba entitlements como `get-task-allow`, que permite a otros procesos obtener el task port, y `task_for_pid-allow`, que permite al proceso obtener los task ports de otros procesos. Si no tiene ninguno de esos, consulta a `amfid permitunrestricteddebugging` para comprobar si está permitido.
- **`proc_check_mprotect`**: Deniega si `mprotect` se llama con la bandera `VM_PROT_TRUSTED`, que indica que la región debe tratarse como si tuviera una firma de código válida.
- **`vnode_check_exec`**: Se llama cuando los archivos ejecutables se cargan en memoria y establece `cs_hard | cs_kill`, lo que matará el proceso si alguna de las páginas se vuelve inválida
- **`vnode_check_getextattr`**: MacOS: Comprueba `com.apple.root.installed` y `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Igual que get + `com.apple.private.allow-bless` y el entitlement internal-installer-equivalent
- **`vnode_check_signature`**: Código que llama a XNU para comprobar la firma de código usando entitlements, trust cache y `amfid`
- **`proc_check_run_cs_invalid`**: Intercepta llamadas a `ptrace()` (`PT_ATTACH` y `PT_TRACE_ME`). Comprueba cualquiera de los entitlements `get-task-allow`, `run-invalid-allow` y `run-unsigned-code` y, si no hay ninguno, comprueba si debugging está permitido.
- **`proc_check_map_anon`**: Si `mmap` se llama con la bandera **`MAP_JIT`**, AMFI comprobará el entitlement `dynamic-codesigning`.

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

Este es el daemon en modo usuario que `AMFI.kext` usará para comprobar firmas de código en modo usuario.\
Para que `AMFI.kext` se comunique con el daemon, usa mach messages sobre el puerto `HOST_AMFID_PORT`, que es el puerto especial `18`.

Ten en cuenta que en macOS ya no es posible que procesos root secuestren puertos especiales, ya que están protegidos por `SIP` y solo `launchd` puede obtenerlos. En iOS se comprueba que el proceso que envía la respuesta de vuelta tenga el CDHash hardcodeado de `amfid`.

Es posible ver cuándo se le pide a `amfid` que compruebe un binario y la respuesta de este depurándolo y estableciendo un breakpoint en `mach_msg`.

Una vez que se recibe un mensaje mediante el puerto especial, se usa **MIG** para enviar cada función a la función a la que está llamando. Las funciones principales fueron invertidas y explicadas dentro del libro.

### Política de DYLD y validación de bibliotecas

Las versiones recientes de `dyld` llaman a `amfi_check_dyld_policy_self()` muy temprano desde `configureProcessRestrictions()` para preguntar a AMFI si el proceso puede usar variables de ruta `DYLD_*`, interposing, fallback paths, variables embebidas o tolerar una inserción de biblioteca fallida. Por tanto, al analizar una superficie de inyección no basta con inspeccionar solo los load commands de Mach-O: también necesitas inspeccionar las entitlements y los runtime flags que AMFI traducirá a política de `dyld`.

Un ciclo práctico de análisis es:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
En las versiones modernas de macOS, muchos binarios de Apple ya no llevan `com.apple.security.cs.disable-library-validation` directamente y, en su lugar, incluyen `com.apple.private.security.clear-library-validation`. En ese caso, la validación de librerías no se desactiva en el momento de `execve`: el proceso debe llamar a `csops(..., CS_OPS_CLEAR_LV, ...)` sobre sí mismo, y XNU solo permite esa operación en el proceso que llama cuando la entitlement está presente. Desde una perspectiva ofensiva, esto importa porque un objetivo puede volverse injectable solo **después** de llegar a la ruta de código que limpia explícitamente LV (por ejemplo, justo antes de cargar plugins opcionales).

## Provisioning Profiles

Un provisioning profile se puede usar para firmar código. Hay perfiles de **Developer** que se pueden usar para firmar código y probarlo, y perfiles de **Enterprise** que se pueden usar en todos los dispositivos.

Después de que una App se envía al Apple Store, si se aprueba, Apple la firma y el provisioning profile ya no es necesario.

Un profile suele usar la extensión `.mobileprovision` o `.provisionprofile` y se puede volcar con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Aunque a veces se les llama certificados, estos provisioning profiles tienen más que un certificado:

- **AppIDName:** El Application Identifier
- **AppleInternalProfile**: Designa esto como un perfil Apple Internal
- **ApplicationIdentifierPrefix**: Prefijado a AppIDName (igual que TeamIdentifier)
- **CreationDate**: Fecha en formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array de (normalmente uno) certificado(s), codificados como datos Base64
- **Entitlements**: Los entitlements permitidos con entitlements para este profile
- **ExpirationDate**: Fecha de expiración en formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: El Application Name, igual que AppIDName
- **ProvisionedDevices**: Un array (para developer certificates) de UDIDs para los que este profile es válido
- **ProvisionsAllDevices**: Un booleano (true para enterprise certificates)
- **TeamIdentifier**: Un array de (normalmente uno) string(s) alfanuméricos usados para identificar al developer con fines de inter-app interaction
- **TeamName**: Un nombre legible por humanos usado para identificar al developer
- **TimeToLive**: Validez (en días) del certificado
- **UUID**: Un Universally Unique Identifier para este profile
- **Version**: Actualmente establecido en 1

Ten en cuenta que la entrada de entitlements contendrá un conjunto restringido de entitlements y el provisioning profile solo podrá otorgar esos entitlements específicos para evitar conceder Apple private entitlements.

Ten en cuenta que los profiles suelen estar ubicados en `/var/MobileDeviceProvisioningProfiles` y es posible verificarlos con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Esta es la librería externa que `amfid` llama para preguntar si debe permitir algo o no. Históricamente se ha abusado de esto en jailbreaking ejecutando una versión backdoored de ella que permitiría todo.

En macOS esto está dentro de `MobileDevice.framework`.

## AMFI Trust Caches

Los trust caches no son solo un concepto de iOS. En macOS moderno, especialmente en **Apple silicon**, la static trust cache y las loadable trust caches forman parte de la cadena de Secure Boot. Cuando el **CodeDirectory hash** de un Mach-O está presente allí, AMFI puede concederle **platform privilege** sin realizar más comprobaciones de autenticidad en el momento del lanzamiento. Esto también significa que Apple puede bloquear los platform binaries a una versión específica de OS y evitar que binarios firmados por Apple de versiones anteriores se reutilicen en sistemas más nuevos.

En versiones recientes de macOS, los metadatos de trust-cache también están vinculados a **launch constraints**, por lo que las copied system apps y los binarios iniciados desde el parent/location incorrecto pueden ser rechazados por AMFI aunque sigan estando firmados por Apple. El flujo detallado de extracción y reversing se cubre en:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

En iOS y en la investigación de jailbreak seguirás encontrando el modelo tradicional de **loadable trust caches** usado para autorizar binarios firmados ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
