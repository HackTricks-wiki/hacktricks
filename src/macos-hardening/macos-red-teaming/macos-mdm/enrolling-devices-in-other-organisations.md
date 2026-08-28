# Inscripción de dispositivos en otras organizaciones

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Apple Automated Device Enrollment (anteriormente DEP) comienza identificando un dispositivo asignado a una organización. La investigación de 2018 resumida aquí mostró que conocer un número de serie asignado era suficiente para recuperar los perfiles de inscripción de algunas organizaciones, porque esas organizaciones no requerían una autenticación adicional adecuada. Este es un hallazgo histórico, no una afirmación de que todos los MDM actuales puedan unirse usando únicamente un número de serie. Los perfiles pueden contener certificados, aplicaciones, secretos de Wi-Fi, configuraciones de VPN y otra configuración sensible.<sup>[[1]](#references)[[2]](#references)</sup>

**Lo siguiente es un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consúltala para obtener más detalles técnicos!**<sup>[[1]](#references)</sup>

## Descripción general del análisis binario de DEP y MDM

La investigación analizó los binarios asociados con DEP y MDM en las versiones de macOS disponibles en ese momento. Los nombres y las responsabilidades de los componentes pueden cambiar entre versiones:

- **`mdmclient`**: Se comunica con los servidores MDM y activa los check-ins de DEP en versiones de macOS anteriores a la 10.13.4.
- **`profiles`**: Gestiona los Configuration Profiles y activa los check-ins de DEP en versiones de macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones con la API de DEP y recupera los perfiles de Device Enrollment.

Los check-ins de DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del framework privado Configuration Profiles para obtener el Activation Record, mientras que `CPFetchActivationRecord` se coordina con `cloudconfigurationd` mediante XPC.<sup>[[1]](#references)</sup>

## Ingeniería inversa del protocolo Tesla y el esquema Absinthe

El check-in de DEP implica que `cloudconfigurationd` envíe un payload JSON cifrado y firmado a _iprofiles.apple.com/macProfile_. El payload incluye el número de serie del dispositivo y la acción "RequestProfileConfiguration". El esquema de cifrado utilizado se denomina internamente "Absinthe". Desentrañar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar números de serie arbitrarios en la solicitud del Activation Record.<sup>[[1]](#references)</sup>

## Proxying de solicitudes DEP

Los intentos de interceptar y modificar solicitudes DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por el cifrado del payload y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite omitir la validación del certificado del servidor, aunque la naturaleza cifrada del payload sigue impidiendo modificar el número de serie sin la clave de descifrado.<sup>[[1]](#references)</sup>

## Instrumentación de binarios del sistema que interactúan con DEP

Instrumentar binarios del sistema como `cloudconfigurationd` requiere deshabilitar System Integrity Protection (SIP) en macOS. Con SIP deshabilitado, pueden utilizarse herramientas como LLDB para adjuntarse a procesos del sistema y modificar potencialmente el número de serie utilizado en las interacciones con la API de DEP. Este método es preferible porque evita las complejidades de los entitlements y la firma de código.<sup>[[1]](#references)</sup>

**Explotación de la instrumentación de binarios:**
Modificar el payload de la solicitud DEP antes de la serialización JSON en `cloudconfigurationd` resultó eficaz. El proceso implicó:

1. Adjuntarse con LLDB a `cloudconfigurationd`.
2. Localizar el punto en el que se obtiene el número de serie del sistema.
3. Inyectar un número de serie arbitrario en la memoria antes de que el payload se cifre y se envíe.

Este método permitió a los investigadores recuperar perfiles DEP para números de serie proporcionados y asignados. No hizo válido un número de serie arbitrario no asignado.<sup>[[1]](#references)</sup>

### Automatización de la instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que hizo posible inyectar números de serie arbitrarios mediante programación y recuperar los perfiles DEP correspondientes.<sup>[[1]](#references)</sup>

## Revisión de 2025: Rogue Enrollment desde una VM

La investigación de Black Hat Asia 2025 demostró que el problema original del límite de confianza todavía puede ser relevante en la **capa MDM**: en lugar de parchear `cloudconfigurationd` con LLDB, los investigadores ejecutaron macOS bajo QEMU/KVM con OpenCore y proporcionaron la identidad candidata mediante el SMBIOS de la VM. A continuación, el stack de inscripción de macOS sin modificar realizó el intercambio cifrado con Apple. Por tanto, los seriales filtrados públicamente y los candidatos con apariencia válida pueden probarse sin poseer el Mac físico correspondiente; aun así, para obtener un resultado positivo es necesario que el serial esté asignado a una organización y que la ruta de inscripción de la organización tenga una autenticación insuficiente.<sup>[[3]](#references)</sup>

Para un dispositivo de laboratorio autorizado, los valores relevantes de OpenCore `PlatformInfo` incluyen un modelo de producto y un serial (en despliegues reales, la ROM y el UUID también deben mantenerse internamente coherentes):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
La misma investigación identificó el estado `CheckProfilesFetchRateLimit` en el archivo privado `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Como la comprobación se mantenía en el cliente, modificar los valores de tiempo almacenados la anulaba. Estas rutas no están documentadas y dependen de la versión, pero resultan útiles como pivotes de reversing al evaluar una compilación actual de macOS:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
El segundo artefacto puede revelar el activation record almacenado en caché, incluido si el flujo utiliza una `ConfigurationURL` directa o una `ConfigurationWebURL` autenticada. Prueba tanto el flujo anunciado como cualquier endpoint de enrollment legacy específico de MDM: habilitar SSO solo en el flujo web principal no protege un endpoint directo paralelo. Para consultar la secuencia completa del protocolo, véase el [resumen de macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Búsqueda de secretos tras el enrollment

Un enrollment rogue es solo el punto de entrada. Después del enrollment, inspecciona cada perfil entregado, política de bootstrap, configuración del repositorio de paquetes, script de instalación de agentes y elemento de self service. La investigación de 2025 recuperó ejemplos de credenciales de Wi-Fi, contraseñas compartidas de administradores locales, URLs firmadas de cloud storage, URLs de webhooks, datos de activación de agentes de seguridad y credenciales de MDM/API. Una credencial de API del tenant en un script entregado puede convertir un endpoint rogue en control sobre otros dispositivos gestionados, por lo que se debe buscar tanto en el sistema de archivos activo como en el contenido de políticas descargado o almacenado en caché.<sup>[[3]](#references)</sup>

Entre los objetivos útiles para la revisión se incluyen:<sup>[[3]](#references)</sup>

- Payloads `.mobileconfig` instalados y la base de datos de Configuration Profiles.
- Scripts y paquetes de PreStage/bootstrap que crean cuentas o instalan agentes de EDR/VPN.
- URLs de Munki u otros repositorios de paquetes, especialmente cadenas de consulta que contengan firmas de tipo bearer/SAS.
- Catálogos de self service y sus APIs de políticas subyacentes, incluidas rutas legacy que podrían no aplicar la política de SSO del enrollment.
- Historial del shell y resultados de políticas almacenados en caché que contengan `password`, `token`, `secret`, `Authorization`, nombres de host de webhooks y endpoints de API de proveedores.

### Refuerzo del límite de confianza

Trata el número de serie como un atributo de inventario/enrutamiento, **no** como una prueba de posesión. Exige autenticación del usuario para el enrollment y el self service, genera contraseñas únicas de administrador local por dispositivo y nunca incrustes credenciales de API del tenant ni secretos de infraestructura reutilizables en perfiles o scripts. Mantén cualquier bootstrap token inevitable con una duración corta y restringido a la única acción y dispositivo que se estén provisionando.<sup>[[3]](#references)</sup>

En los Macs con Apple silicon que ejecuten macOS 14 o posterior, Managed Device Attestation puede vincular criptográficamente la identidad al Secure Enclave. Su attestation basada en la raíz de Apple puede incluir un nonce nuevo junto con el número de serie, UDID, versión del sistema operativo, estado de SIP y estado del secure boot; ACME puede emitir entonces una identidad de cliente vinculada al hardware. Utiliza esa identidad para proteger el canal MDM y controlar certificados de alto valor, acceso VPN y otros recursos, manteniendo al mismo tiempo una autenticación de usuario independiente, ya que la attestation del dispositivo demuestra la identidad del dispositivo, no la del operador.<sup>[[4]](#references)</sup>

## Posibles impactos de las vulnerabilidades de DEP y MDM

La investigación destacó importantes problemas de seguridad:

1. **Divulgación de información**: al proporcionar un número de serie registrado en DEP, se puede recuperar información organizativa sensible contenida en el perfil de DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — Seguridad del Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking Apple MDMs Using Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
