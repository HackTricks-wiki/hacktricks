# Inscribir dispositivos en otras organizaciones

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Apple Automated Device Enrollment (anteriormente DEP) comienza identificando un dispositivo asignado a una organización. La investigación de 2018 resumida aquí mostró que conocer un número de serie asignado era suficiente para recuperar los perfiles de enrollment de algunas organizaciones, porque dichas organizaciones no requerían autenticación adicional adecuada. Este es un hallazgo histórico, no una afirmación de que todos los MDM actuales puedan unirse utilizando únicamente un número de serie. Los perfiles pueden contener certificados, aplicaciones, secretos de Wi-Fi, configuraciones de VPN y otra configuración sensible.<sup>[[1]](#references)[[2]](#references)</sup>

**Lo siguiente es un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consúltala para obtener más detalles técnicos!**<sup>[[1]](#references)</sup>

## Descripción general del análisis binario de DEP y MDM

La investigación analizó binarios asociados con DEP y MDM en las versiones de macOS actuales en ese momento. Los nombres y las responsabilidades de los componentes pueden cambiar entre versiones:

- **`mdmclient`**: Se comunica con los servidores MDM y activa los check-ins de DEP en versiones de macOS anteriores a la 10.13.4.
- **`profiles`**: Gestiona Configuration Profiles y activa los check-ins de DEP en versiones de macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones con la API de DEP y recupera los perfiles de Device Enrollment.

Los check-ins de DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del framework privado Configuration Profiles para obtener el Activation Record, mientras que `CPFetchActivationRecord` coordina la comunicación con `cloudconfigurationd` mediante XPC.<sup>[[1]](#references)</sup>

## Ingeniería inversa del protocolo Tesla y el esquema Absinthe

El check-in de DEP implica que `cloudconfigurationd` envíe un payload JSON cifrado y firmado a _iprofiles.apple.com/macProfile_. El payload incluye el número de serie del dispositivo y la acción "RequestProfileConfiguration". El esquema de cifrado utilizado se denomina internamente "Absinthe". Desentrañar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar números de serie arbitrarios en la solicitud del Activation Record.<sup>[[1]](#references)</sup>

## Proxying de solicitudes DEP

Los intentos de interceptar y modificar solicitudes DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por el cifrado del payload y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite omitir la validación del certificado del servidor, aunque la naturaleza cifrada del payload sigue impidiendo modificar el número de serie sin la clave de descifrado.<sup>[[1]](#references)</sup>

## Instrumentación de binarios del sistema que interactúan con DEP

Instrumentar binarios del sistema como `cloudconfigurationd` requiere deshabilitar System Integrity Protection (SIP) en macOS. Con SIP deshabilitado, se pueden utilizar herramientas como LLDB para conectarse a procesos del sistema y modificar potencialmente el número de serie utilizado en las interacciones con la API de DEP. Este método es preferible porque evita las complejidades de los entitlements y la firma de código.<sup>[[1]](#references)</sup>

**Explotación de la instrumentación de binarios:**
Modificar el payload de la solicitud DEP antes de la serialización JSON en `cloudconfigurationd` resultó efectivo. El proceso consistió en:

1. Conectarse con LLDB a `cloudconfigurationd`.
2. Localizar el punto en el que se obtiene el número de serie del sistema.
3. Inyectar un número de serie arbitrario en la memoria antes de que el payload se cifre y se envíe.

Este método permitió a los investigadores recuperar perfiles DEP para números de serie proporcionados y asignados. No hizo válido un número de serie arbitrario no asignado.<sup>[[1]](#references)</sup>

### Automatización de la instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que permitió inyectar números de serie arbitrarios mediante programación y recuperar los perfiles DEP correspondientes.<sup>[[1]](#references)</sup>

### Posibles impactos de las vulnerabilidades de DEP y MDM

La investigación destacó importantes problemas de seguridad:

1. **Divulgación de información**: Al proporcionar un número de serie registrado en DEP, se puede recuperar información organizativa sensible contenida en el perfil DEP.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Seguridad del Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
