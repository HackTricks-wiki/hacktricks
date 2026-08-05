# Inscribir dispositivos en otras organizaciones

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Como se [**comentó anteriormente**](#what-is-mdm-mobile-device-management)**,** para intentar inscribir un dispositivo en una organización **solo se necesita un número de serie perteneciente a esa organización**. Una vez inscrito el dispositivo, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y demás](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por lo tanto, esto podría ser un entrypoint peligroso para los atacantes si el proceso de inscripción no está correctamente protegido.

**Lo siguiente es un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consúltala para obtener más detalles técnicos!**<sup>[[1]](#references)</sup>

## Descripción general del análisis binario de DEP y MDM

Esta investigación profundiza en los binarios asociados con el Device Enrollment Program (DEP) y Mobile Device Management (MDM) en macOS. Los componentes principales incluyen:

- **`mdmclient`**: Se comunica con los servidores MDM y activa los check-ins de DEP en versiones de macOS anteriores a la 10.13.4.
- **`profiles`**: Gestiona los Configuration Profiles y activa los check-ins de DEP en versiones de macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones con la API de DEP y recupera los perfiles de Device Enrollment.

Los check-ins de DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del framework privado Configuration Profiles para obtener el Activation Record, y `CPFetchActivationRecord` se coordina con `cloudconfigurationd` mediante XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering del protocolo Tesla y el esquema Absinthe

El check-in de DEP implica que `cloudconfigurationd` envíe un payload JSON cifrado y firmado a _iprofiles.apple.com/macProfile_. El payload incluye el número de serie del dispositivo y la acción "RequestProfileConfiguration". El esquema de cifrado utilizado se denomina internamente "Absinthe". Desentrañar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar números de serie arbitrarios en la solicitud del Activation Record.<sup>[[1]](#references)</sup>

## Proxying de solicitudes DEP

Los intentos de interceptar y modificar solicitudes DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por el cifrado del payload y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite omitir la validación del certificado del servidor, aunque la naturaleza cifrada del payload sigue impidiendo modificar el número de serie sin la clave de descifrado.<sup>[[1]](#references)</sup>

## Instrumentación de binarios del sistema que interactúan con DEP

La instrumentación de binarios del sistema como `cloudconfigurationd` requiere desactivar System Integrity Protection (SIP) en macOS. Con SIP desactivado, se pueden utilizar herramientas como LLDB para conectarse a procesos del sistema y modificar potencialmente el número de serie utilizado en las interacciones con la API de DEP. Este método es preferible porque evita las complejidades de los entitlements y la firma de código.

**Explotación de la instrumentación de binarios:**
Modificar el payload de la solicitud DEP antes de la serialización JSON en `cloudconfigurationd` demostró ser eficaz. El proceso implicó:

1. Conectarse con LLDB a `cloudconfigurationd`.
2. Localizar el punto en el que se obtiene el número de serie del sistema.
3. Inyectar un número de serie arbitrario en la memoria antes de que el payload se cifre y envíe.

Este método permitió recuperar perfiles DEP completos para números de serie arbitrarios, demostrando una posible vulnerabilidad.<sup>[[1]](#references)</sup>

### Automatización de la instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que permitió inyectar números de serie arbitrarios mediante programación y recuperar los perfiles DEP correspondientes.<sup>[[1]](#references)</sup>

### Posibles impactos de las vulnerabilidades de DEP y MDM

La investigación destacó importantes problemas de seguridad:

1. **Divulgación de información**: Al proporcionar un número de serie registrado en DEP, se puede recuperar información sensible de la organización contenida en el perfil DEP.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
