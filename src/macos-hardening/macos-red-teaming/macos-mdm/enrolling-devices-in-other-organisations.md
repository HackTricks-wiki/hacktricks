# Inscripción de dispositivos en otras organizaciones

{{#include ../../../banners/hacktricks-training.md}}

## Introducción

Como se [**comentó anteriormente**](#what-is-mdm-mobile-device-management)**,** para intentar inscribir un dispositivo en una organización **solo se necesita un Serial Number perteneciente a esa organización**. Una vez inscrito el dispositivo, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y demás](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por lo tanto, esto podría ser un entrypoint peligroso para los atacantes si el proceso de inscripción no está correctamente protegido.

**Lo siguiente es un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consúltala para obtener más detalles técnicos!**<sup>[1]</sup>

## Descripción general del análisis de binarios de DEP y MDM

Esta investigación analiza los binarios asociados con Device Enrollment Program (DEP) y Mobile Device Management (MDM) en macOS. Los componentes principales incluyen:

- **`mdmclient`**: Se comunica con los servidores MDM y activa los check-ins de DEP en versiones de macOS anteriores a la 10.13.4.
- **`profiles`**: Gestiona los Configuration Profiles y activa los check-ins de DEP en macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones con la API de DEP y recupera los perfiles de Device Enrollment.

Los check-ins de DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del framework privado Configuration Profiles para obtener el Activation Record, mientras que `CPFetchActivationRecord` se coordina con `cloudconfigurationd` mediante XPC.<sup>[1]</sup>

## Reverse Engineering del protocolo Tesla y del esquema Absinthe

El check-in de DEP implica que `cloudconfigurationd` envíe un payload JSON cifrado y firmado a _iprofiles.apple.com/macProfile_. El payload incluye el Serial Number del dispositivo y la acción `"RequestProfileConfiguration"`. El esquema de cifrado utilizado se denomina internamente "Absinthe". Desentrañar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar Serial Numbers arbitrarios en la solicitud del Activation Record.<sup>[1]</sup>

## Proxying de solicitudes DEP

Los intentos de interceptar y modificar las solicitudes DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por el cifrado del payload y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite omitir la validación del certificado del servidor, aunque la naturaleza cifrada del payload todavía impide modificar el Serial Number sin la clave de descifrado.<sup>[1]</sup>

## Instrumentación de binarios del sistema que interactúan con DEP

La instrumentación de binarios del sistema como `cloudconfigurationd` requiere deshabilitar System Integrity Protection (SIP) en macOS. Con SIP deshabilitado, se pueden utilizar herramientas como LLDB para adjuntarse a procesos del sistema y modificar potencialmente el Serial Number utilizado en las interacciones con la API de DEP. Este método es preferible, ya que evita las complejidades de los entitlements y la firma de código.

**Explotación de la instrumentación de binarios:**
Modificar el payload de la solicitud DEP antes de la serialización JSON en `cloudconfigurationd` resultó eficaz. El proceso implicó:

1. Adjuntarse a `cloudconfigurationd` mediante LLDB.
2. Localizar el punto en el que se obtiene el Serial Number del sistema.
3. Inyectar un Serial Number arbitrario en la memoria antes de que el payload se cifre y se envíe.

Este método permitió recuperar perfiles DEP completos para Serial Numbers arbitrarios, demostrando una posible vulnerabilidad.<sup>[1]</sup>

### Automatización de la instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que permitió inyectar Serial Numbers arbitrarios mediante programación y recuperar los perfiles DEP correspondientes.<sup>[1]</sup>

### Posibles impactos de las vulnerabilidades de DEP y MDM

La investigación destacó importantes problemas de seguridad:

1. **Divulgación de información**: Al proporcionar un Serial Number registrado en DEP, se puede recuperar información sensible de la organización contenida en el perfil DEP.<sup>[1]</sup>

## Referencias

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
