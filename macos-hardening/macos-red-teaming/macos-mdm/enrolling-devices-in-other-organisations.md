# Inscripción de Dispositivos en Otras Organizaciones

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

Como se mencionó [**anteriormente**](./#what-is-mdm-mobile-device-management), para intentar inscribir un dispositivo en una organización **solo se necesita un Número de Serie perteneciente a esa Organización**. Una vez que el dispositivo está inscrito, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y más](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por lo tanto, este podría ser un punto de entrada peligroso para los atacantes si el proceso de inscripción no está protegido correctamente.

**Lo siguiente es un resumen de la investigación [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). ¡Consultarla para más detalles técnicos!**

## Resumen del Análisis Binario de DEP y MDM

Esta investigación profundiza en los binarios asociados con el Programa de Inscripción de Dispositivos (DEP) y la Gestión de Dispositivos Móviles (MDM) en macOS. Los componentes clave incluyen:

- **`mdmclient`**: Comunica con servidores MDM y activa los registros DEP en versiones de macOS anteriores a 10.13.4.
- **`profiles`**: Gestiona Perfiles de Configuración y activa los registros DEP en versiones de macOS 10.13.4 y posteriores.
- **`cloudconfigurationd`**: Gestiona las comunicaciones de la API DEP y recupera perfiles de Inscripción de Dispositivos.

Los registros DEP utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` del framework privado de Perfiles de Configuración para recuperar el Registro de Activación, con `CPFetchActivationRecord` coordinando con `cloudconfigurationd` a través de XPC.

## Ingeniería Inversa del Protocolo Tesla y del Esquema Absinthe

El registro DEP implica que `cloudconfigurationd` envíe una carga JSON encriptada y firmada a _iprofiles.apple.com/macProfile_. La carga incluye el número de serie del dispositivo y la acción "RequestProfileConfiguration". El esquema de encriptación utilizado se conoce internamente como "Absinthe". Descifrar este esquema es complejo e implica numerosos pasos, lo que llevó a explorar métodos alternativos para insertar números de serie arbitrarios en la solicitud de Registro de Activación.

## Proxy de Solicitudes DEP

Los intentos de interceptar y modificar las solicitudes DEP a _iprofiles.apple.com_ utilizando herramientas como Charles Proxy se vieron obstaculizados por la encriptación de la carga útil y las medidas de seguridad SSL/TLS. Sin embargo, habilitar la configuración `MCCloudConfigAcceptAnyHTTPSCertificate` permite evitar la validación del certificado del servidor, aunque la naturaleza encriptada de la carga útil aún impide la modificación del número de serie sin la clave de descifrado.

## Instrumentación de Binarios del Sistema que Interactúan con DEP

Instrumentar binarios del sistema como `cloudconfigurationd` requiere desactivar la Protección de la Integridad del Sistema (SIP) en macOS. Con SIP desactivado, se pueden usar herramientas como LLDB para adjuntarse a procesos del sistema y potencialmente modificar el número de serie utilizado en las interacciones de la API DEP. Este método es preferible ya que evita las complejidades de los permisos y la firma de código.

**Explotando la Instrumentación Binaria:**
Modificar la carga útil de la solicitud DEP antes de la serialización JSON en `cloudconfigurationd` resultó efectivo. El proceso implicó:

1. Adjuntar LLDB a `cloudconfigurationd`.
2. Localizar el punto donde se obtiene el número de serie del sistema.
3. Inyectar un número de serie arbitrario en la memoria antes de que la carga útil se encripte y envíe.

Este método permitió recuperar perfiles DEP completos para números de serie arbitrarios, demostrando una vulnerabilidad potencial.

### Automatización de la Instrumentación con Python

El proceso de explotación se automatizó utilizando Python con la API de LLDB, lo que permitió inyectar programáticamente números de serie arbitrarios y recuperar perfiles DEP correspondientes.

### Impactos Potenciales de las Vulnerabilidades de DEP y MDM

La investigación destacó preocupaciones de seguridad significativas:

1. **Divulgación de Información**: Al proporcionar un número de serie registrado en DEP, se puede recuperar información organizativa sensible contenida en el perfil DEP.
2. **Inscripción de DEP Malintencionada**: Sin una autenticación adecuada, un atacante con un número de serie registrado en DEP puede inscribir un dispositivo malintencionado en el servidor MDM de una organización, potencialmente obteniendo acceso a datos sensibles y recursos de red.

En conclusión, aunque DEP y MDM proporcionan herramientas poderosas para gestionar dispositivos Apple en entornos empresariales, también presentan posibles vectores de ataque que deben ser asegurados y monitoreados.
