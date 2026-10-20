# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para aprender sobre macOS MDM, consulta:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Conceptos básicos

### **Descripción general de MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) se utiliza para administrar diversos dispositivos de usuarios finales, como smartphones, laptops y tablets. En particular, en las plataformas de Apple (iOS, macOS, tvOS), comprende un conjunto de funciones, APIs y prácticas especializadas. El funcionamiento de MDM depende de un servidor MDM compatible, que puede ser comercial o de código abierto, y debe admitir el [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Puntos clave:

- Control centralizado de los dispositivos.
- Dependencia de un servidor MDM que cumpla con el protocolo MDM.
- Capacidad del servidor MDM para enviar distintos comandos a los dispositivos, como el borrado remoto de datos o la instalación de configuraciones.

### **Conceptos básicos de DEP (Device Enrollment Program)**

El [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) ofrecido por Apple simplifica la integración de Mobile Device Management (MDM) al facilitar la configuración sin intervención del usuario (zero-touch) de dispositivos iOS, macOS y tvOS. DEP automatiza el proceso de inscripción, lo que permite que los dispositivos estén operativos desde el primer momento, con una intervención mínima del usuario o del administrador. Aspectos esenciales:

- Permite que los dispositivos se registren automáticamente con un servidor MDM predefinido durante la activación inicial.
- Es principalmente útil para dispositivos nuevos, pero también se aplica a dispositivos que se están reconfigurando.
- Facilita una configuración sencilla para que los dispositivos estén listos rápidamente para su uso en la organización.

### **Consideraciones de seguridad**

Es importante tener en cuenta que la facilidad de inscripción que ofrece DEP, aunque es beneficiosa, también puede presentar riesgos de seguridad. Si no se aplican las medidas de protección adecuadas para la inscripción MDM, los atacantes podrían aprovechar este proceso simplificado para registrar su dispositivo en el servidor MDM de la organización, haciéndolo pasar por un dispositivo corporativo.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerta de seguridad**: La inscripción simplificada de DEP podría permitir el registro de dispositivos no autorizados en el servidor MDM de la organización si no se implementan las medidas de protección adecuadas.

### Conceptos básicos: ¿Qué es SCEP (Simple Certificate Enrolment Protocol)?

- Un protocolo relativamente antiguo, creado antes de que TLS y HTTPS fueran de uso generalizado.
- Ofrece a los clientes una forma estandarizada de enviar una **Certificate Signing Request** (CSR) para obtener un certificado. El cliente solicita al servidor que le entregue un certificado firmado.

### ¿Qué son los Configuration Profiles (también llamados mobileconfigs)?

- La forma oficial de Apple de **establecer y aplicar la configuración del sistema**.
- Formato de archivo que puede contener varias cargas útiles.
- Basado en property lists (del tipo XML).
- «se pueden firmar y cifrar para validar su origen, garantizar su integridad y proteger su contenido». Conceptos básicos — página 70, Guía de seguridad de iOS, enero de 2018.

## Protocolos

### MDM

- Combinación de APNs (servidores de **Apple**) + API RESTful (servidores de **proveedores** de **MDM**)
- La **comunicación** se produce entre un **dispositivo** y un servidor asociado a un **producto** de **administración** de **dispositivos**
- **Comandos** enviados desde MDM al dispositivo en **diccionarios codificados como plist**
- Todo a través de **HTTPS**. Los servidores MDM pueden usar certificate pinning (y suelen hacerlo).
- Apple concede al proveedor de MDM un **certificado APNs** para la autenticación

### DEP

- **3 APIs**: 1 para revendedores, 1 para proveedores de MDM y 1 para la identidad del dispositivo (no documentada):
  - La llamada API de [DEP "cloud service"](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Los servidores MDM la utilizan para asociar perfiles DEP con dispositivos específicos.
  - La [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscribir dispositivos y comprobar el estado de inscripción y de las transacciones.
  - La API DEP privada no documentada. Los dispositivos Apple la utilizan para solicitar su perfil DEP. En macOS, el binario `cloudconfigurationd` se encarga de comunicarse mediante esta API.
- Más moderno y basado en **JSON** (en lugar de plist)
- Apple concede un **token OAuth** al proveedor de MDM

**API de DEP "cloud service"**

- RESTful
- sincroniza los registros de dispositivos de Apple con el servidor MDM
- sincroniza los «perfiles DEP» del servidor MDM con Apple (Apple los entrega posteriormente al dispositivo)
- Un «perfil» DEP contiene:
  - URL del servidor del proveedor de MDM
  - Certificados de confianza adicionales para la URL del servidor (certificate pinning opcional)
  - Configuración adicional (por ejemplo, qué pantallas omitir en Setup Assistant)

## Número de serie

Los dispositivos Apple fabricados después de 2010 suelen tener números de serie **alfanuméricos de 12 caracteres**: los **tres primeros dígitos representan el lugar de fabricación**, los **dos** siguientes indican el **año** y la **semana** de fabricación, los **tres** siguientes proporcionan un **identificador** único y los **últimos cuatro dígitos** representan el **número de modelo**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Pasos para la inscripción y la administración

1. Creación del registro del dispositivo (revendedor, Apple): Se crea el registro del nuevo dispositivo
2. Asignación del registro del dispositivo (cliente): El dispositivo se asigna a un servidor MDM
3. Sincronización del registro del dispositivo (proveedor de MDM): MDM sincroniza los registros del dispositivo y envía los perfiles DEP a Apple
4. Registro en DEP (dispositivo): El dispositivo obtiene su perfil DEP
5. Recuperación del perfil (dispositivo)
6. Instalación del perfil (dispositivo), incluidas las cargas útiles de MDM, SCEP y CA raíz
7. Emisión de comandos MDM (dispositivo)

![Número de serie: pasos para la inscripción y la administración: 7. Emisión de comandos MDM (dispositivo)](<../../../images/image (694).png>)

El archivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funciones que pueden considerarse **«pasos» de alto nivel** del proceso de inscripción.

### Paso 4: Registro en DEP: obtención del Activation Record

Esta parte del proceso ocurre cuando un **usuario inicia un Mac por primera vez** (o después de borrarlo por completo)

![Pasos para la inscripción y la administración - Paso 4: Registro en DEP: obtención del Activation Record: esta parte del proceso ocurre cuando un usuario inicia un Mac por primera vez (o después de borrarlo por completo...](<../../../images/image (1044).png>)

o al ejecutar `sudo profiles show -type enrollment`

- Determina **si el dispositivo está habilitado para DEP**
- Activation Record es el nombre interno del **«perfil» DEP**
- Comienza en cuanto el dispositivo se conecta a Internet
- Se ejecuta mediante **`CPFetchActivationRecord`**
- Lo implementa **`cloudconfigurationd`** mediante XPC. **Setup Assistant** (cuando se inicia el dispositivo por primera vez) o el comando **`profiles`** se ponen en contacto con este daemon para recuperar el Activation Record.
  - LaunchDaemon (siempre se ejecuta como root)

Para obtener el Activation Record, **`MCTeslaConfigurationFetcher`** realiza varios pasos. Este proceso utiliza un cifrado llamado **Absinthe**<sup>[[1]](#references)</sup>

1. Recuperar el **certificado**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** el estado a partir del certificado (**`NACInit`**)
   1. Utiliza diversos datos específicos del dispositivo (es decir, el **número de serie mediante `IOKit`**)
3. Recuperar la **clave de sesión**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establecer la sesión (**`NACKeyEstablishment`**)
5. Realizar la solicitud
   1. Enviar un POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) con los datos `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. La carga útil JSON se cifra con Absinthe (**`NACSign`**)
   3. Todas las solicitudes se realizan mediante HTTPS y utilizan los certificados raíz integrados

![Pasos para la inscripción y la administración - Paso 4: Registro en DEP: obtención del Activation Record: 3. Todas las solicitudes se realizan mediante HTTPS y utilizan los certificados raíz integrados](<../../../images/image (566) (1).png>)

La respuesta es un diccionario JSON con datos importantes, como:

- **url**: URL del host del proveedor de MDM para el perfil de activación
- **anchor-certs**: Array de certificados DER que se utilizan como anclas de confianza

### **Paso 5: Recuperación del perfil**

![Paso 4: Registro en DEP: obtención del Activation Record - Paso 5: Recuperación del perfil: Paso 5: Recuperación del perfil](<../../../images/image (444).png>)

- Solicitud enviada a la **url proporcionada en el perfil DEP**.
- Si se proporcionan, los **certificados de anclaje** se utilizan para **evaluar la confianza**.
  - Recordatorio: la propiedad **anchor_certs** del perfil DEP
- La **solicitud es un .plist simple** con la identificación del dispositivo
  - Ejemplos: **UDID, versión del sistema operativo**.
- Firmado con CMS y codificado en DER
- Firmado con el **certificado de identidad del dispositivo (de APNS)**
- La **cadena de certificados** incluye el certificado **Apple iPhone Device CA** caducado

![Paso 4: Registro en DEP: obtención del Activation Record - Paso 5: Recuperación del perfil: firmado con el certificado de identidad del dispositivo (de APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Paso 6: Instalación del perfil

- Una vez recuperado, **el perfil se almacena en el sistema**
- Este paso comienza automáticamente (si se está en **Setup Assistant**)
- Se ejecuta mediante **`CPInstallActivationProfile`**
- Lo implementa mdmclient mediante XPC
  - LaunchDaemon (como root) o LaunchAgent (como usuario), según el contexto
- Los Configuration Profiles contienen varias cargas útiles que se deben instalar
- El framework tiene una arquitectura basada en plugins para instalar perfiles
- Cada tipo de carga útil está asociado a un plugin
  - Puede ser XPC (en el framework) o Cocoa clásico (en ManagedClient.app)
- Ejemplo:
  - Las cargas útiles de certificados utilizan CertificateService.xpc

Normalmente, el **perfil de activación** proporcionado por un proveedor de MDM **incluirá las siguientes cargas útiles**:

- `com.apple.mdm`: para **inscribir** el dispositivo en MDM
- `com.apple.security.scep`: para proporcionar de forma segura un **certificado de cliente** al dispositivo.
- `com.apple.security.pem`: para **instalar certificados CA de confianza** en el System Keychain del dispositivo.
- La instalación de la carga útil de MDM equivale al **registro en MDM descrito en la documentación**
- La carga útil **contiene propiedades clave**:
- - URL de registro de MDM (**`CheckInURL`**)
  - URL de consulta de comandos MDM (**`ServerURL`**) + tema APNs para activarla
- Para instalar la carga útil de MDM, se envía una solicitud a **`CheckInURL`**
- Se implementa en **`mdmclient`**
- La carga útil de MDM puede depender de otras cargas útiles
- Permite **fijar las solicitudes a certificados específicos**:
  - Propiedad: **`CheckInURLPinningCertificateUUIDs`**
  - Propiedad: **`ServerURLPinningCertificateUUIDs`**
  - Se entrega mediante la carga útil PEM
- Permite asignar al dispositivo un certificado de identidad:
  - Propiedad: IdentityCertificateUUID
  - Se entrega mediante la carga útil SCEP

### **Paso 7: Esperar comandos MDM**

- Una vez completado el registro en MDM, el proveedor puede **enviar notificaciones push mediante APNs**
- Al recibirlas, las procesa **`mdmclient`**
- Para consultar los comandos MDM, se envía una solicitud a ServerURL
- Utiliza la carga útil MDM instalada previamente:
  - **`ServerURLPinningCertificateUUIDs`** para fijar la solicitud
  - **`IdentityCertificateUUID`** para el certificado de cliente TLS

## Ataques

### Inscribir dispositivos en otras organizaciones

Un número de serie asignado puede identificar la ruta de inscripción de la organización, pero **no** garantiza la inscripción en MDM. El servidor puede exigir que el usuario se autentique mediante `configuration_web_url` antes de devolver el perfil de inscripción. Comprueba si existe una ruta de inscripción alternativa que omita esa verificación, en lugar de asumir que cualquier número de serie asignado puede unirse a la flota.<sup>[[3]](#references)</sup>

Para un flujo de trabajo de inscripción fraudulenta, utiliza la página enlazada a continuación. Para el control de MDM y la distribución de paquetes después de una intrusión, consulta [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [Análisis profundo de macOS MDM (y cómo puede verse comprometido)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — «¿MDM, quizá?» (investigación sobre la seguridad de la inscripción DEP/MDM)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Autenticación mediante vistas web](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
