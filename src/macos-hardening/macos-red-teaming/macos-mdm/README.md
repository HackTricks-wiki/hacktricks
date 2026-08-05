# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Para aprender sobre macOS MDMs, consulta:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Conceptos básicos

### **Descripción general de MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) se utiliza para supervisar varios dispositivos de usuario final, como smartphones, laptops y tablets. En particular, para las plataformas de Apple (iOS, macOS, tvOS), implica un conjunto de características, APIs y prácticas especializadas. El funcionamiento de MDM depende de un servidor MDM compatible, disponible comercialmente o como open-source, que debe admitir el [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Puntos clave:

- Control centralizado sobre los dispositivos.
- Dependencia de un servidor MDM que cumpla el protocolo MDM.
- Capacidad del servidor MDM para enviar varios comandos a los dispositivos, como el borrado remoto de datos o la instalación de configuraciones.

### **Conceptos básicos de DEP (Device Enrollment Program)**

El [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) ofrecido por Apple simplifica la integración de Mobile Device Management (MDM) al facilitar la configuración zero-touch de dispositivos iOS, macOS y tvOS. DEP automatiza el proceso de inscripción, permitiendo que los dispositivos estén operativos nada más sacarlos de la caja, con una intervención mínima del usuario o del administrador. Aspectos esenciales:

- Permite que los dispositivos se registren automáticamente en un servidor MDM predefinido durante la activación inicial.
- Es principalmente beneficioso para dispositivos nuevos, pero también se aplica a dispositivos que están siendo reconfigurados.
- Facilita una configuración sencilla, haciendo que los dispositivos estén preparados rápidamente para su uso en la organización.

### **Consideraciones de seguridad**

Es crucial tener en cuenta que la facilidad de inscripción proporcionada por DEP, aunque resulta beneficiosa, también puede plantear riesgos de seguridad. Si no se aplican adecuadamente las medidas de protección para la inscripción en MDM, los atacantes podrían explotar este proceso simplificado para registrar su dispositivo en el servidor MDM de la organización, haciéndolo pasar por un dispositivo corporativo.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Alerta de seguridad**: La inscripción DEP simplificada podría permitir potencialmente el registro no autorizado de dispositivos en el servidor MDM de la organización si no existen las medidas de protección adecuadas.

### Conceptos básicos: ¿Qué es SCEP (Simple Certificate Enrolment Protocol)?

- Un protocolo relativamente antiguo, creado antes de que TLS y HTTPS estuvieran ampliamente extendidos.
- Proporciona a los clientes una forma estandarizada de enviar una **Certificate Signing Request** (CSR) con el objetivo de obtener un certificado. El cliente solicita al servidor que le proporcione un certificado firmado.

### ¿Qué son los Configuration Profiles (también conocidos como mobileconfigs)?

- La forma oficial de Apple de **establecer/aplicar la configuración del sistema.**
- Formato de archivo que puede contener múltiples payloads.
- Basado en property lists (del tipo XML).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protocolos

### MDM

- Combinación de APNs (**Apple server**s) + RESTful API (servidores del **vendor** de **MDM**)
- La **comunicación** se produce entre un **dispositivo** y un servidor asociado a un **producto** de **gestión** de **dispositivos**
- Los **comandos** se envían desde MDM al dispositivo en **diccionarios codificados en plist**
- Todo sobre **HTTPS**. Los servidores MDM pueden estar (y normalmente están) pinned.
- Apple proporciona al vendor de MDM un **certificado APNs** para la autenticación

### DEP

- **3 APIs**: 1 para resellers, 1 para vendors de MDM y 1 para la identidad del dispositivo (no documentada):
- La denominada [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Los servidores MDM la utilizan para asociar perfiles DEP con dispositivos específicos.
- La [DEP API utilizada por Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscribir dispositivos, comprobar el estado de inscripción y comprobar el estado de las transacciones.
- La API privada DEP no documentada. Apple Devices la utiliza para solicitar su perfil DEP. En macOS, el binario `cloudconfigurationd` se encarga de comunicarse mediante esta API.
- Más moderna y basada en **JSON** (frente a plist)
- Apple proporciona un **OAuth token** al vendor de MDM

**DEP "cloud service" API**

- RESTful
- sincroniza los registros de dispositivos de Apple con el servidor MDM
- sincroniza los “perfiles DEP” del servidor MDM con Apple (Apple los entrega posteriormente al dispositivo)
- Un “perfil” DEP contiene:
- URL del servidor del vendor de MDM
- Certificados trusted adicionales para la URL del servidor (pinning opcional)
- Configuración adicional (por ejemplo, qué pantallas omitir en Setup Assistant)

## Número de serie

Los dispositivos Apple fabricados después de 2010 generalmente tienen números de serie **alfanuméricos de 12 caracteres**, donde **los tres primeros dígitos representan el lugar de fabricación**, los **dos siguientes** indican el **año** y la **semana** de fabricación, los **tres dígitos siguientes** proporcionan un **identificador** **único** y los **últimos** **cuatro** dígitos representan el **número de modelo**.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Pasos para la inscripción y la gestión

1. Creación del registro del dispositivo (Reseller, Apple): Se crea el registro del dispositivo nuevo
2. Asignación del registro del dispositivo (Customer): El dispositivo se asigna a un servidor MDM
3. Sincronización del registro del dispositivo (vendor de MDM): MDM sincroniza los registros de dispositivos y envía los perfiles DEP a Apple
4. DEP check-in (dispositivo): El dispositivo obtiene su perfil DEP
5. Recuperación del perfil (dispositivo)
6. Instalación del perfil (dispositivo), incluyendo payloads MDM, SCEP y root CA
7. Emisión de comandos MDM (dispositivo)

![Número de serie - Pasos para la inscripción y la gestión: 7. Emisión de comandos MDM (dispositivo)](<../../../images/image (694).png>)

El archivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funciones que pueden considerarse **"pasos" de alto nivel** del proceso de inscripción.

### Paso 4: DEP check-in - Obtención del Activation Record

Esta parte del proceso ocurre cuando un **usuario inicia un Mac por primera vez** (o después de un borrado completo)

![Pasos para la inscripción y la gestión - Paso 4: DEP check-in - Obtención del Activation Record: Esta parte del proceso ocurre cuando un usuario inicia un Mac por primera vez (o después de un...](<../../../images/image (1044).png>)

o al ejecutar `sudo profiles show -type enrollment`

- Determina **si el dispositivo está habilitado para DEP**
- Activation Record es el nombre interno del **“perfil” DEP**
- Comienza en cuanto el dispositivo se conecta a Internet
- Está controlado por **`CPFetchActivationRecord`**
- Lo implementa **`cloudconfigurationd`** mediante XPC. **Setup Assistant** (cuando el dispositivo se inicia por primera vez) o el comando **`profiles`** se pondrán en contacto con este daemon para recuperar el activation record.
- LaunchDaemon (se ejecuta siempre como root)

La obtención del Activation Record sigue varios pasos realizados por **`MCTeslaConfigurationFetcher`**. Este proceso utiliza un cifrado llamado **Absinthe**<sup>[[1]](#references)</sup>

1. Recuperar el **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** el estado a partir del certificado (**`NACInit`**)
1. Utiliza varios datos específicos del dispositivo (es decir, el **número de serie mediante `IOKit`**)
3. Recuperar la **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establecer la sesión (**`NACKeyEstablishment`**)
5. Realizar la solicitud
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando los datos `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. El payload JSON se cifra mediante Absinthe (**`NACSign`**)
3. Todas las solicitudes se realizan sobre HTTPs y se utilizan los certificados root integrados

![Pasos para la inscripción y la gestión - Paso 4: DEP check-in - Obtención del Activation Record: 3. Todas las solicitudes se realizan sobre HTTPs y se utilizan los certificados root integrados](<../../../images/image (566) (1).png>)

La respuesta es un diccionario JSON con algunos datos importantes, como:

- **url**: URL del host del vendor de MDM para el activation profile
- **anchor-certs**: Array de certificados DER utilizados como anchors de confianza

### **Paso 5: Recuperación del perfil**

![Paso 4: DEP check-in - Obtención del Activation Record - Paso 5: Recuperación del perfil: Paso 5: Recuperación del perfil](<../../../images/image (444).png>)

- Solicitud enviada a la **url proporcionada en el perfil DEP**.
- Los **certificados anchor** se utilizan para **evaluar la confianza** si se proporcionan.
- Recordatorio: la propiedad **anchor_certs** del perfil DEP
- La **solicitud es un .plist simple** con la identificación del dispositivo
- Ejemplos: **UDID, versión del sistema operativo**.
- Firmado mediante CMS y codificado en DER
- Firmado utilizando el **certificado de identidad del dispositivo (de APNS)**
- La **cadena de certificados** incluye el **Apple iPhone Device CA** expirado

![Paso 4: DEP check-in - Obtención del Activation Record - Paso 5: Recuperación del perfil: Firmado utilizando el certificado de identidad del dispositivo (de APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Paso 6: Instalación del perfil

- Una vez recuperado, el **perfil se almacena en el sistema**
- Este paso comienza automáticamente (si se encuentra en **Setup Assistant**)
- Está controlado por **`CPInstallActivationProfile`**
- Lo implementa mdmclient mediante XPC
- LaunchDaemon (como root) o LaunchAgent (como usuario), según el contexto
- Los Configuration Profiles tienen múltiples payloads que instalar
- El framework tiene una arquitectura basada en plugins para instalar perfiles
- Cada tipo de payload está asociado a un plugin
- Puede ser XPC (en el framework) o Cocoa clásico (en ManagedClient.app)
- Ejemplo:
- Los Certificate Payloads utilizan CertificateService.xpc

Normalmente, el **activation profile** proporcionado por un vendor de MDM **incluirá los siguientes payloads**:

- `com.apple.mdm`: para **inscribir** el dispositivo en MDM
- `com.apple.security.scep`: para proporcionar de forma segura un **certificado de cliente** al dispositivo.
- `com.apple.security.pem`: para **instalar certificados CA de confianza** en el System Keychain del dispositivo.
- Instalación del payload MDM equivalente al **MDM check-in en la documentación**
- El payload **contiene propiedades clave**:
- - URL de MDM Check-In (**`CheckInURL`**)
- URL de MDM Command Polling (**`ServerURL`**) + topic de APNs para activarla
- Para instalar el payload MDM, se envía una solicitud a **`CheckInURL`**
- Implementado en **`mdmclient`**
- El payload MDM puede depender de otros payloads
- Permite que las **solicitudes estén pinned a certificados específicos**:
- Propiedad: **`CheckInURLPinningCertificateUUIDs`**
- Propiedad: **`ServerURLPinningCertificateUUIDs`**
- Entregado mediante un payload PEM
- Permite atribuir al dispositivo un certificado de identidad:
- Propiedad: IdentityCertificateUUID
- Entregado mediante un payload SCEP

### **Paso 7: Escucha de comandos MDM**

- Una vez completado el MDM check-in, el vendor puede **emitir push notifications mediante APNs**
- Al recibirse, son gestionadas por **`mdmclient`**
- Para consultar los comandos MDM, se envía una solicitud a ServerURL
- Utiliza el payload MDM instalado previamente:
- **`ServerURLPinningCertificateUUIDs`** para hacer pinning de la solicitud
- **`IdentityCertificateUUID`** para el certificado de cliente TLS

## Ataques

### Inscripción de dispositivos en otras organizaciones

Como se ha comentado anteriormente, para intentar inscribir un dispositivo en una organización **solo se necesita un número de serie perteneciente a esa organización**. Una vez inscrito el dispositivo, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas WiFi, configuraciones VPN [y demás](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por tanto, esto podría ser un punto de entrada peligroso para los atacantes si el proceso de inscripción no está protegido correctamente:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Referencias

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
