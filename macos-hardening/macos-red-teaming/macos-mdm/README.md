# macOS MDM

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Para aprender sobre los MDM de macOS, consulta:**

* [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
* [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Conceptos básicos

### **Visión general de MDM (Gestión de Dispositivos Móviles)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) se utiliza para gestionar varios dispositivos de usuarios finales como teléfonos inteligentes, computadoras portátiles y tabletas. Especialmente para las plataformas de Apple (iOS, macOS, tvOS), implica un conjunto de características especializadas, APIs y prácticas. El funcionamiento de MDM depende de un servidor MDM compatible, que puede ser comercial u open-source, y debe admitir el [Protocolo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Los puntos clave incluyen:

* Control centralizado sobre los dispositivos.
* Dependencia de un servidor MDM que cumpla con el protocolo MDM.
* Capacidad del servidor MDM para enviar varios comandos a los dispositivos, por ejemplo, borrado remoto de datos o instalación de configuraciones.

### **Conceptos básicos de DEP (Programa de Inscripción de Dispositivos)**

El [Programa de Inscripción de Dispositivos](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) ofrecido por Apple simplifica la integración de la Gestión de Dispositivos Móviles (MDM) al facilitar la configuración sin intervención para dispositivos iOS, macOS y tvOS. DEP automatiza el proceso de inscripción, permitiendo que los dispositivos estén operativos directamente desde la caja, con mínima intervención del usuario o administrativa. Aspectos esenciales incluyen:

* Permite que los dispositivos se registren automáticamente con un servidor MDM predefinido al activarse inicialmente.
* Beneficioso principalmente para dispositivos nuevos, pero también aplicable para dispositivos que se están reconfigurando.
* Facilita una configuración sencilla, haciendo que los dispositivos estén listos para su uso organizativo rápidamente.

### **Consideraciones de seguridad**

Es crucial tener en cuenta que la facilidad de inscripción proporcionada por DEP, aunque beneficiosa, también puede plantear riesgos de seguridad. Si no se aplican medidas de protección adecuadas para la inscripción en MDM, los atacantes podrían aprovechar este proceso simplificado para registrar su dispositivo en el servidor MDM de la organización, haciéndose pasar por un dispositivo corporativo.

{% hint style="danger" %}
**Alerta de seguridad**: La inscripción simplificada en DEP podría permitir potencialmente el registro de dispositivos no autorizados en el servidor MDM de la organización si no se implementan salvaguardias adecuadas.
{% endhint %}

### ¿Qué es SCEP (Protocolo de Inscripción de Certificados Simple)?

* Un protocolo relativamente antiguo, creado antes de que TLS y HTTPS fueran generalizados.
* Proporciona a los clientes una forma estandarizada de enviar una **Solicitud de Firma de Certificado** (CSR) con el fin de obtener un certificado. El cliente solicitará al servidor que le proporcione un certificado firmado.

### ¿Qué son los Perfiles de Configuración (también conocidos como mobileconfigs)?

* Forma oficial de Apple de **configurar/imponer la configuración del sistema.**
* Formato de archivo que puede contener múltiples cargas útiles.
* Basado en listas de propiedades (del tipo XML).
* "pueden ser firmados y cifrados para validar su origen, garantizar su integridad y proteger su contenido." Conceptos básicos — Página 70, Guía de Seguridad de iOS, enero de 2018.

## Protocolos

### MDM

* Combinación de APNs (**servidores de Apple**) + API RESTful (**servidores de proveedores de MDM**)
* La **comunicación** ocurre entre un **dispositivo** y un servidor asociado con un **producto de gestión de dispositivos**
* Los **comandos** se entregan desde el MDM al dispositivo en **diccionarios codificados en plist**
* Todo a través de **HTTPS**. Los servidores MDM pueden estar (y generalmente están) anclados.
* Apple otorga al proveedor de MDM un **certificado APNs** para autenticación

### DEP

* **3 APIs**: 1 para revendedores, 1 para proveedores de MDM, 1 para identidad de dispositivos (no documentada):
* La llamada [API de "servicio en la nube" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Esta es utilizada por los servidores de MDM para asociar perfiles DEP con dispositivos específicos.
* La [API DEP utilizada por los Revendedores Autorizados de Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscribir dispositivos, verificar el estado de inscripción y verificar el estado de transacción.
* La API DEP privada no documentada. Esta es utilizada por los Dispositivos Apple para solicitar su perfil DEP. En macOS, el binario `cloudconfigurationd` es responsable de comunicarse a través de esta API.
* Más moderno y basado en **JSON** (vs. plist)
* Apple otorga un **token OAuth** al proveedor de MDM

**API de "servicio en la nube" DEP**

* RESTful
* sincroniza registros de dispositivos de Apple al servidor de MDM
* sincroniza perfiles DEP a Apple desde el servidor de MDM (entregados por Apple al dispositivo más tarde)
* Un "perfil" DEP contiene:
* URL del servidor del proveedor de MDM
* Certificados de confianza adicionales para la URL del servidor (anclaje opcional)
* Configuraciones adicionales (por ejemplo, qué pantallas omitir en el Asistente de Configuración)

## Número de serie

Los dispositivos Apple fabricados después de 2010 generalmente tienen números de serie alfanuméricos de **12 caracteres**, con los **tres primeros dígitos representando la ubicación de fabricación**, los siguientes **dos** indicando el **año** y la **semana** de fabricación, los siguientes **tres** dígitos proporcionando un **identificador** **único**, y los **últimos** **cuatro** dígitos representando el **número de modelo**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Pasos para inscripción y gestión

1. Creación de registro de dispositivo (Revendedor, Apple): Se crea el registro para el nuevo dispositivo
2. Asignación de registro de dispositivo (Cliente): El dispositivo se asigna a un servidor MDM
3. Sincronización de registro de dispositivo (Proveedor de MDM): El MDM sincroniza los registros de dispositivos y envía los perfiles DEP a Apple
4. Registro DEP (Dispositivo): El dispositivo obtiene su perfil DEP
5. Recuperación de perfil (Dispositivo)
6. Instalación de perfil (Dispositivo) a. incl. cargas útiles de MDM, SCEP y CA raíz
7. Emisión de comandos de MDM (Dispositivo)

![](<../../../.gitbook/assets/image (694).png>)

El archivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funciones que pueden considerarse **pasos "de alto nivel"** del proceso de inscripción.
### Paso 4: Verificación de DEP - Obtención del Registro de Activación

Esta parte del proceso ocurre cuando un **usuario inicia un Mac por primera vez** (o después de un borrado completo)

![](<../../../.gitbook/assets/image (1044).png>)

o al ejecutar `sudo profiles show -type enrollment`

* Determinar si el dispositivo está habilitado para DEP
* Registro de Activación es el nombre interno para el **"perfil" DEP**
* Comienza tan pronto como el dispositivo se conecta a Internet
* Impulsado por **`CPFetchActivationRecord`**
* Implementado por **`cloudconfigurationd`** a través de XPC. El **"Asistente de Configuración"** (cuando el dispositivo se inicia por primera vez) o el comando **`profiles`** contactarán a este demonio para recuperar el registro de activación.
* LaunchDaemon (siempre se ejecuta como root)

Sigue algunos pasos para obtener el Registro de Activación realizado por **`MCTeslaConfigurationFetcher`**. Este proceso utiliza una encriptación llamada **Absinthe**

1. Recuperar el **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** el estado desde el certificado (**`NACInit`**)
1. Utiliza varios datos específicos del dispositivo (por ejemplo, **Número de Serie a través de `IOKit`**)
3. Recuperar la **clave de sesión**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establecer la sesión (**`NACKeyEstablishment`**)
5. Realizar la solicitud
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando los datos `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. La carga JSON está encriptada usando Absinthe (**`NACSign`**)
3. Todas las solicitudes son a través de HTTPs, se utilizan certificados raíz integrados

![](<../../../.gitbook/assets/image (566) (1).png>)

La respuesta es un diccionario JSON con algunos datos importantes como:

* **url**: URL del host del proveedor de MDM para el perfil de activación
* **anchor-certs**: Array de certificados DER utilizados como anclas de confianza

### **Paso 5: Recuperación del Perfil**

![](<../../../.gitbook/assets/image (444).png>)

* Solicitud enviada a la **URL proporcionada en el perfil DEP**.
* Se utilizan **certificados de anclaje** para **evaluar la confianza** si se proporcionan.
* Recordatorio: la propiedad **anchor\_certs** del perfil DEP
* La **solicitud es un simple .plist** con identificación del dispositivo
* Ejemplos: **UDID, versión de SO**.
* Firmado por CMS, codificado en DER
* Firmado usando el **certificado de identidad del dispositivo (de APNS)**
* La **cadena de certificados** incluye el **Apple iPhone Device CA** caducado

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Paso 6: Instalación del Perfil

* Una vez recuperado, **el perfil se almacena en el sistema**
* Este paso comienza automáticamente (si está en el **asistente de configuración**)
* Impulsado por **`CPInstallActivationProfile`**
* Implementado por mdmclient a través de XPC
* LaunchDaemon (como root) o LaunchAgent (como usuario), dependiendo del contexto
* Los perfiles de configuración tienen múltiples cargas útiles para instalar
* El framework tiene una arquitectura basada en complementos para instalar perfiles
* Cada tipo de carga útil está asociado con un complemento
* Puede ser XPC (en el framework) o Cocoa clásico (en ManagedClient.app)
* Ejemplo:
* Las Cargas de Certificado utilizan CertificateService.xpc

Típicamente, el **perfil de activación** proporcionado por un proveedor de MDM incluirá las siguientes cargas útiles:

* `com.apple.mdm`: para **inscribir** el dispositivo en MDM
* `com.apple.security.scep`: para proporcionar de forma segura un **certificado de cliente** al dispositivo.
* `com.apple.security.pem`: para **instalar certificados CA confiables** en el Llavero del Sistema del dispositivo.
* Instalando la carga útil de MDM equivalente a **MDM check-in en la documentación**
* La carga útil **contiene propiedades clave**:
*
* URL de Check-In de MDM (**`CheckInURL`**)
* URL de Sondeo de Comandos de MDM (**`ServerURL`**) + tema de APNs para activarlo
* Para instalar la carga útil de MDM, se envía una solicitud a **`CheckInURL`**
* Implementado en **`mdmclient`**
* La carga útil de MDM puede depender de otras cargas útiles
* Permite **anclar las solicitudes a certificados específicos**:
* Propiedad: **`CheckInURLPinningCertificateUUIDs`**
* Propiedad: **`ServerURLPinningCertificateUUIDs`**
* Entregado a través de la carga PEM
* Permite atribuir al dispositivo un certificado de identidad:
* Propiedad: IdentityCertificateUUID
* Entregado a través de la carga SCEP

### **Paso 7: Escuchando los comandos de MDM**

Después de que se complete el check-in de MDM, el proveedor puede **emitir notificaciones push usando APNs**
Al recibirlas, son manejadas por **`mdmclient`**
Para sondear los comandos de MDM, se envía una solicitud a ServerURL
Hace uso de la carga útil de MDM previamente instalada:
**`ServerURLPinningCertificateUUIDs`** para anclar la solicitud
**`IdentityCertificateUUID`** para el certificado de cliente TLS

## Ataques

### Inscripción de Dispositivos en Otras Organizaciones

Como se mencionó anteriormente, para intentar inscribir un dispositivo en una organización **solo se necesita un Número de Serie perteneciente a esa Organización**. Una vez que el dispositivo está inscrito, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y más](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Por lo tanto, este podría ser un punto de entrada peligroso para los atacantes si el proceso de inscripción no está protegido correctamente:

{% content-ref url="enrolling-devices-in-other-organisations.md" %}
[enrolling-devices-in-other-organisations.md](enrolling-devices-in-other-organisations.md)
{% endcontent-ref %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
