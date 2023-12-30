# macOS MDM

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Conceptos básicos

### ¿Qué es MDM (Gestión de Dispositivos Móviles)?

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) es una tecnología comúnmente utilizada para **administrar dispositivos de computación de usuarios finales** como teléfonos móviles, portátiles, escritorios y tabletas. En el caso de plataformas de Apple como iOS, macOS y tvOS, se refiere a un conjunto específico de características, APIs y técnicas utilizadas por los administradores para gestionar estos dispositivos. La gestión de dispositivos a través de MDM requiere un servidor MDM comercial o de código abierto compatible que implemente soporte para el [Protocolo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf).

* Una forma de lograr una **gestión centralizada de dispositivos**
* Requiere un **servidor MDM** que implemente soporte para el protocolo MDM
* El servidor MDM puede **enviar comandos MDM**, como borrado remoto o "instalar esta configuración"

### Conceptos básicos ¿Qué es DEP (Programa de Inscripción de Dispositivos)?

El [Programa de Inscripción de Dispositivos](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) es un servicio ofrecido por Apple que **simplifica** la inscripción en la Gestión de Dispositivos Móviles (MDM) ofreciendo una configuración **sin intervención** de dispositivos iOS, macOS y tvOS. A diferencia de los métodos de despliegue más tradicionales, que requieren que el usuario final o el administrador tomen medidas para configurar un dispositivo o inscribirse manualmente con un servidor MDM, DEP tiene como objetivo iniciar este proceso, **permitiendo al usuario desempaquetar un nuevo dispositivo de Apple y tenerlo configurado para su uso en la organización casi inmediatamente**.

Los administradores pueden aprovechar DEP para inscribir automáticamente los dispositivos en el servidor MDM de su organización. Una vez que un dispositivo está inscrito, **en muchos casos se trata como un dispositivo "confiable"** propiedad de la organización, y podría recibir cualquier número de certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y así sucesivamente](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).

* Permite que un dispositivo se inscriba automáticamente en un servidor MDM preconfigurado la **primera vez que se enciende**
* Más útil cuando el **dispositivo** es **completamente nuevo**
* También puede ser útil para flujos de trabajo de **reaprovisionamiento** (**borrado** con una instalación nueva del sistema operativo)

{% hint style="danger" %}
Desafortunadamente, si una organización no ha tomado medidas adicionales para **proteger su inscripción en MDM**, un proceso de inscripción simplificado para el usuario final a través de DEP también puede significar un proceso simplificado para que los **atacantes inscriban un dispositivo de su elección en el servidor MDM de la organización**, asumiendo la "identidad" de un dispositivo corporativo.
{% endhint %}

### Conceptos básicos ¿Qué es SCEP (Protocolo Simple de Inscripción de Certificados)?

* Un protocolo relativamente antiguo, creado antes de que TLS y HTTPS estuvieran generalizados.
* Ofrece a los clientes una forma estandarizada de enviar una **Solicitud de Firma de Certificado** (CSR) con el propósito de obtener un certificado. El cliente pedirá al servidor que le otorgue un certificado firmado.

### ¿Qué son los Perfiles de Configuración (también conocidos como mobileconfigs)?

* La forma oficial de Apple de **establecer/aplicar la configuración del sistema.**
* Formato de archivo que puede contener múltiples cargas útiles.
* Basado en listas de propiedades (del tipo XML).
* "puede ser firmado y cifrado para validar su origen, asegurar su integridad y proteger su contenido." Conceptos básicos — Página 70, Guía de Seguridad de iOS, enero de 2018.

## Protocolos

### MDM

* Combinación de APNs (**servidores de Apple**) + API RESTful (**servidores de proveedores de MDM**)
* La **comunicación** ocurre entre un **dispositivo** y un servidor asociado con un **producto de gestión de dispositivos**
* **Comandos** entregados desde el MDM al dispositivo en **diccionarios codificados en plist**
* Todo sobre **HTTPS**. Los servidores MDM pueden ser (y usualmente son) fijados.
* Apple otorga al proveedor de MDM un **certificado APNs** para autenticación

### DEP

* **3 APIs**: 1 para revendedores, 1 para proveedores de MDM, 1 para identidad del dispositivo (no documentada):
* La llamada [API de "servicio en la nube" de DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Esta es utilizada por los servidores MDM para asociar perfiles DEP con dispositivos específicos.
* La [API de DEP utilizada por Revendedores Autorizados de Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscribir dispositivos, verificar el estado de inscripción y verificar el estado de la transacción.
* La API privada de DEP no documentada. Esta es utilizada por Dispositivos Apple para solicitar su perfil DEP. En macOS, el binario `cloudconfigurationd` es responsable de comunicarse a través de esta API.
* Más moderna y basada en **JSON** (en comparación con plist)
* Apple otorga un **token OAuth** al proveedor de MDM

**API de "servicio en la nube" de DEP**

* RESTful
* sincroniza registros de dispositivos de Apple al servidor MDM
* sincroniza "perfiles DEP" a Apple desde el servidor MDM (entregados por Apple al dispositivo más tarde)
* Un perfil DEP contiene:
* URL del servidor del proveedor de MDM
* Certificados de confianza adicionales para la URL del servidor (fijación opcional)
* Configuraciones extra (por ejemplo, qué pantallas omitir en el Asistente de Configuración)

## Número de Serie

Los dispositivos de Apple fabricados después de 2010 generalmente tienen números de serie alfanuméricos de **12 caracteres**, con los **primeros tres dígitos representando el lugar de fabricación**, los siguientes **dos** indicando el **año** y la **semana** de fabricación, los siguientes **tres** dígitos proporcionando un **identificador único**, y los **últimos cuatro dígitos representando el número de modelo**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Pasos para la inscripción y gestión

1. Creación de registro de dispositivo (Revendedor, Apple): Se crea el registro para el nuevo dispositivo
2. Asignación de registro de dispositivo (Cliente): El dispositivo se asigna a un servidor MDM
3. Sincronización de registro de dispositivo (Proveedor de MDM): MDM sincroniza los registros de dispositivos y empuja los perfiles DEP a Apple
4. Verificación DEP (Dispositivo): El dispositivo obtiene su perfil DEP
5. Recuperación de perfil (Dispositivo)
6. Instalación de perfil (Dispositivo) a. incl. cargas útiles MDM, SCEP y CA raíz
7. Emisión de comandos MDM (Dispositivo)

![](<../../../.gitbook/assets/image (564).png>)

El archivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funciones que pueden considerarse **pasos de alto nivel** del proceso de inscripción.

### Paso 4: Verificación DEP - Obtener el Registro de Activación

Esta parte del proceso ocurre cuando un **usuario inicia un Mac por primera vez** (o después de un borrado completo)

![](<../../../.gitbook/assets/image (568).png>)

o al ejecutar `sudo profiles show -type enrollment`

* Determinar **si el dispositivo está habilitado para DEP**
* Registro de Activación es el nombre interno para el **perfil DEP**
* Comienza tan pronto como el dispositivo se conecta a Internet
* Impulsado por **`CPFetchActivationRecord`**
* Implementado por **`cloudconfigurationd`** a través de XPC. El **"Asistente de Configuración"** (cuando el dispositivo se inicia por primera vez) o el comando **`profiles`** **contactarán a este demonio** para recuperar el registro de activación.
* LaunchDaemon (siempre se ejecuta como root)

Sigue algunos pasos para obtener el Registro de Activación realizados por **`MCTeslaConfigurationFetcher`**. Este proceso utiliza un cifrado llamado **Absinthe**

1. Recuperar **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** estado a partir del certificado (**`NACInit`**)
1. Utiliza varios datos específicos del dispositivo (es decir, **Número de Serie a través de `IOKit`**)
3. Recuperar **clave de sesión**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establecer la sesión (**`NACKeyEstablishment`**)
5. Hacer la solicitud
1. POST a [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando los datos `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. La carga útil JSON está cifrada usando Absinthe (**`NACSign`**)
3. Todas las solicitudes sobre HTTPs, se utilizan certificados raíz integrados

![](<../../../.gitbook/assets/image (566).png>)

La respuesta es un diccionario JSON con algunos datos importantes como:

* **url**: URL del host del proveedor de MDM para el perfil de activación
* **anchor-certs**: Array de certificados DER utilizados como anclas de confianza

### **Paso 5: Recuperación de Perfil**

![](<../../../.gitbook/assets/image (567).png>)

* Solicitud enviada a la **url proporcionada en el perfil DEP**.
* Los **certificados de ancla** se utilizan para **evaluar la confianza** si se proporcionan.
* Recordatorio: la propiedad **anchor\_certs** del perfil DEP
* **La solicitud es un simple .plist** con identificación del dispositivo
* Ejemplos: **UDID, versión del sistema operativo**.
* Firmado CMS, codificado DER
* Firmado usando el **certificado de identidad del dispositivo (de APNS)**
* **Cadena de certificados** incluye **Apple iPhone Device CA** expirado

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1. (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (
