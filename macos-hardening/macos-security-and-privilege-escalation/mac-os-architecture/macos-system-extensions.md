# Extensiones del Sistema macOS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensiones del Sistema / Marco de Seguridad de Punto Final

A diferencia de las Extensiones del Kernel, las **Extensiones del Sistema se ejecutan en el espacio de usuario** en lugar del espacio del kernel, reduciendo el riesgo de un bloqueo del sistema debido al mal funcionamiento de la extensión.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existen tres tipos de extensiones del sistema: Extensiones **DriverKit**, Extensiones de **Red** y Extensiones de **Seguridad de Punto Final**.

### **Extensiones DriverKit**

DriverKit es un reemplazo para las extensiones del kernel que **proporcionan soporte de hardware**. Permite que los controladores de dispositivos (como USB, serie, NIC y controladores HID) se ejecuten en el espacio de usuario en lugar del espacio del kernel. El marco de DriverKit incluye **versiones en espacio de usuario de ciertas clases de I/O Kit**, y el kernel reenvía eventos normales de I/O Kit al espacio de usuario, ofreciendo un entorno más seguro para que estos controladores se ejecuten.

### **Extensiones de Red**

Las Extensiones de Red proporcionan la capacidad de personalizar comportamientos de red. Hay varios tipos de Extensiones de Red:

* **Proxy de Aplicación**: Se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado al flujo. Esto significa que maneja el tráfico de red en función de las conexiones (o flujos) en lugar de paquetes individuales.
* **Túnel de Paquetes**: Se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado a paquetes. Esto significa que maneja el tráfico de red en función de paquetes individuales.
* **Filtrar Datos**: Se utiliza para filtrar "flujos" de red. Puede monitorear o modificar datos de red a nivel de flujo.
* **Filtrar Paquete**: Se utiliza para filtrar paquetes individuales de red. Puede monitorear o modificar datos de red a nivel de paquete.
* **Proxy DNS**: Se utiliza para crear un proveedor DNS personalizado. Puede usarse para monitorear o modificar solicitudes y respuestas DNS.

## Marco de Seguridad de Punto Final

Endpoint Security es un marco proporcionado por Apple en macOS que ofrece un conjunto de APIs para la seguridad del sistema. Está destinado a ser utilizado por **proveedores de seguridad y desarrolladores para construir productos que puedan monitorear y controlar la actividad del sistema** para identificar y protegerse contra actividades maliciosas.

Este marco proporciona una **colección de APIs para monitorear y controlar la actividad del sistema**, como ejecuciones de procesos, eventos del sistema de archivos, eventos de red y del kernel.

El núcleo de este marco se implementa en el kernel, como una Extensión del Kernel (KEXT) ubicada en **`/System/Library/Extensions/EndpointSecurity.kext`**. Esta KEXT se compone de varios componentes clave:

* **EndpointSecurityDriver**: Actúa como el "punto de entrada" para la extensión del kernel. Es el principal punto de interacción entre el sistema operativo y el marco de Seguridad de Punto Final.
* **EndpointSecurityEventManager**: Este componente es responsable de implementar ganchos del kernel. Los ganchos del kernel permiten al marco monitorear eventos del sistema al interceptar llamadas del sistema.
* **EndpointSecurityClientManager**: Gestiona la comunicación con los clientes en el espacio de usuario, manteniendo un registro de qué clientes están conectados y necesitan recibir notificaciones de eventos.
* **EndpointSecurityMessageManager**: Envía mensajes y notificaciones de eventos a los clientes en el espacio de usuario.

Los eventos que el marco de Seguridad de Punto Final puede monitorear se categorizan en:

* Eventos de archivos
* Eventos de procesos
* Eventos de sockets
* Eventos del kernel (como cargar/descargar una extensión del kernel o abrir un dispositivo de I/O Kit)

### Arquitectura del Marco de Seguridad de Punto Final

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicación en el espacio de usuario** con el marco de Seguridad de Punto Final se realiza a través de la clase IOUserClient. Se utilizan dos subclases diferentes, dependiendo del tipo de llamante:

* **EndpointSecurityDriverClient**: Requiere el permiso `com.apple.private.endpoint-security.manager`, que solo es otorgado al proceso del sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Requiere el permiso `com.apple.developer.endpoint-security.client`. Esto sería utilizado típicamente por software de seguridad de terceros que necesita interactuar con el marco de Seguridad de Punto Final.

Las Extensiones de Seguridad de Punto Final:**`libEndpointSecurity.dylib`** es la biblioteca C que las extensiones del sistema utilizan para comunicarse con el kernel. Esta biblioteca utiliza I/O Kit (`IOKit`) para comunicarse con la KEXT de Seguridad de Punto Final.

**`endpointsecurityd`** es un demonio del sistema clave involucrado en la gestión y lanzamiento de extensiones del sistema de seguridad de punto final, especialmente durante el proceso de arranque temprano. **Solo las extensiones del sistema** marcadas con **`NSEndpointSecurityEarlyBoot`** en su archivo `Info.plist` reciben este tratamiento de arranque temprano.

Otro demonio del sistema, **`sysextd`**, **valida las extensiones del sistema** y las mueve a las ubicaciones adecuadas del sistema. Luego solicita al demonio relevante cargar la extensión. El **`SystemExtensions.framework`** es responsable de activar y desactivar las extensiones del sistema.

## Saltando ESF

ESF es utilizado por herramientas de seguridad que intentarán detectar a un red teamer, por lo que cualquier información sobre cómo evitar esto suena interesante.

### CVE-2021-30965

La cuestión es que la aplicación de seguridad necesita tener **permisos de Acceso Completo al Disco**. Por lo tanto, si un atacante pudiera eliminar eso, podría evitar que el software se ejecute:
```bash
tccutil reset All
```
Para **más información** sobre este bypass y otros relacionados, consulta la charla [#OBTS v5.0: "El Talón de Aquiles de la Seguridad del Punto Final" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Al final, esto se solucionó otorgando el nuevo permiso **`kTCCServiceEndpointSecurityClient`** a la aplicación de seguridad gestionada por **`tccd`** para que `tccutil` no borre sus permisos, evitando que se ejecute.

## Referencias

* [**OBTS v3.0: "Seguridad e Inseguridad del Punto Final" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
