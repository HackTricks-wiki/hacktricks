# Extensiones del Sistema macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensiones del Sistema / Marco de Seguridad de Endpoint

A diferencia de las Extensiones del Kernel, las **Extensiones del Sistema se ejecutan en el espacio de usuario** en lugar del espacio del kernel, reduciendo el riesgo de un fallo del sistema debido a un mal funcionamiento de la extensión.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Hay tres tipos de extensiones del sistema: Extensiones **DriverKit**, Extensiones de **Red** y Extensiones de **Seguridad de Endpoint**.

### **Extensiones DriverKit**

DriverKit es un reemplazo para las extensiones del kernel que **proporcionan soporte de hardware**. Permite que los controladores de dispositivos (como controladores USB, Serial, NIC y HID) se ejecuten en el espacio de usuario en lugar del espacio del kernel. El marco de trabajo de DriverKit incluye **versiones en el espacio de usuario de ciertas clases de I/O Kit**, y el kernel reenvía eventos normales de I/O Kit al espacio de usuario, ofreciendo un entorno más seguro para la ejecución de estos controladores.

### **Extensiones de Red**

Las Extensiones de Red proporcionan la capacidad de personalizar comportamientos de red. Hay varios tipos de Extensiones de Red:

* **App Proxy**: Se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado al flujo. Esto significa que maneja el tráfico de red basado en conexiones (o flujos) en lugar de paquetes individuales.
* **Packet Tunnel**: Se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado a paquetes. Esto significa que maneja el tráfico de red basado en paquetes individuales.
* **Filter Data**: Se utiliza para filtrar "flujos" de red. Puede monitorear o modificar datos de red a nivel de flujo.
* **Filter Packet**: Se utiliza para filtrar paquetes de red individuales. Puede monitorear o modificar datos de red a nivel de paquete.
* **DNS Proxy**: Se utiliza para crear un proveedor de DNS personalizado. Puede ser utilizado para monitorear o modificar solicitudes y respuestas de DNS.

## Marco de Seguridad de Endpoint

Endpoint Security es un marco proporcionado por Apple en macOS que ofrece un conjunto de APIs para la seguridad del sistema. Está destinado para ser utilizado por **proveedores de seguridad y desarrolladores para construir productos que puedan monitorear y controlar la actividad del sistema** para identificar y proteger contra actividades maliciosas.

Este marco proporciona un **conjunto de APIs para monitorear y controlar la actividad del sistema**, como ejecuciones de procesos, eventos del sistema de archivos, eventos de red y del kernel.

El núcleo de este marco está implementado en el kernel, como una Extensión del Kernel (KEXT) ubicada en **`/System/Library/Extensions/EndpointSecurity.kext`**. Este KEXT está compuesto por varios componentes clave:

* **EndpointSecurityDriver**: Actúa como el "punto de entrada" para la extensión del kernel. Es el principal punto de interacción entre el OS y el marco de seguridad de Endpoint.
* **EndpointSecurityEventManager**: Este componente es responsable de implementar ganchos del kernel. Los ganchos del kernel permiten al marco monitorear eventos del sistema interceptando llamadas al sistema.
* **EndpointSecurityClientManager**: Gestiona la comunicación con clientes en el espacio de usuario, manteniendo un registro de qué clientes están conectados y necesitan recibir notificaciones de eventos.
* **EndpointSecurityMessageManager**: Envía mensajes y notificaciones de eventos a clientes en el espacio de usuario.

Los eventos que el marco de seguridad de Endpoint puede monitorear se categorizan en:

* Eventos de archivos
* Eventos de procesos
* Eventos de sockets
* Eventos del kernel (como cargar/descargar una extensión del kernel o abrir un dispositivo de I/O Kit)

### Arquitectura del Marco de Seguridad de Endpoint

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

La **comunicación en el espacio de usuario** con el marco de seguridad de Endpoint ocurre a través de la clase IOUserClient. Se utilizan dos subclases diferentes, dependiendo del tipo de llamador:

* **EndpointSecurityDriverClient**: Requiere el privilegio `com.apple.private.endpoint-security.manager`, que solo posee el proceso del sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: Requiere el privilegio `com.apple.developer.endpoint-security.client`. Esto sería típicamente utilizado por software de seguridad de terceros que necesita interactuar con el marco de seguridad de Endpoint.

Las Extensiones de Seguridad de Endpoint: **`libEndpointSecurity.dylib`** es la biblioteca C que las extensiones del sistema utilizan para comunicarse con el kernel. Esta biblioteca utiliza I/O Kit (`IOKit`) para comunicarse con el KEXT de seguridad de Endpoint.

**`endpointsecurityd`** es un daemon del sistema clave involucrado en la gestión y lanzamiento de extensiones del sistema de seguridad de endpoint, particularmente durante el proceso de arranque temprano. **Solo las extensiones del sistema** marcadas con **`NSEndpointSecurityEarlyBoot`** en su archivo `Info.plist` reciben este tratamiento de arranque temprano.

Otro daemon del sistema, **`sysextd`**, **valida las extensiones del sistema** y las mueve a las ubicaciones del sistema adecuadas. Luego pide al daemon relevante que cargue la extensión. El **`SystemExtensions.framework`** es responsable de activar y desactivar las extensiones del sistema.

## Eludiendo ESF

ESF es utilizado por herramientas de seguridad que intentarán detectar a un red teamer, por lo que cualquier información sobre cómo esto podría evitarse suena interesante.

### CVE-2021-30965

El asunto es que la aplicación de seguridad necesita tener permisos de **Acceso Completo al Disco**. Así que si un atacante pudiera eliminar eso, podría evitar que el software se ejecute:
```bash
tccutil reset All
```
Para **más información** sobre este bypass y otros relacionados, consulta la charla [#OBTS v5.0: "El Talón de Aquiles de EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Al final, esto se solucionó otorgando el nuevo permiso **`kTCCServiceEndpointSecurityClient`** a la aplicación de seguridad gestionada por **`tccd`**, de modo que `tccutil` no borrará sus permisos evitando que se ejecute.

## Referencias

* [**OBTS v3.0: "Seguridad y Inseguridad de Endpoint" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
