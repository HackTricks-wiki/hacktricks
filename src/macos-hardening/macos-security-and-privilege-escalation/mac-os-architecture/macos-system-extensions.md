# Extensiones del sistema en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Extensiones del sistema / Endpoint Security Framework

A diferencia de las Kernel Extensions, las **System Extensions se ejecutan en el espacio de usuario** en lugar de hacerlo en el espacio del kernel, lo que reduce el riesgo de que el sistema se bloquee debido a un mal funcionamiento de la extensión.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Existen tres tipos de extensiones del sistema: extensiones **DriverKit**, extensiones de **Network** y extensiones de **Endpoint Security**.

### **Extensiones DriverKit**

DriverKit es un reemplazo de las extensiones del kernel que **proporcionan compatibilidad con hardware**. Permite que los controladores de dispositivos (como controladores USB, Serial, NIC y HID) se ejecuten en el espacio de usuario en lugar de hacerlo en el espacio del kernel. El framework DriverKit incluye **versiones para el espacio de usuario de determinadas clases de I/O Kit**, y el kernel reenvía los eventos normales de I/O Kit al espacio de usuario, ofreciendo un entorno más seguro para que se ejecuten estos controladores.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions permiten personalizar los comportamientos de red. Existen varios tipos de Network Extensions:

- **App Proxy**: Se utiliza para crear un cliente VPN que implemente un protocolo VPN personalizado orientado a flujos. Esto significa que gestiona el tráfico de red basándose en conexiones (o flujos) en lugar de en paquetes individuales.
- **Packet Tunnel**: Se utiliza para crear un cliente VPN que implemente un protocolo VPN personalizado orientado a paquetes. Esto significa que gestiona el tráfico de red basándose en paquetes individuales.
- **Filter Data**: Se utiliza para filtrar "flujos" de red. Puede monitorizar o modificar los datos de red a nivel de flujo.
- **Filter Packet**: Se utiliza para filtrar paquetes de red individuales. Puede monitorizar o modificar los datos de red a nivel de paquete.
- **DNS Proxy**: Se utiliza para crear un proveedor DNS personalizado. Puede utilizarse para monitorizar o modificar solicitudes y respuestas DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security es un framework proporcionado por Apple en macOS que ofrece un conjunto de APIs para la seguridad del sistema. Está destinado a que **los proveedores y desarrolladores de seguridad creen productos capaces de monitorizar y controlar la actividad del sistema** para identificar y protegerse contra actividades maliciosas.

Este framework proporciona una **colección de APIs para monitorizar y controlar la actividad del sistema**, como ejecuciones de procesos, eventos del sistema de archivos y eventos de red y del kernel.

El núcleo de este framework está implementado en el kernel, como una Kernel Extension (KEXT) ubicada en **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Esta KEXT está compuesta por varios componentes clave:

- **EndpointSecurityDriver**: Actúa como el "punto de entrada" de la extensión del kernel. Es el principal punto de interacción entre el sistema operativo y el framework Endpoint Security.
- **EndpointSecurityEventManager**: Este componente se encarga de implementar hooks del kernel. Los hooks del kernel permiten al framework monitorizar eventos del sistema interceptando llamadas al sistema.
- **EndpointSecurityClientManager**: Gestiona la comunicación con los clientes del espacio de usuario, realizando un seguimiento de qué clientes están conectados y necesitan recibir notificaciones de eventos.
- **EndpointSecurityMessageManager**: Envía mensajes y notificaciones de eventos a los clientes del espacio de usuario.

Los eventos que el framework Endpoint Security puede monitorizar se clasifican en:

- Eventos de archivos
- Eventos de procesos
- Eventos de sockets
- Eventos del kernel (como cargar o descargar una extensión del kernel o abrir un dispositivo I/O Kit)

### Arquitectura de Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicación desde el espacio de usuario** con el framework Endpoint Security se realiza mediante la clase IOUserClient. Se utilizan dos subclases diferentes, dependiendo del tipo de emisor:

- **EndpointSecurityDriverClient**: Requiere el entitlement `com.apple.private.endpoint-security.manager`, que solo posee el proceso del sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Requiere el entitlement `com.apple.developer.endpoint-security.client`. Normalmente lo utilizaría software de seguridad de terceros que necesite interactuar con el framework Endpoint Security.<sup>[[1]](#references)</sup>

Las Endpoint Security Extensions:**`libEndpointSecurity.dylib`** es la biblioteca C que utilizan las extensiones del sistema para comunicarse con el kernel. Esta biblioteca utiliza I/O Kit (`IOKit`) para comunicarse con la KEXT de Endpoint Security.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** es un daemon clave del sistema que participa en la gestión y el lanzamiento de las extensiones del sistema de seguridad de endpoints, especialmente durante el proceso de arranque temprano. **Solo las extensiones del sistema** marcadas con **`NSEndpointSecurityEarlyBoot`** en su archivo `Info.plist` reciben este tratamiento de arranque temprano.<sup>[[2]](#references)</sup>

Otro daemon del sistema, **`sysextd`**, **valida las extensiones del sistema** y las mueve a las ubicaciones adecuadas del sistema. Después solicita al daemon correspondiente que cargue la extensión. El **`SystemExtensions.framework`** se encarga de activar y desactivar las extensiones del sistema.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF se utiliza en herramientas de seguridad que intentarán detectar a un red teamer, por lo que resulta interesante cualquier información sobre cómo evitarlo.

### CVE-2021-30965

El problema es que la aplicación de seguridad necesita tener **permisos de Full Disk Access**. Por tanto, si un atacante pudiera eliminarlos, podría impedir que el software se ejecutara:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Para obtener **más información** sobre este bypass y otros relacionados, consulta la charla [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Al final, esto se solucionó otorgando el nuevo permiso **`kTCCServiceEndpointSecurityClient`** a la aplicación de seguridad administrada por **`tccd`**, de modo que `tccutil` no elimine sus permisos, evitando que se ejecute.<sup>[[3]](#references)</sup>

## Referencias

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
