# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

A diferencia de las Kernel Extensions, **las System Extensions se ejecutan en el espacio de usuario** en lugar del espacio del kernel, reduciendo el riesgo de un fallo del sistema debido a un mal funcionamiento de la extensión.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Hay tres tipos de system extensions: **DriverKit** Extensions, **Network** Extensions y **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit es un reemplazo para las kernel extensions que **proporcionan soporte de hardware**. Permite que los controladores de dispositivos (como USB, Serial, NIC y controladores HID) se ejecuten en el espacio de usuario en lugar del espacio del kernel. El marco DriverKit incluye **versiones de espacio de usuario de ciertas clases de I/O Kit**, y el kernel reenvía eventos normales de I/O Kit al espacio de usuario, ofreciendo un entorno más seguro para que estos controladores se ejecuten.

### **Network Extensions**

Las Network Extensions proporcionan la capacidad de personalizar comportamientos de red. Hay varios tipos de Network Extensions:

- **App Proxy**: Esto se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado a flujos. Esto significa que maneja el tráfico de red basado en conexiones (o flujos) en lugar de paquetes individuales.
- **Packet Tunnel**: Esto se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado a paquetes. Esto significa que maneja el tráfico de red basado en paquetes individuales.
- **Filter Data**: Esto se utiliza para filtrar "flujos" de red. Puede monitorear o modificar datos de red a nivel de flujo.
- **Filter Packet**: Esto se utiliza para filtrar paquetes individuales de red. Puede monitorear o modificar datos de red a nivel de paquete.
- **DNS Proxy**: Esto se utiliza para crear un proveedor DNS personalizado. Puede usarse para monitorear o modificar solicitudes y respuestas DNS.

## Endpoint Security Framework

Endpoint Security es un marco proporcionado por Apple en macOS que ofrece un conjunto de APIs para la seguridad del sistema. Está destinado a ser utilizado por **proveedores de seguridad y desarrolladores para construir productos que puedan monitorear y controlar la actividad del sistema** para identificar y protegerse contra actividades maliciosas.

Este marco proporciona una **colección de APIs para monitorear y controlar la actividad del sistema**, como ejecuciones de procesos, eventos del sistema de archivos, eventos de red y del kernel.

El núcleo de este marco está implementado en el kernel, como una Kernel Extension (KEXT) ubicada en **`/System/Library/Extensions/EndpointSecurity.kext`**. Este KEXT está compuesto por varios componentes clave:

- **EndpointSecurityDriver**: Actúa como el "punto de entrada" para la extensión del kernel. Es el principal punto de interacción entre el sistema operativo y el marco de Endpoint Security.
- **EndpointSecurityEventManager**: Este componente es responsable de implementar ganchos del kernel. Los ganchos del kernel permiten que el marco monitoree eventos del sistema interceptando llamadas al sistema.
- **EndpointSecurityClientManager**: Este gestiona la comunicación con los clientes del espacio de usuario, manteniendo un registro de qué clientes están conectados y necesitan recibir notificaciones de eventos.
- **EndpointSecurityMessageManager**: Este envía mensajes y notificaciones de eventos a los clientes del espacio de usuario.

Los eventos que el marco de Endpoint Security puede monitorear se clasifican en:

- Eventos de archivos
- Eventos de procesos
- Eventos de sockets
- Eventos del kernel (como cargar/descargar una extensión del kernel o abrir un dispositivo de I/O Kit)

### Arquitectura del Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicación en el espacio de usuario** con el marco de Endpoint Security ocurre a través de la clase IOUserClient. Se utilizan dos subclases diferentes, dependiendo del tipo de llamador:

- **EndpointSecurityDriverClient**: Esto requiere el derecho `com.apple.private.endpoint-security.manager`, que solo posee el proceso del sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Esto requiere el derecho `com.apple.developer.endpoint-security.client`. Esto sería utilizado típicamente por software de seguridad de terceros que necesita interactuar con el marco de Endpoint Security.

Las Endpoint Security Extensions:**`libEndpointSecurity.dylib`** es la biblioteca C que utilizan las system extensions para comunicarse con el kernel. Esta biblioteca utiliza el I/O Kit (`IOKit`) para comunicarse con el KEXT de Endpoint Security.

**`endpointsecurityd`** es un daemon del sistema clave involucrado en la gestión y lanzamiento de las system extensions de seguridad de endpoint, particularmente durante el proceso de arranque temprano. **Solo las system extensions** marcadas con **`NSEndpointSecurityEarlyBoot`** en su archivo `Info.plist` reciben este tratamiento de arranque temprano.

Otro daemon del sistema, **`sysextd`**, **valida las system extensions** y las mueve a las ubicaciones adecuadas del sistema. Luego pide al daemon relevante que cargue la extensión. El **`SystemExtensions.framework`** es responsable de activar y desactivar las system extensions.

## Bypassing ESF

ESF es utilizado por herramientas de seguridad que intentarán detectar a un red teamer, por lo que cualquier información sobre cómo evitar esto suena interesante.

### CVE-2021-30965

La cuestión es que la aplicación de seguridad necesita tener **permisos de Acceso Completo al Disco**. Así que si un atacante pudiera eliminar eso, podría evitar que el software se ejecute:
```bash
tccutil reset All
```
Para **más información** sobre este bypass y otros relacionados, consulta la charla [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Al final, esto se solucionó otorgando el nuevo permiso **`kTCCServiceEndpointSecurityClient`** a la aplicación de seguridad gestionada por **`tccd`**, de modo que `tccutil` no borre sus permisos, impidiendo que deje de funcionar.

## Referencias

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
