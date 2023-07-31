# Extensiones del sistema macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Extensiones del sistema / Marco de seguridad de punto final

A diferencia de las extensiones del kernel, las **extensiones del sistema se ejecutan en el espacio de usuario** en lugar del espacio del kernel, lo que reduce el riesgo de un bloqueo del sistema debido a un mal funcionamiento de la extensión.

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Existen tres tipos de extensiones del sistema: extensiones de **DriverKit**, extensiones de **Network** y extensiones de **Endpoint Security**.

### **Extensiones de DriverKit**

DriverKit es un reemplazo de las extensiones del kernel que **proporciona soporte de hardware**. Permite que los controladores de dispositivos (como controladores USB, serie, NIC y HID) se ejecuten en el espacio de usuario en lugar del espacio del kernel. El marco de DriverKit incluye **versiones en el espacio de usuario de ciertas clases de I/O Kit**, y el kernel reenvía los eventos normales de I/O Kit al espacio de usuario, ofreciendo un entorno más seguro para que estos controladores se ejecuten.

### **Extensiones de Network**

Las extensiones de Network proporcionan la capacidad de personalizar los comportamientos de red. Existen varios tipos de extensiones de Network:

* **Proxy de aplicación**: se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado al flujo. Esto significa que maneja el tráfico de red en función de las conexiones (o flujos) en lugar de los paquetes individuales.
* **Túnel de paquetes**: se utiliza para crear un cliente VPN que implementa un protocolo VPN personalizado orientado a paquetes individuales. Esto significa que maneja el tráfico de red en función de los paquetes individuales.
* **Filtro de datos**: se utiliza para filtrar "flujos" de red. Puede monitorear o modificar datos de red a nivel de flujo.
* **Filtro de paquetes**: se utiliza para filtrar paquetes de red individuales. Puede monitorear o modificar datos de red a nivel de paquete.
* **Proxy DNS**: se utiliza para crear un proveedor DNS personalizado. Se puede utilizar para monitorear o modificar solicitudes y respuestas DNS.

## Marco de seguridad de punto final

Endpoint Security es un marco proporcionado por Apple en macOS que proporciona un conjunto de API para la seguridad del sistema. Está destinado a ser utilizado por **proveedores de seguridad y desarrolladores para construir productos que puedan monitorear y controlar la actividad del sistema** para identificar y protegerse contra actividades maliciosas.

Este marco proporciona una **colección de API para monitorear y controlar la actividad del sistema**, como ejecuciones de procesos, eventos del sistema de archivos, eventos de red y del kernel.

El núcleo de este marco se implementa en el kernel, como una extensión del kernel (KEXT) ubicada en **`/System/Library/Extensions/EndpointSecurity.kext`**. Esta KEXT está compuesta por varios componentes clave:

* **EndpointSecurityDriver**: actúa como el "punto de entrada" para la extensión del kernel. Es el principal punto de interacción entre el sistema operativo y el marco de seguridad de punto final.
* **EndpointSecurityEventManager**: este componente es responsable de implementar ganchos del kernel. Los ganchos del kernel permiten que el marco monitoree eventos del sistema al interceptar llamadas del sistema.
* **EndpointSecurityClientManager**: gestiona la comunicación con los clientes en el espacio de usuario, realizando un seguimiento de los clientes conectados que necesitan recibir notificaciones de eventos.
* **EndpointSecurityMessageManager**: envía mensajes y notificaciones de eventos a los clientes en el espacio de usuario.

Los eventos que el marco de seguridad de punto final puede monitorear se clasifican en:

* Eventos de archivos
* Eventos de procesos
* Eventos de sockets
* Eventos del kernel (como cargar/descargar una extensión del kernel o abrir un dispositivo I/O Kit)

### Arquitectura del marco de seguridad de punto final

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

La comunicación en el espacio de usuario con el marco de seguridad de punto final se realiza a través de la clase IOUserClient. Se utilizan dos subclases diferentes, según el tipo de llamante:

* **EndpointSecurityDriverClient**: esto requiere el permiso `com.apple.private.endpoint-security.manager`, que solo lo tiene el proceso del sistema `endpointsecurityd`.
* **EndpointSecurityExternalClient**: esto requiere el permiso `com.apple.developer.endpoint-security.client`. Esto normalmente sería utilizado por software de seguridad de terceros que necesita interactuar con el marco de seguridad de punto final.

Las extensiones de seguridad de punto final:**`libEndpointSecurity.dylib`** es la biblioteca C que utilizan las extensiones del sistema para comunicarse con el kernel. Esta biblioteca utiliza I/O Kit (`IOKit`) para comunicarse con la KEXT de seguridad de punto final.

**`endpointsecurityd`** es un demonio del sistema clave que participa en la gestión y el lanzamiento de extensiones del sistema de seguridad de punto final, especialmente durante el proceso de inicio temprano. Solo las extensiones del sistema marcadas con **`NSEndpointSecurityEarlyBoot`** en su archivo `Info.plist` reciben este tratamiento de inicio temprano.

Otro demonio del sistema, **`sysextd`**, **valida las extensiones del sistema** y las mueve a las ubicaciones adecuadas del sistema. Luego, solicita al demonio relevante que cargue la extensión. El **`SystemExtensions.framework`** es responsable de activar y desactivar las extensiones del sistema.
## Bypassando ESF

ESF es utilizado por herramientas de seguridad que intentarán detectar a un red teamer, por lo que cualquier información sobre cómo evitar esto suena interesante.

### CVE-2021-30965

La cuestión es que la aplicación de seguridad necesita tener **permisos de acceso completo al disco**. Entonces, si un atacante pudiera eliminar eso, podría evitar que el software se ejecute:
```bash
tccutil reset All
```
Para obtener **más información** sobre este bypass y otros relacionados, consulta la charla [#OBTS v5.0: "El talón de Aquiles de EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Al final, esto se solucionó otorgando el nuevo permiso **`kTCCServiceEndpointSecurityClient`** a la aplicación de seguridad gestionada por **`tccd`** para que `tccutil` no borre sus permisos y evite que se ejecute.

## Referencias

* [**OBTS v3.0: "Seguridad e inseguridad de Endpoint" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
