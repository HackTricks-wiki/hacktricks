# Seguridad en Docker

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, potenciados por las herramientas comunitarias **más avanzadas**.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Seguridad Básica del Motor Docker**

El motor Docker realiza la tarea de ejecutar y gestionar Contenedores. Utiliza características del kernel de Linux como **Namespaces** y **Cgroups** para proporcionar **aislamiento** básico entre Contenedores. También utiliza características como **Capabilities dropping**, **Seccomp**, **SELinux/AppArmor para lograr un mejor aislamiento**.

Finalmente, se puede utilizar un **plugin de autenticación** para **limitar las acciones** que los usuarios pueden realizar.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Acceso seguro al motor Docker**

El cliente Docker puede acceder al motor Docker **localmente usando socket Unix o remotamente usando http**. Para usarlo remotamente, es necesario utilizar https y **TLS** para asegurar la confidencialidad, integridad y autenticación.

Por defecto escucha en el socket Unix `unix:///var/`\
`run/docker.sock` y en distribuciones de Ubuntu, las opciones de inicio de Docker se especifican en `/etc/default/docker`. Para permitir que la API de Docker y el cliente accedan al motor Docker remotamente, necesitamos **exponer el demonio de Docker usando socket http**. Esto se puede hacer mediante:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Exponer el daemon de Docker usando http no es una buena práctica y es necesario asegurar la conexión usando https. Hay dos opciones: la primera opción es que el **cliente verifique la identidad del servidor** y en la segunda opción **tanto el cliente como el servidor verifican la identidad del otro**. Los certificados establecen la identidad de un servidor. Para un ejemplo de ambas opciones [**consulta esta página**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Seguridad de la imagen del contenedor**

Las imágenes de contenedores se almacenan ya sea en un repositorio privado o público. A continuación se presentan las opciones que Docker ofrece para almacenar imágenes de contenedores:

* [Docker hub](https://hub.docker.com) – Este es un servicio de registro público proporcionado por Docker.
* [Docker registry](https://github.com/%20docker/distribution) – Este es un proyecto de código abierto que los usuarios pueden utilizar para alojar su propio registro.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) – Esta es la implementación comercial de Docker registry por parte de Docker y proporciona autenticación de usuario basada en roles junto con la integración del servicio de directorio LDAP.

### Escaneo de Imágenes

Los contenedores pueden tener **vulnerabilidades de seguridad** ya sea debido a la imagen base o debido al software instalado encima de la imagen base. Docker está trabajando en un proyecto llamado **Nautilus** que realiza escaneos de seguridad de Contenedores y enumera las vulnerabilidades. Nautilus funciona comparando cada capa de la imagen del Contenedor con el repositorio de vulnerabilidades para identificar fallos de seguridad.

Para más [**información lee esto**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

El comando **`docker scan`** te permite escanear imágenes de Docker existentes usando el nombre o ID de la imagen. Por ejemplo, ejecuta el siguiente comando para escanear la imagen hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Firma de Imágenes Docker

Las imágenes de contenedores Docker pueden almacenarse en un registro público o privado. Es necesario **firmar** las imágenes de **Contenedores** para poder confirmar que las imágenes no han sido alteradas. El **editor** de contenido se encarga de **firmar** la imagen del Contenedor y subirla al registro.\
A continuación, algunos detalles sobre la confianza de contenido de Docker:

* La confianza de contenido de Docker es una implementación del [proyecto de código abierto Notary](https://github.com/docker/notary). El proyecto de código abierto Notary se basa en [el proyecto The Update Framework (TUF)](https://theupdateframework.github.io).
* La confianza de contenido de Docker se **habilita** con `export DOCKER_CONTENT_TRUST=1`. A partir de la versión 1.10 de Docker, la confianza de contenido **no está habilitada por defecto**.
* **Cuando** la confianza de contenido está **habilitada**, solo podemos **descargar imágenes firmadas**. Cuando se sube una imagen, necesitamos ingresar una clave de etiquetado.
* Cuando el editor **sube** la imagen por **primera** **vez** usando docker push, es necesario ingresar una **frase de contraseña** para la **clave raíz y la clave de etiquetado**. Las demás claves se generan automáticamente.
* Docker también ha añadido soporte para llaves de hardware usando Yubikey y los detalles están disponibles [aquí](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

A continuación, el **error** que recibimos cuando **la confianza de contenido está habilitada y la imagen no está firmada**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
La salida siguiente muestra la **imagen del Contenedor siendo subida a Docker hub con la firma** activada. Dado que no es la primera vez, se solicita al usuario que ingrese solo la frase de paso para la clave del repositorio.
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
Es necesario almacenar la clave de root, la clave del repositorio, así como la frase de paso en un lugar seguro. El siguiente comando se puede utilizar para hacer una copia de seguridad de las claves privadas:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Cuando cambié de host de Docker, tuve que mover las claves raíz y las claves del repositorio para operar desde el nuevo host.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Características de Seguridad de Contenedores

<details>

<summary>Resumen de Características de Seguridad de Contenedores</summary>

**Namespaces**

Los namespaces son útiles para aislar un proyecto de los demás, aislando comunicaciones de procesos, red, montajes... Es útil para aislar el proceso de docker de otros procesos (e incluso la carpeta /proc) para que no pueda escapar abusando de otros procesos.

Podría ser posible "escapar" o más exactamente **crear nuevos namespaces** usando el binario **`unshare`** (que utiliza la syscall **`unshare`**). Docker por defecto lo previene, pero kubernetes no (en el momento de escribir esto).\
De todos modos, esto es útil para crear nuevos namespaces, pero **no para volver a los namespaces predeterminados del host** (a menos que tengas acceso a algún `/proc` dentro de los namespaces del host, donde podrías usar **`nsenter`** para entrar en los namespaces del host).

**CGroups**

Esto permite limitar recursos y no afecta la seguridad del aislamiento del proceso (excepto por el `release_agent` que podría ser utilizado para escapar).

**Capabilities Drop**

Encuentro que esta es una de las características **más importantes** en cuanto a la seguridad del aislamiento del proceso. Esto se debe a que sin las capacidades, incluso si el proceso se ejecuta como root **no podrás realizar algunas acciones privilegiadas** (porque la syscall llamada **retornará un error de permiso porque el proceso no tiene las capacidades necesarias**).

Estas son las **capacidades restantes** después de que el proceso suelte las demás:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Está habilitado por defecto en Docker. Ayuda a **limitar aún más las llamadas al sistema** que el proceso puede realizar.\
El **perfil Seccomp predeterminado de Docker** se puede encontrar en [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker tiene una plantilla que puedes activar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Esto permitirá reducir capacidades, llamadas al sistema, acceso a archivos y carpetas...

</details>

### Namespaces

Los **Namespaces** son una característica del kernel de Linux que **particiona los recursos del kernel** de tal manera que un conjunto de **procesos** **ve** un conjunto de **recursos** mientras que **otro** conjunto de **procesos** ve un conjunto **diferente** de recursos. La característica funciona al tener el mismo namespace para un conjunto de recursos y procesos, pero esos namespaces se refieren a recursos distintos. Los recursos pueden existir en múltiples espacios.

Docker utiliza los siguientes Namespaces del kernel de Linux para lograr el aislamiento de Contenedores:

* namespace de pid
* namespace de montaje
* namespace de red
* namespace de ipc
* namespace de UTS

Para **más información sobre los namespaces** consulta la siguiente página:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La característica del kernel de Linux **cgroups** proporciona la capacidad de **restringir recursos como cpu, memoria, io, ancho de banda de red entre** un conjunto de procesos. Docker permite crear Contenedores utilizando la característica cgroup que permite el control de recursos para el Contenedor específico.\
A continuación se muestra un Contenedor creado con memoria de espacio de usuario limitada a 500m, memoria del kernel limitada a 50m, participación de cpu a 512, peso de blkioweight a 400. La participación de CPU es una proporción que controla el uso de CPU del Contenedor. Tiene un valor predeterminado de 1024 y un rango entre 0 y 1024. Si tres Contenedores tienen la misma participación de CPU de 1024, cada Contenedor puede tomar hasta el 33% de la CPU en caso de contención de recursos de CPU. blkio-weight es una proporción que controla el IO del Contenedor. Tiene un valor predeterminado de 500 y un rango entre 10 y 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obtener el cgroup de un contenedor puedes hacer:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para más información, consulta:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacidades

Las capacidades permiten un **control más fino de las capacidades que pueden ser permitidas** para el usuario root. Docker utiliza la característica de capacidades del kernel de Linux para **limitar las operaciones que se pueden realizar dentro de un Contenedor**, independientemente del tipo de usuario.

Cuando se ejecuta un contenedor de docker, el **proceso descarta capacidades sensibles que el proceso podría usar para escapar del aislamiento**. Esto intenta asegurar que el proceso no pueda realizar acciones sensibles y escapar:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp en Docker

Esta es una característica de seguridad que permite a Docker **limitar las llamadas al sistema** que se pueden usar dentro del contenedor:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor en Docker

**AppArmor** es una mejora del kernel para confinar **contenedores** a un conjunto **limitado** de **recursos** con **perfiles por programa**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux en Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) es un **sistema de etiquetado**. Cada **proceso** y cada objeto del **sistema de archivos** tiene una **etiqueta**. Las políticas de SELinux definen reglas sobre lo que una **etiqueta de proceso puede hacer con todas las demás etiquetas** en el sistema.

Los motores de contenedores lanzan **procesos de contenedores con una única etiqueta de SELinux confinada**, generalmente `container_t`, y luego configuran el contenedor dentro del contenedor para que esté etiquetado como `container_file_t`. Las reglas de políticas de SELinux básicamente dicen que los procesos **`container_t` solo pueden leer/escribir/ejecutar archivos etiquetados como `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Un plugin de autorización **aprueba** o **niega** **solicitudes** al **daemon** de Docker basado tanto en el contexto de **autenticación** actual como en el contexto del **comando**. El contexto de **autenticación** contiene todos los **detalles del usuario** y el **método de autenticación**. El contexto del **comando** contiene todos los datos **relevantes** de la **solicitud**.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS desde un contenedor

Si no estás limitando adecuadamente los recursos que un contenedor puede usar, un contenedor comprometido podría realizar un DoS al host donde se está ejecutando.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Ataque de denegación de servicio por ancho de banda
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Banderas interesantes de Docker

### bandera --privileged

En la siguiente página puedes aprender **qué implica la bandera `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Si estás ejecutando un contenedor donde un atacante logra obtener acceso como un usuario de bajo privilegio. Si tienes un **binario suid mal configurado**, el atacante podría abusar de él y **escalar privilegios dentro** del contenedor. Lo que podría permitirle escapar de él.

Ejecutar el contenedor con la opción **`no-new-privileges`** habilitada **prevendrá este tipo de escalada de privilegios**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Otros
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Para más opciones de **`--security-opt`** consulta: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Otras Consideraciones de Seguridad

### Gestión de Secretos

Primero que nada, **¡no los pongas dentro de tu imagen!**

Además, **no uses variables de entorno** para tu información sensible. Cualquiera que pueda ejecutar `docker inspect` o `exec` en el contenedor puede encontrar tu secreto.

Los volúmenes de Docker son mejores. Son el método recomendado para acceder a tu información sensible en la documentación de Docker. Puedes **usar un volumen como sistema de archivos temporal en memoria**. Los volúmenes eliminan el riesgo de `docker inspect` y de registro. Sin embargo, **los usuarios root todavía podrían ver el secreto, al igual que cualquiera que pueda hacer `exec` en el contenedor**.

Incluso **mejor que los volúmenes, usa los secretos de Docker**.

Si solo necesitas el **secreto en tu imagen**, puedes usar **BuildKit**. BuildKit reduce significativamente el tiempo de construcción y tiene otras características interesantes, incluyendo **soporte de secretos durante la construcción**.

Hay tres maneras de especificar el backend de BuildKit para que puedas usar sus características ahora:

1. Establecerlo como una variable de entorno con `export DOCKER_BUILDKIT=1`.
2. Iniciar tu comando de `build` o `run` con `DOCKER_BUILDKIT=1`.
3. Habilitar BuildKit por defecto. Configura /_etc/docker/daemon.json_ a _true_ con: `{ "features": { "buildkit": true } }`. Luego reinicia Docker.
4. Luego puedes usar secretos durante la construcción con la bandera `--secret` de esta manera:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Donde su archivo especifica sus secretos como par clave-valor.

Estos secretos están excluidos de la caché de construcción de la imagen y de la imagen final.

Si necesita su **secreto en su contenedor en ejecución**, y no solo al construir su imagen, use **Docker Compose o Kubernetes**.

Con Docker Compose, agregue el par clave-valor de los secretos a un servicio y especifique el archivo secreto. Un reconocimiento a [respuesta de Stack Exchange](https://serverfault.com/a/936262/535325) por el consejo de secretos de Docker Compose que el ejemplo a continuación está adaptado.

Ejemplo de `docker-compose.yml` con secretos:
```yaml
version: "3.7"

services:

my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret

secrets:
my_secret:
file: ./my_secret_file.txt
```
Luego inicia Compose como de costumbre con `docker-compose up --build my_service`.

Si estás utilizando [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), este tiene soporte para secretos. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) puede ayudar a facilitar la gestión de secretos en K8s. Además, K8s tiene Controles de Acceso Basados en Roles (RBAC) — al igual que Docker Enterprise. RBAC hace que la gestión de Secretos sea más manejable y segura para los equipos.

### gVisor

**gVisor** es un núcleo de aplicación, escrito en Go, que implementa una parte sustancial de la superficie del sistema Linux. Incluye un tiempo de ejecución de [Open Container Initiative (OCI)](https://www.opencontainers.org) llamado `runsc` que proporciona un **límite de aislamiento entre la aplicación y el núcleo del host**. El tiempo de ejecución `runsc` se integra con Docker y Kubernetes, facilitando la ejecución de contenedores en entornos aislados.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** es una comunidad de código abierto que trabaja para construir un tiempo de ejecución de contenedores seguro con máquinas virtuales ligeras que se sienten y se desempeñan como contenedores, pero proporcionan **un aislamiento de carga de trabajo más fuerte utilizando la tecnología de virtualización de hardware** como una segunda capa de defensa.

{% embed url="https://katacontainers.io/" %}

### Consejos Resumidos

* **No uses la bandera `--privileged` ni montes un** [**socket de Docker dentro del contenedor**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** El socket de Docker permite la creación de contenedores, por lo que es una forma fácil de tomar el control total del host, por ejemplo, ejecutando otro contenedor con la bandera `--privileged`.
* **No ejecutes como root dentro del contenedor. Usa un** [**usuario diferente**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **y** [**espacios de nombres de usuario**](https://docs.docker.com/engine/security/userns-remap/)**.** El root en el contenedor es el mismo que en el host a menos que se remapee con espacios de nombres de usuario. Solo está ligeramente restringido por, principalmente, espacios de nombres de Linux, capacidades y cgroups.
* [**Deshabilita todas las capacidades**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) y habilita solo aquellas que sean necesarias** (`--cap-add=...`). Muchas cargas de trabajo no necesitan ninguna capacidad y agregarlas aumenta el alcance de un posible ataque.
* [**Usa la opción de seguridad “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que los procesos obtengan más privilegios, por ejemplo a través de binarios suid.
* [**Limita los recursos disponibles para el contenedor**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Los límites de recursos pueden proteger la máquina de ataques de denegación de servicio.
* **Ajusta** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(o SELinux)** perfiles para restringir las acciones y llamadas al sistema disponibles para el contenedor al mínimo requerido.
* **Usa** [**imágenes oficiales de docker**](https://docs.docker.com/docker-hub/official_images/) **y requiere firmas** o construye las tuyas propias basándote en ellas. No heredes ni uses imágenes [comprometidas](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Además, almacena las claves raíz, la frase de paso en un lugar seguro. Docker tiene planes para gestionar las claves con UCP.
* **Reconstruye regularmente** tus imágenes para **aplicar parches de seguridad al host e imágenes.**
* Gestiona tus **secretos sabiamente** para que sea difícil para el atacante acceder a ellos.
* Si **expones el daemon de docker usa HTTPS** con autenticación de cliente y servidor.
* En tu Dockerfile, **prefiere COPY en lugar de ADD**. ADD extrae automáticamente archivos comprimidos y puede copiar archivos de URLs. COPY no tiene estas capacidades. Siempre que sea posible, evita usar ADD para no ser susceptible a ataques a través de URLs remotas y archivos Zip.
* Ten **contenedores separados para cada microservicio**
* **No pongas ssh** dentro del contenedor, se puede usar “docker exec” para acceder al contenedor mediante ssh.
* Ten **imágenes de contenedor más pequeñas**

## Docker Breakout / Escalada de Privilegios

Si estás **dentro de un contenedor de docker** o tienes acceso a un usuario en el **grupo de docker**, podrías intentar **escapar y escalar privilegios**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass de Plugin de Autenticación de Docker

Si tienes acceso al socket de docker o tienes acceso a un usuario en el **grupo de docker pero tus acciones están siendo limitadas por un plugin de autenticación de docker**, verifica si puedes **eludirlo:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Endurecimiento de Docker

* La herramienta [**docker-bench-security**](https://github.com/docker/docker-bench-security) es un script que verifica docenas de prácticas comunes recomendadas para desplegar contenedores de Docker en producción. Las pruebas son todas automatizadas y se basan en el [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Necesitas ejecutar la herramienta desde el host que ejecuta docker o desde un contenedor con suficientes privilegios. Descubre **cómo ejecutarlo en el README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las herramientas comunitarias **más avanzadas** del mundo.\
Obtén Acceso Hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
