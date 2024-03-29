# Seguridad de Docker

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Seguridad Básica del Motor de Docker**

El **motor de Docker** emplea los **Namespaces** y **Cgroups** del kernel de Linux para aislar contenedores, ofreciendo una capa básica de seguridad. La protección adicional se logra mediante la **reducción de capacidades**, **Seccomp**, y **SELinux/AppArmor**, mejorando el aislamiento de los contenedores. Un **plugin de autenticación** puede restringir aún más las acciones de los usuarios.

![Seguridad de Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Acceso Seguro al Motor de Docker

El motor de Docker puede ser accedido localmente a través de un socket Unix o de forma remota utilizando HTTP. Para el acceso remoto, es esencial emplear HTTPS y **TLS** para garantizar la confidencialidad, integridad y autenticación.

El motor de Docker, por defecto, escucha en el socket Unix en `unix:///var/run/docker.sock`. En sistemas Ubuntu, las opciones de inicio de Docker se definen en `/etc/default/docker`. Para habilitar el acceso remoto a la API y al cliente de Docker, expone el demonio de Docker sobre un socket HTTP agregando la siguiente configuración:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sin embargo, exponer el demonio de Docker a través de HTTP no es recomendado debido a preocupaciones de seguridad. Es aconsejable asegurar las conexiones utilizando HTTPS. Hay dos enfoques principales para asegurar la conexión:

1. El cliente verifica la identidad del servidor.
2. Tanto el cliente como el servidor autentican mutuamente la identidad del otro.

Se utilizan certificados para confirmar la identidad de un servidor. Para ejemplos detallados de ambos métodos, consulta [**esta guía**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Seguridad de las Imágenes de Contenedores

Las imágenes de contenedores pueden almacenarse en repositorios privados o públicos. Docker ofrece varias opciones de almacenamiento para imágenes de contenedores:

* [**Docker Hub**](https://hub.docker.com): Un servicio de registro público de Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Un proyecto de código abierto que permite a los usuarios alojar su propio registro.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Oferta de registro comercial de Docker, con autenticación de usuario basada en roles e integración con servicios de directorio LDAP.

### Escaneo de Imágenes

Los contenedores pueden tener **vulnerabilidades de seguridad** ya sea debido a la imagen base o al software instalado encima de la imagen base. Docker está trabajando en un proyecto llamado **Nautilus** que realiza un escaneo de seguridad de los contenedores y lista las vulnerabilidades. Nautilus funciona comparando cada capa de imagen de contenedor con un repositorio de vulnerabilidades para identificar agujeros de seguridad.

Para más [**información lee esto**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

El comando **`docker scan`** te permite escanear imágenes de Docker existentes utilizando el nombre o ID de la imagen. Por ejemplo, ejecuta el siguiente comando para escanear la imagen hello-world:
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
trivy -q -f json <container_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Firma de Imágenes de Docker

La firma de imágenes de Docker garantiza la seguridad e integridad de las imágenes utilizadas en contenedores. Aquí tienes una explicación resumida:

- **Docker Content Trust** utiliza el proyecto Notary, basado en The Update Framework (TUF), para gestionar la firma de imágenes. Para obtener más información, consulta [Notary](https://github.com/docker/notary) y [TUF](https://theupdateframework.github.io).
- Para activar la confianza en el contenido de Docker, establece `export DOCKER_CONTENT_TRUST=1`. Esta función está desactivada de forma predeterminada en Docker versión 1.10 y posteriores.
- Con esta función habilitada, solo se pueden descargar imágenes firmadas. La carga inicial de la imagen requiere establecer frases de paso para las claves raíz y de etiquetado, con Docker también admitiendo Yubikey para una seguridad mejorada. Puedes encontrar más detalles [aquí](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Intentar descargar una imagen no firmada con la confianza en el contenido habilitada resulta en un error de "No hay datos de confianza para la última versión".
- Para las cargas de imágenes posteriores a la primera, Docker solicita la frase de paso de la clave del repositorio para firmar la imagen.

Para hacer una copia de seguridad de tus claves privadas, utiliza el comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Cuando se cambia de hosts de Docker, es necesario mover las claves de root y del repositorio para mantener las operaciones.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir fácilmente y **automatizar flujos de trabajo** impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Características de Seguridad de Contenedores

<details>

<summary>Resumen de las Características de Seguridad de Contenedores</summary>

**Principales Características de Aislamiento de Procesos**

En entornos contenerizados, aislar proyectos y sus procesos es fundamental para la seguridad y la gestión de recursos. Aquí tienes una explicación simplificada de conceptos clave:

**Espacios de Nombres (Namespaces)**

* **Propósito**: Asegurar el aislamiento de recursos como procesos, red y sistemas de archivos. Especialmente en Docker, los espacios de nombres mantienen separados los procesos de un contenedor del host y de otros contenedores.
* **Uso de `unshare`**: El comando `unshare` (o la llamada al sistema subyacente) se utiliza para crear nuevos espacios de nombres, proporcionando una capa adicional de aislamiento. Sin embargo, mientras Kubernetes no bloquea esto inherentemente, Docker sí lo hace.
* **Limitación**: Crear nuevos espacios de nombres no permite que un proceso vuelva a los espacios de nombres predeterminados del host. Para penetrar en los espacios de nombres del host, normalmente se requeriría acceso al directorio `/proc` del host, utilizando `nsenter` para ingresar.

**Grupos de Control (CGroups)**

* **Función**: Utilizado principalmente para asignar recursos entre procesos.
* **Aspecto de Seguridad**: Los CGroups en sí mismos no ofrecen seguridad de aislamiento, excepto por la característica `release_agent`, que, si está mal configurada, podría ser potencialmente explotada para acceder sin autorización.

**Descarte de Capacidades (Capability Drop)**

* **Importancia**: Es una característica de seguridad crucial para el aislamiento de procesos.
* **Funcionalidad**: Restringe las acciones que un proceso raíz puede realizar al descartar ciertas capacidades. Incluso si un proceso se ejecuta con privilegios de root, la falta de las capacidades necesarias evita que ejecute acciones privilegiadas, ya que las llamadas al sistema fallarán debido a permisos insuficientes.

Estas son las **capacidades restantes** después de que el proceso descarte las demás:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Está habilitado de forma predeterminada en Docker. Ayuda a **limitar aún más las syscalls** que el proceso puede llamar.\
El **perfil Seccomp predeterminado de Docker** se puede encontrar en [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker tiene una plantilla que se puede activar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Esto permitirá reducir capacidades, syscalls, acceso a archivos y carpetas...

</details>

### Namespaces

**Namespaces** son una característica del kernel de Linux que **particiona los recursos del kernel** de tal manera que un conjunto de **procesos** **ve** un conjunto de **recursos** mientras que **otro** conjunto de **procesos** ve un **conjunto diferente** de recursos. La característica funciona al tener el mismo espacio de nombres para un conjunto de recursos y procesos, pero esos espacios de nombres se refieren a recursos distintos. Los recursos pueden existir en múltiples espacios.

Docker hace uso de los siguientes Namespaces del kernel de Linux para lograr el aislamiento de Contenedores:

* espacio de nombres pid
* espacio de nombres de montaje
* espacio de nombres de red
* espacio de nombres ipc
* espacio de nombres UTS

Para **más información sobre los espacios de nombres** consulta la siguiente página:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

La característica del kernel de Linux **cgroups** proporciona la capacidad de **restringir recursos como cpu, memoria, io, ancho de banda de red entre** un conjunto de procesos. Docker permite crear Contenedores utilizando la característica cgroup que permite el control de recursos para el Contenedor específico.\
A continuación se muestra un Contenedor creado con la memoria del espacio de usuario limitada a 500m, la memoria del kernel limitada a 50m, la cuota de cpu a 512, el peso de blkioweight a 400. La cuota de CPU es una proporción que controla el uso de CPU del Contenedor. Tiene un valor predeterminado de 1024 y un rango entre 0 y 1024. Si tres Contenedores tienen la misma cuota de CPU de 1024, cada Contenedor puede utilizar hasta el 33% de la CPU en caso de contención de recursos de CPU. blkio-weight es una proporción que controla la E/S del Contenedor. Tiene un valor predeterminado de 500 y un rango entre 10 y 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obtener el cgroup de un contenedor puedes hacer lo siguiente:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para obtener más información, consulta:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacidades

Las capacidades permiten un **control más preciso de las capacidades que se pueden permitir** para el usuario root. Docker utiliza la característica de capacidades del kernel de Linux para **limitar las operaciones que se pueden realizar dentro de un contenedor** independientemente del tipo de usuario.

Cuando se ejecuta un contenedor de Docker, el **proceso elimina las capacidades sensibles que el proceso podría usar para escapar del aislamiento**. Esto intenta asegurar que el proceso no pueda realizar acciones sensibles y escapar:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp en Docker

Esta es una característica de seguridad que permite a Docker **limitar las syscalls** que se pueden utilizar dentro del contenedor:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor en Docker

**AppArmor** es una mejora del kernel para confinar **contenedores** a un **conjunto limitado de recursos** con **perfiles por programa**.:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux en Docker

* **Sistema de Etiquetado**: SELinux asigna una etiqueta única a cada proceso y objeto del sistema de archivos.
* **Aplicación de Políticas**: Hace cumplir políticas de seguridad que definen qué acciones puede realizar una etiqueta de proceso en otras etiquetas dentro del sistema.
* **Etiquetas de Procesos de Contenedores**: Cuando los motores de contenedores inician procesos de contenedores, generalmente se les asigna una etiqueta SELinux confinada, comúnmente `container_t`.
* **Etiquetado de Archivos dentro de los Contenedores**: Los archivos dentro del contenedor suelen estar etiquetados como `container_file_t`.
* **Reglas de Política**: La política de SELinux garantiza principalmente que los procesos con la etiqueta `container_t` solo puedan interactuar (leer, escribir, ejecutar) con archivos etiquetados como `container_file_t`.

Este mecanismo garantiza que incluso si un proceso dentro de un contenedor se ve comprometido, está confinado a interactuar solo con objetos que tengan las etiquetas correspondientes, limitando significativamente el daño potencial de tales compromisos.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

En Docker, un complemento de autorización desempeña un papel crucial en la seguridad al decidir si permitir o bloquear las solicitudes al demonio de Docker. Esta decisión se toma examinando dos contextos clave:

* **Contexto de Autenticación**: Incluye información completa sobre el usuario, como quiénes son y cómo se han autenticado.
* **Contexto de Comando**: Comprende todos los datos pertinentes relacionados con la solicitud que se está realizando.

Estos contextos ayudan a garantizar que solo se procesen solicitudes legítimas de usuarios autenticados, mejorando la seguridad de las operaciones de Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS desde un contenedor

Si no estás limitando adecuadamente los recursos que un contenedor puede utilizar, un contenedor comprometido podría realizar un ataque de denegación de servicio (DoS) en el host donde se está ejecutando.

* DoS de CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Denegación de Servicio de Ancho de Banda
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interesantes Banderas de Docker

### Banderas --privileged

En la siguiente página puedes aprender **qué implica la bandera `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Si estás ejecutando un contenedor donde un atacante logra acceder como un usuario de baja privilegios. Si tienes un **binario suid mal configurado**, el atacante podría abusar de él y **escalar privilegios dentro** del contenedor. Lo que podría permitirle escapar de él.

Ejecutar el contenedor con la opción **`no-new-privileges`** habilitada **evitará este tipo de escalada de privilegios**.
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
Para obtener más opciones de **`--security-opt`**, consulta: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Otras Consideraciones de Seguridad

### Gestión de Secretos: Mejores Prácticas

Es crucial evitar incrustar secretos directamente en las imágenes de Docker o utilizar variables de entorno, ya que estos métodos exponen tu información sensible a cualquier persona con acceso al contenedor a través de comandos como `docker inspect` o `exec`.

Los **volúmenes de Docker** son una alternativa más segura, recomendada para acceder a información sensible. Pueden ser utilizados como un sistema de archivos temporal en memoria, mitigando los riesgos asociados con `docker inspect` y el registro. Sin embargo, los usuarios root y aquellos con acceso `exec` al contenedor aún podrían acceder a los secretos.

**Docker secrets** ofrecen un método aún más seguro para manejar información sensible. Para casos que requieran secretos durante la fase de construcción de la imagen, **BuildKit** presenta una solución eficiente con soporte para secretos en tiempo de construcción, mejorando la velocidad de construcción y proporcionando características adicionales.

Para aprovechar BuildKit, se puede activar de tres maneras:

1. A través de una variable de entorno: `export DOCKER_BUILDKIT=1`
2. Prefijando comandos: `DOCKER_BUILDKIT=1 docker build .`
3. Habilitándolo de forma predeterminada en la configuración de Docker: `{ "features": { "buildkit": true } }`, seguido de un reinicio de Docker.

BuildKit permite el uso de secretos en tiempo de construcción con la opción `--secret`, asegurando que estos secretos no se incluyan en la caché de construcción de la imagen o en la imagen final, utilizando un comando como:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Para los secretos necesarios en un contenedor en ejecución, **Docker Compose y Kubernetes** ofrecen soluciones sólidas. Docker Compose utiliza una clave `secrets` en la definición del servicio para especificar archivos secretos, como se muestra en un ejemplo de `docker-compose.yml`:
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
Esta configuración permite el uso de secretos al iniciar servicios con Docker Compose.

En entornos de Kubernetes, los secretos son compatibles de forma nativa y pueden ser gestionados con herramientas como [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Los Controles de Acceso Basados en Roles (RBAC) de Kubernetes mejoran la seguridad en la gestión de secretos, similar a Docker Enterprise.

### gVisor

**gVisor** es un kernel de aplicación, escrito en Go, que implementa una parte sustancial de la superficie del sistema Linux. Incluye un tiempo de ejecución de [Open Container Initiative (OCI)](https://www.opencontainers.org) llamado `runsc` que proporciona un **límite de aislamiento entre la aplicación y el kernel del host**. El tiempo de ejecución `runsc` se integra con Docker y Kubernetes, facilitando la ejecución de contenedores en sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** es una comunidad de código abierto que trabaja para construir un tiempo de ejecución de contenedores seguro con máquinas virtuales ligeras que se sienten y se comportan como contenedores, pero proporcionan una **mayor aislamiento de carga de trabajo utilizando tecnología de virtualización de hardware** como una segunda capa de defensa.

{% embed url="https://katacontainers.io/" %}

### Consejos Resumidos

* **No utilices la bandera `--privileged` ni montes un** [**socket de Docker dentro del contenedor**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** El socket de Docker permite generar contenedores, por lo que es una forma sencilla de tomar el control total del host, por ejemplo, ejecutando otro contenedor con la bandera `--privileged`.
* No ejecutes como root dentro del contenedor. Utiliza un [usuario diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) y [espacios de nombres de usuario](https://docs.docker.com/engine/security/userns-remap/). El root en el contenedor es el mismo que en el host a menos que se remapee con espacios de nombres de usuario. Está solo ligeramente restringido por, principalmente, espacios de nombres de Linux, capacidades y cgroups.
* [Elimina todas las capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) y habilita solo las necesarias (`--cap-add=...`). Muchas cargas de trabajo no necesitan capacidades y agregarlas aumenta el alcance de un posible ataque.
* [Utiliza la opción de seguridad "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que los procesos obtengan más privilegios, por ejemplo, a través de binarios suid.
* [Limita los recursos disponibles para el contenedor](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Los límites de recursos pueden proteger la máquina de ataques de denegación de servicio.
* Ajusta los perfiles de [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (o SELinux) para restringir las acciones y llamadas al sistema disponibles para el contenedor al mínimo requerido.
* Utiliza [imágenes oficiales de Docker](https://docs.docker.com/docker-hub/official_images/) y exige firmas o construye las tuyas basadas en ellas. No heredes ni uses imágenes [con puertas traseras](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Almacena también claves raíz, frases de contraseña en un lugar seguro. Docker tiene planes para gestionar claves con UCP.
* **Reconstruye regularmente** tus imágenes para **aplicar parches de seguridad al host e imágenes**.
* Gestiona tus **secretos sabiamente** para que sea difícil para el atacante acceder a ellos.
* Si **expones el daemon de Docker, utiliza HTTPS** con autenticación de cliente y servidor.
* En tu Dockerfile, **prefiere COPY en lugar de ADD**. ADD extrae automáticamente archivos comprimidos y puede copiar archivos desde URL. COPY no tiene estas capacidades. Siempre que sea posible, evita usar ADD para no ser susceptible a ataques a través de URL remotas y archivos Zip.
* Ten **contenedores separados para cada microservicio**.
* **No incluyas ssh** dentro del contenedor, "docker exec" se puede usar para ssh al contenedor.
* Utiliza **imágenes de contenedores más pequeñas**.

## Fuga de Docker / Escalada de Privilegios

Si estás **dentro de un contenedor de Docker** o tienes acceso a un usuario en el **grupo de Docker**, podrías intentar **escapar y escalar privilegios**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass del Plugin de Autenticación de Docker

Si tienes acceso al socket de Docker o tienes acceso a un usuario en el **grupo de Docker pero tus acciones están siendo limitadas por un plugin de autenticación de Docker**, verifica si puedes **burlarlo**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Reforzando Docker

* La herramienta [**docker-bench-security**](https://github.com/docker/docker-bench-security) es un script que verifica docenas de prácticas recomendadas comunes sobre la implementación de contenedores Docker en producción. Las pruebas son todas automatizadas y se basan en el [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Debes ejecutar la herramienta desde el host que ejecuta Docker o desde un contenedor con suficientes privilegios. Descubre **cómo ejecutarlo en el README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>
<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
