# Namespace UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El namespace UTS aísla el **hostname** y el **nombre de dominio NIS** que ve el proceso. A primera vista, esto puede parecer trivial en comparación con los namespaces de mount, PID o usuario, pero forma parte de lo que hace que un contenedor parezca su propio host. Dentro del namespace, el workload puede ver y, en ocasiones, cambiar un hostname que es local a ese namespace en lugar de global para la máquina.

Por sí solo, normalmente no es el elemento central de una historia de breakout. Sin embargo, cuando se comparte el namespace UTS del host, un proceso con privilegios suficientes puede influir en configuraciones relacionadas con la identidad del host, lo que puede ser relevante desde el punto de vista operativo y, ocasionalmente, de la seguridad.

## Lab

Puedes crear un namespace UTS con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
El cambio del hostname permanece local a ese namespace y no altera el hostname global del host. Esta es una demostración sencilla pero eficaz de la propiedad de aislamiento.

## Uso en tiempo de ejecución

Los contenedores normales obtienen un namespace UTS aislado. Docker y Podman pueden unirse al namespace UTS del host mediante `--uts=host`, y patrones similares de uso compartido del host pueden aparecer en otros runtimes y sistemas de orquestación. Sin embargo, la mayoría de las veces el aislamiento UTS privado forma parte de la configuración normal del contenedor y requiere poca atención por parte del operador.

## Impacto de seguridad

Aunque el namespace UTS no suele ser el más peligroso de compartir, sigue contribuyendo a la integridad del límite del contenedor. Si el namespace UTS del host está expuesto y el proceso tiene los privilegios necesarios, podría ser capaz de modificar información relacionada con el hostname del host. Esto puede afectar a la monitorización, el logging, las suposiciones operativas o los scripts que toman decisiones de confianza basadas en los datos de identidad del host.

## Abuso

Si el namespace UTS del host está compartido, la cuestión práctica es si el proceso puede modificar la configuración de identidad del host en lugar de limitarse a leerla:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si el container también tiene el privilegio necesario, comprueba si se puede cambiar el hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Esto es principalmente un problema de integridad e impacto operativo, más que un escape completo, pero aun así demuestra que el container puede influir directamente en una propiedad global del host.

Impacto:

- manipulación de la identidad del host
- logs, monitorización o automatización confusos que confían en el hostname
- normalmente no es un escape completo por sí solo, a menos que se combine con otras debilidades

En entornos de estilo Docker, un patrón útil de detección desde el host es:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Los contenedores que muestran `UTSMode=host` comparten el namespace UTS del host y deben revisarse con más atención si también tienen capabilities que les permitan llamar a `sethostname()` o `setdomainname()`.

## Comprobaciones

Estos comandos bastan para comprobar si la carga de trabajo tiene su propia vista del hostname o si comparte el namespace UTS del host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Qué es interesante aquí:

- La coincidencia de los identificadores de namespace con un proceso del host puede indicar que se comparte el UTS namespace del host.
- Si cambiar el hostname afecta a algo más que al propio contenedor, la workload tiene más influencia sobre la identidad del host de la que debería.
- Esto suele ser un hallazgo de menor prioridad que los problemas relacionados con los namespaces de PID, mount o user, pero aun así confirma hasta qué punto está realmente aislado el proceso.

En la mayoría de los entornos, el UTS namespace se entiende mejor como una capa de aislamiento complementaria. Rara vez es lo primero que se busca en un breakout, pero sigue formando parte de la coherencia y la seguridad generales de la vista del contenedor.

{{#include ../../../../../banners/hacktricks-training.md}}
