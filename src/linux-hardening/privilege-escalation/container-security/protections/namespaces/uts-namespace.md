# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El UTS namespace aísla el **hostname** y el **nombre de dominio NIS** que ve el proceso. A primera vista, esto puede parecer trivial en comparación con los namespaces de mount, PID o user, pero forma parte de lo que hace que un contenedor parezca ser su propio host. Dentro del namespace, la carga de trabajo puede ver y, en ocasiones, cambiar un hostname que es local a ese namespace en lugar de global para la máquina.

Por sí solo, esto normalmente no es el núcleo de una historia de breakout. Sin embargo, una vez que se comparte el host UTS namespace, un proceso con privilegios suficientes puede influir en ajustes relacionados con la identidad del host, lo cual puede importar operacionalmente y, ocasionalmente, desde el punto de vista de la seguridad.

## Laboratorio

Puedes crear un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
El cambio de hostname permanece local a ese namespace y no altera el hostname global del host. Esta es una demostración simple pero efectiva de la propiedad de aislamiento.

## Uso en tiempo de ejecución

Los contenedores normales obtienen un UTS namespace aislado. Docker y Podman pueden unirse al host UTS namespace mediante `--uts=host`, y patrones similares de compartir con el host pueden aparecer en otros runtimes y sistemas de orquestación. Sin embargo, la mayor parte del tiempo, el aislamiento privado de UTS es simplemente parte de la configuración normal del contenedor y requiere poca atención por parte del operador.

## Impacto en la seguridad

Aunque el UTS namespace no suele ser el más peligroso de compartir, aún contribuye a la integridad del límite del contenedor. Si el host UTS namespace está expuesto y el proceso tiene los privilegios necesarios, podría ser capaz de alterar la información relacionada con el hostname del host. Eso puede afectar al monitoreo, registro, suposiciones operativas o scripts que toman decisiones de confianza basadas en datos de identidad del host.

## Abuso

Si el host UTS namespace está compartido, la pregunta práctica es si el proceso puede modificar los ajustes de identidad del host en lugar de solo leerlos:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si el contenedor también tiene el privilegio necesario, prueba si se puede cambiar el hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Esto es principalmente un problema de integridad y de impacto operativo en lugar de un full escape, pero aún así muestra que el container puede influir directamente en una propiedad global del host.

Impacto:

- manipulación de la identidad del host
- confundir logs, monitoring o automation que confían en el hostname
- normalmente no es un full escape por sí solo a menos que se combine con otras debilidades

En entornos estilo Docker, un patrón útil de detección en el lado del host es:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Los contenedores que muestran `UTSMode=host` comparten el UTS namespace del host y deberían revisarse con más cuidado si además tienen capacidades que les permiten llamar a `sethostname()` o `setdomainname()`.

## Comprobaciones

Estos comandos son suficientes para ver si la carga de trabajo tiene su propia vista de hostname o está compartiendo el UTS namespace del host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Lo interesante aquí:

- La coincidencia de identificadores de namespace con un proceso del host puede indicar compartición del UTS del host.
- Si cambiar el hostname afecta a más que el propio contenedor, el workload tiene más influencia sobre la identidad del host de la que debería.
- Esto suele ser un hallazgo de menor prioridad que problemas de PID, mount o user namespace, pero aún así confirma cuán aislado está realmente el proceso.

En la mayoría de los entornos, el UTS namespace debe considerarse como una capa de aislamiento complementaria. Rara vez es lo primero que persigues en un breakout, pero sigue siendo parte de la consistencia y seguridad general de la vista del container.
