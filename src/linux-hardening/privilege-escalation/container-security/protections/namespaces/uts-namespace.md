# Espacio de nombres UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Descripción general

El espacio de nombres UTS aísla el **hostname** y el **NIS domain name** que ve el proceso. A primera vista esto puede parecer trivial comparado con mount, PID, or user namespaces, pero forma parte de lo que hace que un contenedor parezca ser su propio host. Dentro del namespace, la carga de trabajo puede ver y, a veces, cambiar un hostname que es local a ese namespace en lugar de global para la máquina.

Por sí solo, esto normalmente no es el centro de una historia de breakout. Sin embargo, una vez que se comparte el host UTS namespace, un proceso con privilegios suficientes puede influir en configuraciones relacionadas con la identidad del host, lo que puede importar operativamente y, ocasionalmente, desde el punto de vista de la seguridad.

## Laboratorio

Puedes crear un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
El cambio del nombre de host permanece local en ese UTS namespace y no altera el nombre de host global del anfitrión. Esta es una demostración simple pero efectiva de la propiedad de aislamiento.

## Uso en tiempo de ejecución

Los contenedores normales obtienen un UTS namespace aislado. Docker y Podman pueden unirse al UTS namespace del host mediante `--uts=host`, y patrones similares de compartición con el host pueden aparecer en otros runtimes y sistemas de orquestación. La mayor parte del tiempo, sin embargo, el aislamiento privado de UTS es simplemente parte de la configuración normal del contenedor y requiere poca atención por parte del operador.

## Impacto en la seguridad

Aunque el UTS namespace no suele ser el más peligroso para compartir, aún contribuye a la integridad del límite del contenedor. Si el UTS namespace del anfitrión está expuesto y el proceso tiene los privilegios necesarios, podría ser capaz de alterar la información relacionada con el nombre de host del anfitrión. Eso puede afectar la monitorización, el registro, los supuestos operativos o los scripts que toman decisiones de confianza basadas en datos de identidad del anfitrión.

## Abuso

Si el UTS namespace del anfitrión se comparte, la pregunta práctica es si el proceso puede modificar la configuración de identidad del anfitrión en lugar de solo leerla:
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
Esto es principalmente un problema de integridad y de impacto operativo más que una fuga completa, pero aún así muestra que el contenedor puede influir directamente en una propiedad global del host.

Impacto:

- manipulación de la identidad del host
- confundir registros, monitorización o automatización que confían en el nombre del host
- normalmente no constituye un escape completo por sí sola a menos que se combine con otras debilidades

En entornos estilo Docker, un patrón útil de detección en el host es:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Los contenedores que muestran `UTSMode=host` están compartiendo el espacio de nombres UTS del host y deben revisarse con más cuidado si además tienen capacidades que les permitan llamar a `sethostname()` o `setdomainname()`.

## Comprobaciones

Estos comandos son suficientes para ver si la carga de trabajo tiene su propia vista de hostname o está compartiendo el espacio de nombres UTS del host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Que los identificadores de namespace coincidan con un proceso del host puede indicar que se comparte el UTS del host.
- Si cambiar el hostname afecta a más que el propio container, el workload tiene más influencia sobre la identidad del host de la que debería.
- Normalmente esto es un hallazgo de menor prioridad que los problemas de PID, mount o user namespace, pero aun así confirma cuán aislado está realmente el proceso.

En la mayoría de entornos, el UTS namespace debe considerarse como una capa de aislamiento auxiliar. Rara vez es lo primero que persigues en un breakout, pero sigue siendo parte de la consistencia y seguridad global de la vista del container.
{{#include ../../../../../banners/hacktricks-training.md}}
