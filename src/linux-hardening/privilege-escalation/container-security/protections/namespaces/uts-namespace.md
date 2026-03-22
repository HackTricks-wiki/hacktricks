# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Resumen

El UTS namespace aísla el **hostname** y el **NIS domain name** que ve el proceso. A primera vista esto puede parecer trivial en comparación con mount, PID, o user namespaces, pero forma parte de lo que hace que un container parezca ser su propio host. Dentro del namespace, la workload puede ver y a veces cambiar un hostname que es local a ese namespace en lugar de global para la máquina.

Por sí sola, esto normalmente no es el elemento central de una historia de breakout. Sin embargo, una vez que se comparte el host UTS namespace, un proceso con privilegios suficientes puede influir en ajustes relacionados con la identidad del host, lo que puede importar a nivel operativo y, ocasionalmente, desde el punto de vista de la seguridad.

## Laboratorio

Puedes crear un UTS namespace con:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
El cambio del nombre de host permanece local en ese espacio de nombres y no altera el nombre de host global del anfitrión. Esto es una demostración simple pero efectiva de la propiedad de aislamiento.

## Uso en tiempo de ejecución

Los contenedores normales obtienen un espacio de nombres UTS aislado. Docker y Podman pueden unirse al espacio de nombres UTS del host mediante `--uts=host`, y patrones similares de compartición con el host pueden aparecer en otros runtimes y sistemas de orquestación. Sin embargo, la mayoría de las veces el aislamiento UTS privado es simplemente parte de la configuración normal del contenedor y requiere poca atención por parte del operador.

## Impacto en la seguridad

Aunque el espacio de nombres UTS no suele ser el más peligroso para compartir, sigue contribuyendo a la integridad del límite del contenedor. Si el espacio de nombres UTS del anfitrión está expuesto y el proceso tiene los privilegios necesarios, podría ser capaz de alterar la información relacionada con el nombre de host del anfitrión. Eso puede afectar al monitoreo, al registro (logging), a las suposiciones operativas o a scripts que toman decisiones de confianza basadas en datos de identidad del anfitrión.

## Abuso

Si el espacio de nombres UTS del anfitrión está compartido, la cuestión práctica es si el proceso puede modificar los ajustes de identidad del anfitrión en lugar de solo leerlos:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si el container también tiene el privilegio necesario, prueba si se puede cambiar el hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Esto es principalmente un problema de integridad y de impacto operativo más que un full escape, pero aun así muestra que el container puede influir directamente en una propiedad global del host.

Impacto:

- manipulación de la identidad del host
- confundir logs, monitoring o automation que confían en el hostname
- por lo general no es un full escape por sí solo a menos que se combine con otras debilidades

En entornos Docker-style, un host-side detection pattern útil es:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Los contenedores que muestran `UTSMode=host` comparten el UTS namespace del host y deben revisarse con más cuidado si también poseen capacidades que les permitan llamar a `sethostname()` o `setdomainname()`.

## Comprobaciones

Estos comandos son suficientes para ver si la carga de trabajo tiene su propia vista del nombre de host o está compartiendo el UTS namespace del host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Lo interesante aquí:

- Que los identificadores del namespace coincidan con un proceso del host puede indicar compartición del UTS con el host.
- Si cambiar el hostname afecta a más que el propio container, la workload tiene más influencia sobre la identidad del host de la que debería.
- Normalmente esto es un hallazgo de menor prioridad que problemas de PID, mount o user namespace, pero aun así confirma cuánto aislado está realmente el proceso.

En la mayoría de los entornos, el UTS namespace debe considerarse como una capa de aislamiento de soporte. Rara vez es lo primero que persigues en un breakout, pero sigue siendo parte de la consistencia y seguridad general de la vista del container.
{{#include ../../../../../banners/hacktricks-training.md}}
