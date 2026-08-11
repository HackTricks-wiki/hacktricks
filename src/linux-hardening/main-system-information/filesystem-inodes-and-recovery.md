# Sistemas de archivos, Inodes y recuperación

El abuso de sistemas de archivos suele consistir en confundir la relación entre una ruta visible y el objeto que se encuentra detrás.

Las imágenes de disco pueden ocultar otro sistema de archivos.<sup>[[1]](#references)</sup> Los montajes con permisos de escritura pueden ser utilizados por jobs privilegiados.

Los hardlinks pueden exponer el mismo inode mediante un nombre diferente.<sup>[[3]](#references)</sup> Los archivos eliminados aún pueden leerse a través de un descriptor de archivo abierto.<sup>[[5]](#references)[[6]](#references)</sup>

Esta página se centra en la técnica, no en un laboratorio o target específico.

## Imágenes de disco y montajes Loop

Un archivo normal puede contener un sistema de archivos completo, por lo que una imagen de disco puede exponer un segundo árbol de sistema de archivos al montarse.<sup>[[1]](#references)</sup>

Por tanto, las imágenes de backup, los dispositivos de bloque copiados, los artefactos de VM o los blobs renombrados pueden contener credenciales, scripts, claves SSH, archivos de configuración o flags, incluso cuando no parezcan útiles desde el exterior.

Identifica las imágenes probables con `file` para clasificar un candidato, `blkid` para examinar los metadatos reconocidos del sistema de archivos y `strings -a` para analizar todo el archivo en busca de secuencias imprimibles.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Cuando se permita el montaje, usa un montaje loop con `ro` para que la imagen se adjunte en modo de solo lectura; el comando `find` que aparece a continuación limita la profundidad de inspección y el tipo de archivo.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Si el montaje no está disponible y la imagen es ext2/ext3/ext4, inspecciona sus metadatos directamente con `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
La técnica es útil porque convierte un archivo de aspecto normal en un segundo árbol del sistema de archivos.<sup>[[1]](#references)</sup> Considérala una forma de recuperar datos ocultos, no una escalada de privilegios por sí sola.

## Abuso de montajes escribibles

Un montaje escribible se vuelve peligroso cuando un contexto con más privilegios confía posteriormente en algo que contiene. La pregunta importante no es solo «¿puedo escribir aquí?», sino «¿quién leerá, ejecutará, importará o cargará posteriormente algo desde aquí?».

Usa `findmnt` para inspeccionar los sistemas de archivos montados y sus opciones.<sup>[[9]](#references)</sup>

Busca montajes escribibles y consumidores sospechosos con los predicados documentados de permisos, tipo y límites del sistema de archivos de `find`; después, usa `grep` recursivo para buscar configuraciones de posibles consumidores.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Patrones comunes de abuso:

- Un trabajo de cron o un servicio de systemd ejecuta un script escribible desde el montaje.<sup>[[13]](#references)[[14]](#references)</sup>
- Un servicio privilegiado carga plugins, configuraciones, plantillas o binarios auxiliares desde el montaje.
- Un montaje contiene archivos SUID y permite su modificación, sustitución o manipulación de rutas.
- Un contenedor o chroot expone una ruta respaldada por el host que se puede escribir desde el entorno restringido. Los mount namespaces proporcionan jerarquías de montajes distintas, mientras que `chroot()` solo cambia la resolución de nombres de ruta y no es un sandbox completo.<sup>[[15]](#references)[[16]](#references)</sup>

Patrón genérico de validación usando los mismos predicados de `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Al demostrar el impacto en un laboratorio autorizado, mantén el payload observable y mínimo; por ejemplo, escribiendo la salida de `id` en un archivo temporal.<sup>[[23]](#references)</sup> La técnica central consiste en una ejecución retrasada mediante una ubicación de confianza con permisos de escritura.

## Inodos y confusión de rutas

Un inode es el objeto del sistema de archivos; una ruta es solo un nombre que apunta a él. Los metadatos del dispositivo y del inode permiten distinguir objetos entre sistemas de archivos, mientras que los recuentos de enlaces revelan la existencia de múltiples enlaces duros.<sup>[[3]](#references)</sup> Una ruta eliminada no siempre significa que los datos hayan desaparecido mientras un proceso aún mantenga abierto el archivo.<sup>[[5]](#references)</sup>

Los predicados de `find` que aparecen a continuación comparan la identidad del inode, los recuentos de enlaces, los límites de dispositivo y las marcas de tiempo.<sup>[[4]](#references)</sup>

Compara archivos por inode y dispositivo mediante `ls -i` y los formatos de metadatos de `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Busca todas las rutas visibles para el mismo inode con `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Busca directamente por número de inode con `find -inum` cuando solo tengas metadatos.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Esta técnica es útil cuando un archivo aparece con un nombre inesperado, cuando una aplicación valida una ruta pero utiliza otra, o cuando un wrapper con privilegios interactúa con un inode al que también se puede acceder desde otro lugar.

## Abuso de hardlinks

Los hardlinks crean varios nombres para el mismo inode. No apuntan a una ruta de destino como lo hacen los symlinks; son nombres equivalentes para el mismo objeto de archivo.<sup>[[3]](#references)</sup>

Busca archivos SUID con varios hardlinks utilizando los predicados de permisos y número de enlaces de `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona un archivo sospechoso con `stat` y `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Por qué importa:

- Un archivo sensible puede ser accesible a través de una ruta menos evidente.
- Un wrapper SUID puede estar oculto tras un nombre que no parezca privilegiado.
- Una limpieza que elimina un pathname puede dejar otro hardlink activo.

El sysctl `fs.protected_hardlinks` de Linux puede restringir la creación de hardlinks entre límites de privilegios.<sup>[[7]](#references)</sup> Los hardlinks existentes aún merecen una revisión.

## Recuperación de archivos eliminados mediante FDs abiertos

Cuando un proceso mantiene un archivo abierto, eliminar su último pathname mantiene el archivo activo hasta que se cierra el último descriptor; Linux expone esos descriptores en `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Encuentra archivos abiertos eliminados enumerando los descriptores de `/proc` y filtrando la salida de archivos abiertos.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
La recuperación mediante estos enlaces depende de los permisos, porque la desreferenciación de `/proc/<pid>/fd` está sujeta a las comprobaciones de acceso de `ptrace` y a los permisos de los archivos.<sup>[[6]](#references)</sup>

Cuando está permitido, `readlink` muestra el destino del descriptor y `cp` copia su contenido.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Esta es una técnica práctica para recuperar logs eliminados, secretos temporales, binarios descartados, archivos rotados o scripts eliminados después de su ejecución.

## Recuperación de ext con debugfs

En sistemas de archivos ext2/ext3/ext4, `debugfs` puede inspeccionar los metadatos de los inodos y volcar el contenido de los inodos desde un dispositivo de bloques o una imagen; sin `-w`, abre el sistema de archivos en modo de solo lectura.<sup>[[2]](#references)</sup> Trabaja sobre una copia o una imagen de solo lectura siempre que sea posible.

Lista las entradas e inspecciona los inodos con solicitudes de `debugfs` para obtener listados de directorios, el estado de los inodos y comprobar la correspondencia entre inodos y rutas.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Vuelca un inode conocido con el comando `debugfs dump` y, después, clasifica el resultado recuperado con `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Esto no garantiza la recuperación. Depende del estado del filesystem, de si los bloques se reutilizaron y de si los metadatos aún existen. Para ext3/ext4, el manual de `debugfs` señala que la recuperación de inodos eliminados puede fallar porque los bloques de datos de los inodos liberados ya no están disponibles.<sup>[[2]](#references)</sup> La técnica sigue siendo valiosa porque permite inspeccionar el estado a nivel de inodo sin depender del recorrido normal de rutas.

## Agotamiento y orden de los inodos

El agotamiento de inodos ocurre cuando un filesystem se queda sin nodos de archivo aunque aún quede espacio libre en disco.<sup>[[8]](#references)[[17]](#references)</sup> Normalmente provoca fallos de fiabilidad, pero también puede explicar comportamientos extraños durante la respuesta a incidentes o el triage en un laboratorio.

Usa `df -i` para mostrar información de inodos en lugar del uso de bloques.<sup>[[8]](#references)</sup>

Comprueba la presión de inodos con `df` y un recuento de `find` de los directorios padre.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Los números de inode y las marcas de tiempo también pueden ayudar a reconstruir la actividad en entornos de laboratorio sencillos.

Las directivas de formato de `find` que aparecen a continuación exponen esos campos.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Trata el orden como una pista, no como una prueba. Las operaciones de copia, la extracción de archivos, el tipo de filesystem, las restauraciones y las escrituras concurrentes pueden cambiar los patrones de asignación.

## Notas defensivas

- Monta las imágenes desconocidas como de solo lectura durante el análisis.<sup>[[1]](#references)</sup>
- Mantén los scripts privilegiados, las unidades de servicio, los plugins y las rutas auxiliares fuera de los mounts modificables por los usuarios.
- Usa `nosuid`, `nodev` y `noexec` cuando sea operativamente apropiado; estas opciones deshabilitan la ejecución de set-ID/capabilities, la interpretación de dispositivos o la ejecución directa de binarios en el mount.<sup>[[1]](#references)</sup> No las consideres un boundary completo.
- Restringe el acceso a `/proc/<pid>/fd`; la desreferenciación de esos enlaces está controlada por las comprobaciones de acceso de ptrace y los permisos de archivo.<sup>[[6]](#references)</sup> Restringe, cuando sea posible, los metadatos más amplios de los procesos y la inspección entre usuarios.
- Monitoriza los puntos de mount modificables, los hardlinks inesperados a archivos privilegiados y los archivos sensibles eliminados pero aún abiertos.

## References

- [1] [mount(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentación de /proc/sys/fs/ — documentación del kernel de Linux](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — página del manual de Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — página del manual de Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
