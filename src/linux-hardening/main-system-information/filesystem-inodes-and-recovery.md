# Sistema de archivos, inodos y recuperación

{{#include ../../banners/hacktricks-training.md}}

El abuso del sistema de archivos suele consistir en confundir la relación entre una ruta visible y el objeto que se encuentra detrás de ella. Las imágenes de disco pueden ocultar otro sistema de archivos, los mounts con permisos de escritura pueden ser utilizados por jobs privilegiados, los hardlinks pueden exponer el mismo inodo mediante otro nombre y los archivos eliminados aún pueden leerse a través de un descriptor de archivo abierto.

Esta página se centra en la técnica, no en un laboratorio o target específico.

## Imágenes de disco y loop mounts

Un archivo normal puede contener un sistema de archivos completo. Por tanto, las imágenes de backup, los dispositivos de bloques copiados, los artefactos de VM o los blobs renombrados pueden contener credenciales, scripts, claves SSH, archivos de configuración o flags, aunque no parezcan útiles externamente.

Identifica las imágenes probables:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Si se permite el montaje, monta primero las imágenes desconocidas en modo de solo lectura:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Si el montaje no está disponible, inspecciona directamente los metadatos del sistema de archivos:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
La técnica es útil porque convierte un archivo de apariencia normal en un segundo árbol del sistema de archivos. Considérala una forma de recuperar datos ocultos, no como una privilege escalation por sí sola.

## Writable Mount Abuse

Un montaje con permisos de escritura se vuelve peligroso cuando un contexto con mayores privilegios confía posteriormente en algo que contiene. La pregunta importante no es solo «¿puedo escribir aquí?», sino también «¿quién leerá, ejecutará, importará o cargará algo desde aquí posteriormente?».

Encuentra los montajes con permisos de escritura y los consumidores sospechosos:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Patrones comunes de abuso:

- Un cron privilegiado o una unidad de systemd ejecuta un script modificable desde el mount.
- Un servicio privilegiado carga plugins, configuración, plantillas o binarios auxiliares desde el mount.
- Un mount contiene archivos SUID y permite su modificación, sustitución o manipulación de rutas.
- Un container o chroot expone una ruta respaldada por el host que se puede modificar desde el entorno restringido.

Patrón genérico de validación:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Al demostrar el impacto en un laboratorio autorizado, mantén el payload observable y mínimo; por ejemplo, escribe la salida de `id` en un archivo temporal. La técnica principal consiste en la ejecución retrasada mediante una ubicación de escritura confiable.

## Inodes y confusión de rutas

Un inode es el objeto del sistema de archivos; una ruta es solo un nombre que apunta a él. Esto es importante porque dos rutas diferentes pueden apuntar al mismo inode, y eliminar un nombre de ruta no siempre significa que los datos hayan desaparecido.

Compara los archivos por inode y dispositivo:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Encuentra cada ruta visible para el mismo inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Busca directamente por número de inode cuando solo tengas metadatos:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Esta técnica es útil cuando un archivo aparece con un nombre inesperado, cuando una aplicación valida una ruta pero utiliza otra, o cuando un wrapper privilegiado interactúa con un inode que también es accesible desde otro lugar.

## Hardlink Abuse

Los hardlinks crean varios nombres para el mismo inode. No apuntan a una ruta de destino como hacen los symlinks; son nombres equivalentes para el mismo objeto de archivo.

Encuentra archivos SUID con varios hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona un archivo sospechoso:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Por qué importa:

- Un archivo sensible puede ser accesible a través de una ruta menos evidente.
- Un wrapper SUID puede estar oculto tras un nombre que no parezca privilegiado.
- La limpieza que elimina un pathname puede dejar otro hardlink activo.

Los kernels modernos y las opciones de montaje pueden restringir la creación de hardlinks para reducir este tipo de abuso, pero aun así conviene revisar los hardlinks existentes.

## Recuperación de archivos eliminados mediante FDs abiertos

Cuando un proceso mantiene un archivo abierto, los datos del archivo pueden seguir disponibles incluso después de eliminar el pathname. Linux expone esos descriptores abiertos en `/proc/<pid>/fd/`.

Buscar archivos eliminados abiertos:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Recupera los datos cuando los permisos lo permitan:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Esta es una técnica práctica para recuperar logs eliminados, secretos temporales, binarios descartados, archivos rotados o scripts eliminados después de su ejecución.

## Recuperación de ext con debugfs

En los filesystems ext, `debugfs` puede inspeccionar los metadatos de los inodes y, en ocasiones, volcar el contenido de los archivos desde una imagen del filesystem. Trabaja sobre una copia o una imagen de solo lectura siempre que sea posible.

Lista las entradas e inspecciona los inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Volcar un inode conocido:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Esto no garantiza la recuperación. Depende del estado del filesystem, de si los bloques se reutilizaron y de si los metadatos todavía existen. La técnica sigue siendo valiosa porque permite inspeccionar el estado a nivel de inode sin depender del path traversal normal.

## Agotamiento y orden de los inodes

El agotamiento de inodes ocurre cuando un filesystem se queda sin objetos de archivo, incluso si todavía queda espacio libre en el disco. Normalmente provoca fallos de fiabilidad, pero también puede explicar comportamientos extraños durante la respuesta a incidentes o el triage en un laboratorio.

Comprueba la presión sobre los inodes:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Los números de inodo y las marcas de tiempo también pueden ayudar a reconstruir la actividad en entornos de laboratorio sencillos:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Considera el orden como una pista, no como una prueba. Las operaciones de copia, la extracción de archivos, el tipo de sistema de archivos, las restauraciones y las escrituras simultáneas pueden cambiar los patrones de asignación.

## Notas defensivas

- Monta las imágenes desconocidas en modo de solo lectura durante el análisis.
- Mantén los scripts privilegiados, las unidades de servicio, los plugins y las rutas de los helpers fuera de los montajes en los que los usuarios puedan escribir.
- Usa `nosuid`, `nodev` y `noexec` cuando sea apropiado desde el punto de vista operativo, pero no los consideres un límite de seguridad completo.
- Restringe, cuando sea posible, el acceso a `/proc/<pid>/fd`, los metadatos de los procesos y la inspección de procesos entre usuarios.
- Supervisa los puntos de montaje con permisos de escritura, los hardlinks inesperados a archivos privilegiados y los archivos sensibles eliminados pero aún abiertos.
