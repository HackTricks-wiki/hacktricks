# Sistema de archivos, inodos y recuperación

{{#include ../../banners/hacktricks-training.md}}

El abuso del sistema de archivos suele consistir en confundir la relación entre una ruta visible y el objeto que se encuentra detrás de ella. Las imágenes de disco pueden ocultar otro sistema de archivos, los montajes con permisos de escritura pueden ser utilizados por jobs privilegiados, los hardlinks pueden exponer el mismo inodo mediante otro nombre y los archivos eliminados aún pueden leerse a través de un descriptor de archivo abierto.

Esta página se centra en la técnica, no en un laboratorio o target específico.

## Imágenes de disco y montajes loop

Un archivo normal puede contener un sistema de archivos completo. Por lo tanto, las imágenes de backup, los dispositivos de bloque copiados, los artefactos de VM o los blobs renombrados pueden contener credenciales, scripts, claves SSH, archivos de configuración o flags, aunque no parezcan útiles desde el exterior.

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
La técnica es útil porque convierte un archivo de aspecto normal en un segundo árbol del sistema de archivos. Considérala una forma de recuperar datos ocultos, no como una escalada de privilegios por sí sola.

## Writable Mount Abuse

Un punto de montaje con permisos de escritura se vuelve peligroso cuando un contexto con más privilegios confía posteriormente en algo que contiene. La pregunta importante no es solo «¿puedo escribir aquí?», sino también «¿quién lee, ejecuta, importa o carga posteriormente desde aquí?».

Busca puntos de montaje con permisos de escritura y consumidores sospechosos:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Patrones comunes de abuso:

- Un cron privilegiado o una unidad de systemd ejecuta un script escribible desde el montaje.
- Un servicio privilegiado carga plugins, configuraciones, plantillas o binarios auxiliares desde el montaje.
- Un montaje contiene archivos SUID y permite su modificación, sustitución o manipulación de rutas.
- Un contenedor o chroot expone una ruta respaldada por el host que es escribible desde el entorno restringido.

Patrón de validación genérico:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Al demostrar el impacto en un laboratorio autorizado, mantén el payload observable y mínimo, por ejemplo, escribiendo la salida de `id` en un archivo temporal. La técnica principal consiste en la ejecución diferida mediante una ubicación de confianza con permisos de escritura.

## Inodos y confusión de rutas

Un inodo es el objeto del sistema de archivos; una ruta es solo un nombre que apunta a él. Esto es importante porque dos rutas diferentes pueden apuntar al mismo inodo, y eliminar un nombre de ruta no siempre significa que los datos hayan desaparecido.

Compara los archivos por inodo y dispositivo:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Encuentra cada pathname visible para el mismo inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Busca directamente por número de inode cuando solo tienes metadatos:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Esta técnica resulta útil cuando un archivo aparece con un nombre inesperado, cuando una aplicación valida una ruta pero utiliza otra, o cuando un wrapper privilegiado interactúa con un inode al que también se puede acceder desde otro lugar.

## Hardlink Abuse

Los hardlinks crean varios nombres para el mismo inode. No apuntan a una ruta de destino como lo hacen los symlinks; son nombres equivalentes para el mismo objeto de archivo.

Busca archivos SUID con varios hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecciona un archivo sospechoso:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Por qué importa:

- Un archivo sensible puede ser accesible a través de una ruta menos obvia.
- Un wrapper SUID puede estar oculto tras un nombre que no parezca privilegiado.
- Una limpieza que elimina un nombre de ruta puede dejar otro hardlink activo.

Los kernels modernos y las opciones de montaje pueden restringir la creación de hardlinks para reducir este tipo de abuso, pero sigue siendo recomendable revisar los hardlinks existentes.

## Recuperación de archivos eliminados mediante FDs abiertos

Cuando un proceso mantiene un archivo abierto, los datos del archivo pueden seguir estando disponibles incluso después de eliminar el nombre de ruta. Linux expone esos descriptores abiertos en `/proc/<pid>/fd/`.

Buscar archivos abiertos eliminados:
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

## Recuperación en ext con debugfs

En sistemas de archivos ext, `debugfs` puede inspeccionar los metadatos de los inodos y, en ocasiones, volcar el contenido de los archivos desde una imagen del sistema de archivos. Trabaja con una copia o una imagen de solo lectura siempre que sea posible.

Lista las entradas e inspecciona los inodos:
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
Esto no garantiza la recuperación. Depende del estado del filesystem, de si los bloques se reutilizaron y de si los metadatos aún existen. La técnica sigue siendo valiosa porque permite inspeccionar el estado a nivel de inode sin depender del path traversal normal.

## Agotamiento y orden de los inodes

El agotamiento de inodes ocurre cuando un filesystem se queda sin objetos de archivo, aunque todavía quede espacio libre en disco. Normalmente provoca fallos de fiabilidad, pero también puede explicar comportamientos extraños durante la respuesta a incidentes o el triage en un laboratorio.

Comprueba la presión de inodes:
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
- Mantén los scripts privilegiados, las unidades de servicio, los plugins y las rutas de ayuda fuera de los montajes modificables por los usuarios.
- Usa `nosuid`, `nodev` y `noexec` cuando sea apropiado desde el punto de vista operativo, pero no los consideres un límite completo.
- Restringe el acceso a `/proc/<pid>/fd`, los metadatos de los procesos y la inspección de procesos entre usuarios cuando sea posible.
- Supervisa los puntos de montaje modificables, los hardlinks inesperados a archivos privilegiados y los archivos sensibles eliminados pero abiertos.
{{#include ../../banners/hacktricks-training.md}}
