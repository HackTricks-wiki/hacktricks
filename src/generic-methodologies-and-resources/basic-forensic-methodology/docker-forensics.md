# Análisis forense de Docker

{{#include ../../banners/hacktricks-training.md}}

## Modificación del contenedor

Hay sospechas de que algún contenedor de Docker fue comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puedes **encontrar fácilmente los cambios realizados en el sistema de archivos de este contenedor desde que se creó** con:<sup>[[1]](#references)</sup>
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
En el comando anterior, **C** significa **Changed** y **A** significa **Added**.<sup>[[1]](#references)</sup>\
Si descubres que se modificó algún archivo interesante, como `/etc/shadow`, puedes descargarlo del contenedor para comprobar si existe actividad maliciosa con:<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
También puedes **compararlo con el original** ejecutando un nuevo contenedor y extrayendo el archivo de este:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si encuentras que **se ha añadido algún archivo sospechoso**, puedes acceder al contenedor y comprobarlo:<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## Modificaciones de imágenes

Cuando se te proporciona una imagen de Docker exportada (probablemente en formato `.tar`), puedes usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extraer un resumen de las modificaciones**:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Luego, puedes **descomprimir** la imagen y **acceder a los blobs** para buscar archivos sospechosos que puedas haber encontrado en el historial de cambios:<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### Análisis básico

Puedes obtener **información básica** de la imagen ejecutando:<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
También puedes obtener un resumen del **historial de cambios** con:<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
También puedes generar un **dockerfile a partir de una imagen** con:<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

Para encontrar archivos añadidos/modificados en Docker images, también puedes usar la utilidad [**dive**](https://github.com/wagoodman/dive) (descárgala desde [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):<sup>[[11]](#references)[[12]](#references)</sup>

Carga el archivo guardado en Docker antes de abrir su image tag con dive:<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Esto te permite **navegar por los distintos blobs de las imágenes de docker** y comprobar qué archivos se modificaron/añadieron/eliminaron. Usa **tab** para desplazarte a la otra vista y **space** para contraer/abrir carpetas.<sup>[[11]](#references)</sup>

Con dive no podrás acceder al contenido de las distintas etapas de la imagen. Para hacerlo, tendrás que **descomprimir cada layer y acceder a ella**.\
Puedes descomprimir todos los layers de una imagen desde el directorio donde se descomprimió la imagen ejecutando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciales de la memoria

En Linux, el namespace de PID ancestral del host puede ver los procesos del namespace de PID hijo de un contenedor, por lo que una lista de procesos del host como `ps -ef` puede mostrarlos.<sup>[[14]](#references)</sup>

Cuando las credenciales del host, las capabilities y la política de LSM/ptrace lo permiten, un investigador del host con los privilegios adecuados puede **volcar la memoria del proceso** y buscar **credenciales** [**como en el siguiente ejemplo**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).<sup>[[15]](#references)</sup>

## References

- [1] [Diferencias de un contenedor Docker](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Copiar un contenedor Docker](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Ejecutar un contenedor Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Ejecutar comandos en un contenedor Docker](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [Definiciones de analizadores de container-diff](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Guardar una imagen Docker](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Inspeccionar una imagen Docker](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Historial de una imagen Docker](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [README de Dive v0.10.0](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Lanzamiento de Dive v0.10.0](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Cargar una imagen Docker](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
