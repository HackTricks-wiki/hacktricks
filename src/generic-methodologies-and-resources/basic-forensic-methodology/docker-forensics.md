# Forense de Docker

{{#include ../../banners/hacktricks-training.md}}


## Modificación del contenedor

Hay sospechas de que algún contenedor de Docker fue comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puedes **encontrar fácilmente las modificaciones realizadas en este container con respecto a la imagen** con:
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
En el comando anterior, **C** significa **Changed** y **A,** **Added**.\
Si descubres que se modificó algún archivo interesante, como `/etc/shadow`, puedes descargarlo del contenedor para comprobar si hay actividad maliciosa con:
```bash
docker cp wordpress:/etc/shadow.
```
También puedes **compararlo con el original** ejecutando un nuevo contenedor y extrayendo el archivo de él:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si encuentras que **se añadió algún archivo sospechoso**, puedes acceder al contenedor y comprobarlo:
```bash
docker exec -it wordpress bash
```
## Modificaciones de imágenes

Cuando se proporciona una imagen de docker exportada (probablemente en formato `.tar`), puedes usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extraer un resumen de las modificaciones**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Entonces, puedes **descomprimir** la imagen y **acceder a los blobs** para buscar archivos sospechosos que quizá hayas encontrado en el historial de cambios:
```bash
tar -xf image.tar
```
### Análisis básico

Puedes obtener **información básica** de la imagen ejecutando:
```bash
docker inspect <image>
```
También puedes obtener un resumen del **historial de cambios** con:
```bash
docker history --no-trunc <image>
```
También puedes generar un **dockerfile a partir de una imagen** con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Para encontrar archivos añadidos o modificados en imágenes de Docker, también puedes usar la utilidad [**dive**](https://github.com/wagoodman/dive) (descárgala desde [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Esto permite **navegar por los distintos blobs de las imágenes de Docker** y comprobar qué archivos se modificaron o añadieron. **Rojo** significa añadido y **amarillo** significa modificado. Usa **tab** para cambiar a la otra vista y **space** para contraer/abrir carpetas.

Con die no podrás acceder al contenido de las distintas etapas de la imagen. Para hacerlo, tendrás que **descomprimir cada layer y acceder a él**.\
Puedes descomprimir todos los layers de una imagen desde el directorio donde se descomprimió la imagen ejecutando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciales desde la memoria

Ten en cuenta que cuando ejecutas un contenedor Docker dentro de un host **puedes ver los procesos que se ejecutan en el contenedor desde el host** simplemente ejecutando `ps -ef`

Por lo tanto, como root, puedes **volcar la memoria de los procesos** desde el host y buscar **credenciales**, [**como en el siguiente ejemplo**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory).


{{#include ../../banners/hacktricks-training.md}}
