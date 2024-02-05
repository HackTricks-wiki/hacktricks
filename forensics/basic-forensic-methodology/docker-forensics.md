# Análisis Forense de Docker

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## Modificación de Contenedores

Existen sospechas de que algún contenedor de Docker fue comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puedes **encontrar fácilmente las modificaciones realizadas en este contenedor con respecto a la imagen** con:
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
En el comando anterior, **C** significa **Cambiado** y **A,** **Añadido**.\
Si descubres que algún archivo interesante como `/etc/shadow` fue modificado, puedes descargarlo del contenedor para verificar la actividad maliciosa con:
```bash
docker cp wordpress:/etc/shadow.
```
También puedes **compararlo con el original** ejecutando un nuevo contenedor y extrayendo el archivo de él:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si encuentras que **se agregó algún archivo sospechoso** puedes acceder al contenedor y verificarlo:
```bash
docker exec -it wordpress bash
```
## Modificaciones de imágenes

Cuando se te proporciona una imagen de Docker exportada (probablemente en formato `.tar`), puedes usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extraer un resumen de las modificaciones**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Entonces, puedes **descomprimir** la imagen y **acceder a los blobs** para buscar archivos sospechosos que hayas encontrado en el historial de cambios:
```bash
tar -xf image.tar
```
### Análisis Básico

Puedes obtener **información básica** de la imagen en ejecución:
```bash
docker inspect <image>
```
También puedes obtener un resumen **historial de cambios** con:
```bash
docker history --no-trunc <image>
```
También puedes generar un **dockerfile a partir de una imagen** con:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Bucear

Para encontrar archivos añadidos/modificados en imágenes de Docker también puedes usar la utilidad [**dive**](https://github.com/wagoodman/dive) (descárgala desde [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Esto te permite **navegar a través de los diferentes bloques de imágenes de Docker** y verificar qué archivos fueron modificados/agregados. **Rojo** significa agregado y **amarillo** significa modificado. Usa **tabulación** para moverte a la otra vista y **espacio** para colapsar/abrir carpetas.

Con die no podrás acceder al contenido de las diferentes etapas de la imagen. Para hacerlo, necesitarás **descomprimir cada capa y acceder a ella**.\
Puedes descomprimir todas las capas de una imagen desde el directorio donde se descomprimió la imagen ejecutando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciales de la memoria

Tenga en cuenta que al ejecutar un contenedor de docker dentro de un host **puede ver los procesos en ejecución en el contenedor desde el host** simplemente ejecutando `ps -ef`

Por lo tanto (como root) puede **volcar la memoria de los procesos** desde el host y buscar **credenciales** tal y como se muestra en el [**siguiente ejemplo**](../../linux-hardening/privilege-escalation/#process-memory).
