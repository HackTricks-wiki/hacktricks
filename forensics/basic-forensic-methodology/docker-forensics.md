# Docker Forensics

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Modificación de contenedores

Hay sospechas de que algún contenedor docker fue comprometido:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Puedes encontrar fácilmente **las modificaciones realizadas a este contenedor con respecto a la imagen** con:
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
En el comando anterior **C** significa **Cambiado** y **A,** **Agregado**.\
Si descubres que algún archivo interesante como `/etc/shadow` fue modificado, puedes descargarlo del contenedor para verificar actividad maliciosa con:
```bash
docker cp wordpress:/etc/shadow.
```
También puedes **compararlo con el original** ejecutando un nuevo contenedor y extrayendo el archivo de este:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Si descubres que **se añadió algún archivo sospechoso**, puedes acceder al contenedor y verificarlo:
```bash
docker exec -it wordpress bash
```
## Modificaciones en imágenes

Cuando se te proporciona una imagen de docker exportada (probablemente en formato `.tar`) puedes usar [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) para **extraer un resumen de las modificaciones**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Luego, puedes **descomprimir** la imagen y **acceder a los blobs** para buscar archivos sospechosos que puedas haber encontrado en el historial de cambios:
```bash
tar -xf image.tar
```
### Análisis Básico

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

Para encontrar archivos añadidos/modificados en imágenes de docker también puedes utilizar la herramienta [**dive**](https://github.com/wagoodman/dive) (descárgala desde [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)):
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Esto te permite **navegar a través de los diferentes blobs de imágenes de docker** y verificar qué archivos fueron modificados/agregados. **Rojo** significa agregado y **amarillo** significa modificado. Usa **tab** para moverte a la otra vista y **espacio** para colapsar/abrir carpetas.

Con die no podrás acceder al contenido de las diferentes etapas de la imagen. Para hacerlo necesitarás **descomprimir cada capa y acceder a ella**.\
Puedes descomprimir todas las capas de una imagen desde el directorio donde la imagen fue descomprimida ejecutando:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credenciales desde la memoria

Ten en cuenta que cuando ejecutas un contenedor docker dentro de un host **puedes ver los procesos que se ejecutan en el contenedor desde el host** simplemente ejecutando `ps -ef`

Por lo tanto (como root) puedes **volcar la memoria de los procesos** desde el host y buscar **credenciales** [**tal como en el siguiente ejemplo**](../../linux-hardening/privilege-escalation/#process-memory).

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
