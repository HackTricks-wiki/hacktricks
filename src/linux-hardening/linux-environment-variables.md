# Variables de Entorno de Linux

{{#include ../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por **procesos hijos**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable será accesible por tus sesiones actuales y sus procesos hijos.

Puedes **eliminar** una variable haciendo:
```bash
unset MYGLOBAL
```
## Variables locales

Las **variables locales** solo pueden ser **accedidas** por el **shell/script actual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Variables comunes

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – la pantalla utilizada por **X**. Esta variable generalmente se establece en **:0.0**, lo que significa la primera pantalla en la computadora actual.
- **EDITOR** – el editor de texto preferido del usuario.
- **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
- **HISTSIZE** – Número de líneas añadidas al archivo de historial cuando el usuario termina su sesión.
- **HOME** – tu directorio personal.
- **HOSTNAME** – el nombre del host de la computadora.
- **LANG** – tu idioma actual.
- **MAIL** – la ubicación de la cola de correo del usuario. Generalmente **/var/spool/mail/USER**.
- **MANPATH** – la lista de directorios para buscar páginas de manual.
- **OSTYPE** – el tipo de sistema operativo.
- **PS1** – el aviso predeterminado en bash.
- **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que deseas ejecutar solo especificando el nombre del archivo y no por ruta relativa o absoluta.
- **PWD** – el directorio de trabajo actual.
- **SHELL** – la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
- **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ** – tu zona horaria.
- **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, para que cuando **termines tu sesión** el **archivo de historial** (\~/.bash_history) **sea eliminado**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que cuando **termines tu sesión** cualquier comando se agregue al **archivo de historial** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Los procesos utilizarán el **proxy** declarado aquí para conectarse a internet a través de **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Cambia cómo se ve tu aviso.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Usuario regular:

![](<../images/image (740).png>)

Uno, dos y tres trabajos en segundo plano:

![](<../images/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
